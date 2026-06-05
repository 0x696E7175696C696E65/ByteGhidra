pub mod snapshot {
    use std::cell::RefCell;
    use std::collections::BTreeSet;

    #[derive(Debug, Clone)]
    pub struct BinarySnapshot {
        id: u64,
        pub name: String,
        bytes: Vec<u8>,
        chunk_size: usize,
        materialized_chunks: RefCell<BTreeSet<usize>>,
    }

    impl BinarySnapshot {
        pub fn from_bytes(name: impl Into<String>, bytes: Vec<u8>, chunk_size: usize) -> Self {
            let name = name.into();
            let chunk_size = chunk_size.max(1);
            let id =
                stable_hash(name.as_bytes()) ^ stable_hash(&bytes) ^ ((chunk_size as u64) << 32);

            Self {
                id,
                name,
                bytes,
                chunk_size,
                materialized_chunks: RefCell::new(BTreeSet::new()),
            }
        }

        pub fn id(&self) -> u64 {
            self.id
        }

        pub fn len(&self) -> usize {
            self.bytes.len()
        }

        pub fn is_empty(&self) -> bool {
            self.bytes.is_empty()
        }

        pub fn read_range(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
            let offset = usize::try_from(offset).ok()?;
            let end = offset.checked_add(len)?;
            if end > self.bytes.len() {
                return None;
            }

            if len > 0 {
                let first_chunk = offset / self.chunk_size;
                let last_chunk = (end - 1) / self.chunk_size;
                let mut materialized = self.materialized_chunks.borrow_mut();
                for chunk in first_chunk..=last_chunk {
                    materialized.insert(chunk);
                }
            }

            Some(self.bytes[offset..end].to_vec())
        }

        pub fn materialized_chunk_count(&self) -> usize {
            self.materialized_chunks.borrow().len()
        }
    }

    pub(crate) fn stable_hash(bytes: &[u8]) -> u64 {
        let mut hash = 0xcbf29ce484222325u64;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash
    }
}

pub mod loader {
    use crate::snapshot::BinarySnapshot;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BinaryFormat {
        Pe,
        Elf,
        MachO,
        RawFirmware,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Permission {
        ReadOnly,
        ReadWrite,
        ReadExecute,
        ReadWriteExecute,
    }

    impl Permission {
        pub fn executable(self) -> bool {
            matches!(self, Self::ReadExecute | Self::ReadWriteExecute)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LoadedBinary {
        pub format: BinaryFormat,
        pub snapshot_id: u64,
    }

    #[derive(Debug, Default, Clone)]
    pub struct LoaderRegistry;

    impl LoaderRegistry {
        pub fn load(&self, snapshot: &BinarySnapshot) -> Result<LoadedBinary, String> {
            let header = snapshot
                .read_range(0, snapshot.len().min(4))
                .unwrap_or_default();
            let format = if header.starts_with(b"MZ") {
                BinaryFormat::Pe
            } else if header.starts_with(b"\x7fELF") {
                BinaryFormat::Elf
            } else if matches!(
                header.as_slice(),
                [0xfe, 0xed, 0xfa, 0xce] | [0xcf, 0xfa, 0xed, 0xfe] | [0xca, 0xfe, 0xba, 0xbe]
            ) {
                BinaryFormat::MachO
            } else {
                BinaryFormat::RawFirmware
            };

            Ok(LoadedBinary {
                format,
                snapshot_id: snapshot.id(),
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Segment {
        pub name: String,
        pub base: u64,
        pub file_offset: u64,
        pub size: u64,
        pub permission: Permission,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MemoryMap {
        pub snapshot_id: u64,
        segments: Vec<Segment>,
    }

    impl MemoryMap {
        pub fn new(snapshot_id: u64) -> Self {
            Self {
                snapshot_id,
                segments: Vec::new(),
            }
        }

        pub fn add_segment(
            &mut self,
            name: impl Into<String>,
            base: u64,
            file_offset: u64,
            size: u64,
            permission: Permission,
        ) -> Result<(), String> {
            if size == 0 {
                return Err("segment size must be non-zero".into());
            }

            let end = base
                .checked_add(size)
                .ok_or_else(|| "segment address range overflows".to_string())?;
            if self.segments.iter().any(|segment| {
                let segment_end = segment.base + segment.size;
                base < segment_end && segment.base < end
            }) {
                return Err("segment overlaps an existing mapping".into());
            }

            self.segments.push(Segment {
                name: name.into(),
                base,
                file_offset,
                size,
                permission,
            });
            self.segments.sort_by_key(|segment| segment.base);
            Ok(())
        }

        pub fn read_u8(&self, snapshot: &BinarySnapshot, address: u64) -> Option<u8> {
            if snapshot.id() != self.snapshot_id {
                return None;
            }
            let segment = self.segment_for(address)?;
            let file_offset = segment.file_offset + (address - segment.base);
            snapshot
                .read_range(file_offset, 1)
                .and_then(|bytes| bytes.first().copied())
        }

        pub fn segment_for(&self, address: u64) -> Option<&Segment> {
            self.segments
                .iter()
                .find(|segment| address >= segment.base && address < segment.base + segment.size)
        }

        pub fn executable_ranges(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
            self.segments
                .iter()
                .filter(|segment| segment.permission.executable())
                .map(|segment| (segment.base, segment.base + segment.size))
        }
    }
}

pub mod graph {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum EdgeKind {
        Fallthrough,
        Call,
        Return,
        BranchTrue,
        BranchFalse,
        Speculative,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Edge {
        pub from: u64,
        pub to: u64,
        pub kind: EdgeKind,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Cfg {
        pub edges: Vec<Edge>,
    }

    impl Cfg {
        pub fn add_edge(&mut self, from: u64, to: u64, kind: EdgeKind) {
            if !self
                .edges
                .iter()
                .any(|edge| edge.from == from && edge.to == to && edge.kind == kind)
            {
                self.edges.push(Edge { from, to, kind });
            }
        }

        pub fn successors(&self, address: u64) -> impl Iterator<Item = &Edge> {
            self.edges.iter().filter(move |edge| edge.from == address)
        }
    }
}

pub mod arch {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Architecture {
        X86,
        X64,
        Arm,
        Arm64,
        Mips,
        RiscV,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Decoder {
        pub architecture: Architecture,
        pub version: u32,
    }

    #[derive(Debug, Clone)]
    pub struct ArchitectureRegistry {
        decoders: Vec<Decoder>,
    }

    impl Default for ArchitectureRegistry {
        fn default() -> Self {
            Self::with_builtin_decoders()
        }
    }

    impl ArchitectureRegistry {
        pub fn with_builtin_decoders() -> Self {
            Self {
                decoders: vec![
                    Decoder {
                        architecture: Architecture::X86,
                        version: 1,
                    },
                    Decoder {
                        architecture: Architecture::X64,
                        version: 1,
                    },
                    Decoder {
                        architecture: Architecture::Arm,
                        version: 1,
                    },
                    Decoder {
                        architecture: Architecture::Arm64,
                        version: 1,
                    },
                    Decoder {
                        architecture: Architecture::Mips,
                        version: 1,
                    },
                    Decoder {
                        architecture: Architecture::RiscV,
                        version: 1,
                    },
                ],
            }
        }

        pub fn decoder(&self, architecture: Architecture) -> Option<Decoder> {
            self.decoders
                .iter()
                .find(|decoder| decoder.architecture == architecture)
                .copied()
        }
    }
}

pub mod decode {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    use crate::arch::{Architecture, Decoder};
    use crate::graph::{Cfg, EdgeKind};
    use crate::loader::MemoryMap;
    use crate::snapshot::{BinarySnapshot, stable_hash};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum InstructionKind {
        Nop,
        Ret,
        Call(u64),
        Jump(u64),
        BranchIfZero(u64),
        Unknown,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Instruction {
        pub address: u64,
        pub length: u8,
        pub bytes: Vec<u8>,
        pub kind: InstructionKind,
        pub confidence: u8,
        pub decoder_version: u32,
        pub semantic_hash: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecodeHypothesis {
        pub start: u64,
        pub end: u64,
        pub strategy: String,
        pub confidence: u8,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Program {
        pub architecture: Architecture,
        pub entry: u64,
        pub instructions: Vec<Instruction>,
        pub cfg: Cfg,
        pub decode_hypotheses: Vec<DecodeHypothesis>,
    }

    impl Program {
        pub fn instruction_at(&self, address: u64) -> Option<&Instruction> {
            self.instructions
                .iter()
                .find(|instruction| instruction.address == address)
        }
    }

    #[derive(Debug, Clone)]
    pub struct DisassemblyEngine {
        decoder: Decoder,
    }

    impl DisassemblyEngine {
        pub fn new(decoder: Decoder) -> Self {
            Self { decoder }
        }

        pub fn analyze(
            &self,
            snapshot: &BinarySnapshot,
            map: &MemoryMap,
            entry: u64,
        ) -> Result<Program, String> {
            let mut queue = VecDeque::from([entry]);
            let mut visited = BTreeSet::new();
            let mut instructions = BTreeMap::new();
            let mut hypotheses = Vec::new();

            while let Some(address) = queue.pop_front() {
                if !visited.insert(address) {
                    continue;
                }
                let Some(instruction) = self.decode_one(snapshot, map, address) else {
                    continue;
                };

                let next = instruction.address + u64::from(instruction.length);
                match instruction.kind {
                    InstructionKind::Call(target) => {
                        queue.push_back(target);
                        queue.push_back(next);
                    }
                    InstructionKind::Jump(target) => {
                        queue.push_back(target);
                    }
                    InstructionKind::BranchIfZero(target) => {
                        queue.push_back(target);
                        queue.push_back(next);
                    }
                    InstructionKind::Nop | InstructionKind::Unknown => {
                        queue.push_back(next);
                    }
                    InstructionKind::Ret => {}
                }

                instructions.insert(address, instruction);
            }

            for (start, end) in map.executable_ranges() {
                hypotheses.push(DecodeHypothesis {
                    start,
                    end,
                    strategy: "recursive-descent+linear-sweep".into(),
                    confidence: 90,
                });
            }

            let instructions = instructions.into_values().collect::<Vec<_>>();
            let cfg = build_cfg(&instructions);
            Ok(Program {
                architecture: self.decoder.architecture,
                entry,
                instructions,
                cfg,
                decode_hypotheses: hypotheses,
            })
        }

        fn decode_one(
            &self,
            snapshot: &BinarySnapshot,
            map: &MemoryMap,
            address: u64,
        ) -> Option<Instruction> {
            let opcode = map.read_u8(snapshot, address)?;
            let (length, kind) = match opcode {
                0x90 => (1, InstructionKind::Nop),
                0xc3 => (1, InstructionKind::Ret),
                0xe8 => {
                    let rel = read_i32(snapshot, map, address + 1)?;
                    let next = address + 5;
                    (
                        5,
                        InstructionKind::Call(next.wrapping_add_signed(i64::from(rel))),
                    )
                }
                0xeb => {
                    let rel = map.read_u8(snapshot, address + 1)? as i8;
                    let next = address + 2;
                    (
                        2,
                        InstructionKind::Jump(next.wrapping_add_signed(i64::from(rel))),
                    )
                }
                0x74 => {
                    let rel = map.read_u8(snapshot, address + 1)? as i8;
                    let next = address + 2;
                    (
                        2,
                        InstructionKind::BranchIfZero(next.wrapping_add_signed(i64::from(rel))),
                    )
                }
                _ => (1, InstructionKind::Unknown),
            };

            let bytes = (0..length)
                .filter_map(|offset| map.read_u8(snapshot, address + u64::from(offset)))
                .collect::<Vec<_>>();
            Some(Instruction {
                address,
                length,
                semantic_hash: stable_hash(&bytes),
                bytes,
                kind,
                confidence: if opcode == 0 { 20 } else { 95 },
                decoder_version: self.decoder.version,
            })
        }
    }

    fn read_i32(snapshot: &BinarySnapshot, map: &MemoryMap, address: u64) -> Option<i32> {
        let bytes = [
            map.read_u8(snapshot, address)?,
            map.read_u8(snapshot, address + 1)?,
            map.read_u8(snapshot, address + 2)?,
            map.read_u8(snapshot, address + 3)?,
        ];
        Some(i32::from_le_bytes(bytes))
    }

    fn build_cfg(instructions: &[Instruction]) -> Cfg {
        let addresses = instructions
            .iter()
            .map(|instruction| instruction.address)
            .collect::<BTreeSet<_>>();
        let mut cfg = Cfg::default();
        for instruction in instructions {
            let next = instruction.address + u64::from(instruction.length);
            match instruction.kind {
                InstructionKind::Nop | InstructionKind::Unknown => {
                    if addresses.contains(&next) {
                        cfg.add_edge(instruction.address, next, EdgeKind::Fallthrough);
                    }
                }
                InstructionKind::Call(target) => {
                    cfg.add_edge(instruction.address, target, EdgeKind::Call);
                    if addresses.contains(&next) {
                        cfg.add_edge(instruction.address, next, EdgeKind::Fallthrough);
                    }
                }
                InstructionKind::Jump(target) => {
                    cfg.add_edge(instruction.address, target, EdgeKind::BranchTrue);
                }
                InstructionKind::BranchIfZero(target) => {
                    cfg.add_edge(instruction.address, target, EdgeKind::BranchTrue);
                    if addresses.contains(&next) {
                        cfg.add_edge(instruction.address, next, EdgeKind::BranchFalse);
                    }
                }
                InstructionKind::Ret => {
                    cfg.add_edge(instruction.address, 0, EdgeKind::Return);
                }
            }
        }
        cfg
    }
}

pub mod ir {
    use crate::decode::{InstructionKind, Program};
    use crate::graph::EdgeKind;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IrLayer {
        Raw,
        Normalized,
        Ssa,
        Typed,
        Structured,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Value {
        pub id: u64,
        pub name: String,
        pub defined_at: u64,
        pub width_bits: u16,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MemoryState {
        pub id: u64,
        pub region: String,
        pub defined_at: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Effect {
        pub id: u64,
        pub kind: String,
        pub address: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Phi {
        pub output: u64,
        pub inputs: Vec<u64>,
        pub block: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IrProgram {
        pub layers: Vec<IrLayer>,
        pub values: Vec<Value>,
        pub memory_states: Vec<MemoryState>,
        pub effects: Vec<Effect>,
        pub phis: Vec<Phi>,
        pub control_edges: Vec<(u64, u64, EdgeKind)>,
    }

    #[derive(Debug, Default, Clone)]
    pub struct Lifter;

    impl Lifter {
        pub fn lift_program(&self, program: &Program) -> Result<IrProgram, String> {
            let mut values = Vec::new();
            let mut memory_states = vec![MemoryState {
                id: 0,
                region: "stack".into(),
                defined_at: program.entry,
            }];
            let mut effects = Vec::new();

            for (index, instruction) in program.instructions.iter().enumerate() {
                values.push(Value {
                    id: index as u64,
                    name: format!("v{index}"),
                    defined_at: instruction.address,
                    width_bits: 64,
                });

                match instruction.kind {
                    InstructionKind::Call(_) => {
                        let id = effects.len() as u64;
                        effects.push(Effect {
                            id,
                            kind: "call".into(),
                            address: instruction.address,
                        });
                        memory_states.push(MemoryState {
                            id: memory_states.len() as u64,
                            region: "unknown".into(),
                            defined_at: instruction.address,
                        });
                    }
                    InstructionKind::Ret => {
                        let id = effects.len() as u64;
                        effects.push(Effect {
                            id,
                            kind: "return".into(),
                            address: instruction.address,
                        });
                    }
                    InstructionKind::Unknown => {
                        let id = effects.len() as u64;
                        effects.push(Effect {
                            id,
                            kind: "unknown".into(),
                            address: instruction.address,
                        });
                    }
                    _ => {}
                }
            }

            Ok(IrProgram {
                layers: vec![IrLayer::Raw, IrLayer::Normalized, IrLayer::Ssa],
                values,
                memory_states,
                effects,
                phis: build_phis(program),
                control_edges: program
                    .cfg
                    .edges
                    .iter()
                    .map(|edge| (edge.from, edge.to, edge.kind))
                    .collect(),
            })
        }
    }

    fn build_phis(program: &Program) -> Vec<Phi> {
        let mut phis = Vec::new();
        for instruction in &program.instructions {
            let incoming = program
                .cfg
                .edges
                .iter()
                .filter(|edge| edge.to == instruction.address)
                .count();
            if incoming > 1 {
                phis.push(Phi {
                    output: instruction.address,
                    inputs: program
                        .cfg
                        .edges
                        .iter()
                        .filter(|edge| edge.to == instruction.address)
                        .map(|edge| edge.from)
                        .collect(),
                    block: instruction.address,
                });
            }
        }
        phis
    }
}

pub mod analysis {
    use std::collections::{BTreeMap, BTreeSet};

    use crate::decode::{InstructionKind, Program};
    use crate::graph::EdgeKind;
    use crate::ir::IrProgram;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AnalysisEvent {
        BinaryMapped,
        FunctionBoundaryChanged(u64),
        TypeFactChanged(u64),
        PluginFailure(String),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FunctionFact {
        pub entry: u64,
        pub name: String,
        pub signature: Option<String>,
        pub boundary_confidence: u8,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CrossReference {
        pub from: u64,
        pub to: u64,
        pub kind: EdgeKind,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct AnalysisFacts {
        pub functions: Vec<FunctionFact>,
        pub xrefs: Vec<CrossReference>,
    }

    #[derive(Debug, Default, Clone)]
    pub struct AnalysisEngine {
        events: Vec<AnalysisEvent>,
        signatures: BTreeMap<u64, String>,
        dependencies: BTreeMap<u64, Vec<String>>,
    }

    impl AnalysisEngine {
        pub fn analyze_program(
            &mut self,
            program: &Program,
            _ir: &IrProgram,
        ) -> Result<AnalysisFacts, String> {
            self.events.push(AnalysisEvent::BinaryMapped);
            let mut function_entries = BTreeSet::from([program.entry]);
            for edge in &program.cfg.edges {
                if edge.kind == EdgeKind::Call {
                    function_entries.insert(edge.to);
                }
            }
            for instruction in &program.instructions {
                if matches!(instruction.kind, InstructionKind::Call(_)) {
                    self.dependencies.entry(instruction.address).or_default();
                }
            }

            let functions = function_entries
                .into_iter()
                .map(|entry| {
                    self.dependencies.entry(entry).or_insert_with(|| {
                        vec![
                            format!("function:0x{entry:x}"),
                            format!("type:0x{entry:x}"),
                            format!("decompile:0x{entry:x}"),
                        ]
                    });
                    FunctionFact {
                        entry,
                        name: format!("sub_{entry:x}"),
                        signature: self.signatures.get(&entry).cloned(),
                        boundary_confidence: if entry == program.entry { 100 } else { 85 },
                    }
                })
                .collect();

            let xrefs = program
                .cfg
                .edges
                .iter()
                .filter(|edge| edge.to != 0)
                .map(|edge| CrossReference {
                    from: edge.from,
                    to: edge.to,
                    kind: edge.kind,
                })
                .collect();

            Ok(AnalysisFacts { functions, xrefs })
        }

        pub fn apply_user_signature(
            &mut self,
            entry: u64,
            signature: impl Into<String>,
        ) -> Result<Vec<String>, String> {
            self.signatures.insert(entry, signature.into());
            self.events.push(AnalysisEvent::TypeFactChanged(entry));
            Ok(self
                .dependencies
                .entry(entry)
                .or_insert_with(|| {
                    vec![
                        format!("function:0x{entry:x}"),
                        format!("type:0x{entry:x}"),
                        format!("decompile:0x{entry:x}"),
                    ]
                })
                .clone())
        }

        pub fn apply_user_name(&mut self, entry: u64, _name: impl Into<String>) -> Vec<String> {
            vec![
                format!("function:0x{entry:x}"),
                format!("decompile:0x{entry:x}"),
            ]
        }

        pub fn apply_user_type(
            &mut self,
            entry: u64,
            _type_name: impl Into<String>,
        ) -> Vec<String> {
            self.events.push(AnalysisEvent::TypeFactChanged(entry));
            vec![
                format!("type:0x{entry:x}"),
                format!("decompile:0x{entry:x}"),
            ]
        }

        pub fn apply_function_boundary(
            &mut self,
            entry: u64,
            _range: impl Into<String>,
        ) -> Vec<String> {
            self.events
                .push(AnalysisEvent::FunctionBoundaryChanged(entry));
            vec![
                format!("function:0x{entry:x}"),
                format!("cfg:0x{entry:x}"),
                format!("ir:0x{entry:x}"),
                format!("decompile:0x{entry:x}"),
            ]
        }

        pub fn events(&self) -> &[AnalysisEvent] {
            &self.events
        }
    }
}

pub mod decompiler {
    use crate::analysis::AnalysisFacts;
    use crate::decode::{InstructionKind, Program};
    use crate::ir::IrProgram;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecompiledFunction {
        pub function_id: u64,
        pub text: String,
        pub low_confidence_regions: Vec<u64>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DecompilerReview {
        pub variable_mappings: Vec<String>,
        pub type_conflicts: Vec<String>,
        pub low_confidence_regions: Vec<u64>,
    }

    #[derive(Debug, Default, Clone)]
    pub struct Decompiler;

    impl Decompiler {
        pub fn decompile(
            &self,
            function_id: u64,
            program: &Program,
            ir: &IrProgram,
            facts: &AnalysisFacts,
        ) -> Result<DecompiledFunction, String> {
            let function = facts
                .functions
                .iter()
                .find(|function| function.entry == function_id)
                .ok_or_else(|| format!("unknown function 0x{function_id:x}"))?;
            let signature = function
                .signature
                .clone()
                .unwrap_or_else(|| format!("fn {}()", function.name));

            let mut text = String::new();
            text.push_str(&format!("{signature} {{\n"));
            let mut low_confidence_regions = Vec::new();

            for (index, instruction) in program.instructions.iter().enumerate() {
                if instruction.address < function_id {
                    continue;
                }
                if instruction.confidence < 50 {
                    low_confidence_regions.push(instruction.address);
                }
                match instruction.kind {
                    InstructionKind::Nop => {
                        let value = ir
                            .values
                            .get(index)
                            .map(|value| value.name.as_str())
                            .unwrap_or("v?");
                        text.push_str(&format!("  let {value} = nop();\n"));
                    }
                    InstructionKind::Call(target) => {
                        text.push_str(&format!("  call sub_{target:x}();\n"));
                    }
                    InstructionKind::Ret => {
                        text.push_str("  return;\n");
                        break;
                    }
                    InstructionKind::Jump(target) => {
                        text.push_str(&format!("  goto loc_{target:x};\n"));
                    }
                    InstructionKind::BranchIfZero(target) => {
                        text.push_str(&format!("  if zf {{ goto loc_{target:x}; }}\n"));
                    }
                    InstructionKind::Unknown => {
                        low_confidence_regions.push(instruction.address);
                        text.push_str(&format!("  opaque_asm(0x{:x});\n", instruction.address));
                    }
                }
            }

            text.push('}');
            Ok(DecompiledFunction {
                function_id,
                text,
                low_confidence_regions,
            })
        }

        pub fn review(&self, output: &DecompiledFunction) -> DecompilerReview {
            DecompilerReview {
                variable_mappings: vec![format!("v0 -> function_0x{:x}_temp0", output.function_id)],
                type_conflicts: Vec::new(),
                low_confidence_regions: output.low_confidence_regions.clone(),
            }
        }
    }
}

pub mod plugins {
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SandboxMode {
        Wasm,
        OutOfProcess,
        TrustedCore,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Capability {
        ReadBinary,
        EmitDecodeFacts,
        EmitIr,
        EmitAnalysisFacts,
        DecompilerRewrite,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PluginManifest {
        pub id: String,
        pub api_version: u32,
        pub sandbox: SandboxMode,
        pub capabilities: Vec<Capability>,
        pub deterministic: bool,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct PluginDiagnostics {
        pub crashes: u32,
        pub rejected_facts: u32,
        pub timeout_count: u32,
        pub memory_limit_hits: u32,
    }

    #[derive(Debug, Clone)]
    struct PluginState {
        manifest: PluginManifest,
        enabled: bool,
        diagnostics: PluginDiagnostics,
    }

    #[derive(Debug, Default, Clone)]
    pub struct PluginManager {
        plugins: BTreeMap<String, PluginState>,
    }

    impl PluginManager {
        pub fn install(&mut self, manifest: PluginManifest) -> Result<(), String> {
            if manifest.api_version != 1 {
                return Err("unsupported plugin API version".into());
            }
            if manifest.id.trim().is_empty() {
                return Err("plugin id must not be empty".into());
            }
            self.plugins.insert(
                manifest.id.clone(),
                PluginState {
                    manifest,
                    enabled: false,
                    diagnostics: PluginDiagnostics::default(),
                },
            );
            Ok(())
        }

        pub fn enable(&mut self, id: &str) -> Result<(), String> {
            let state = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| format!("unknown plugin {id}"))?;
            state.enabled = true;
            Ok(())
        }

        pub fn submit_fact(&mut self, id: &str, fact: &str) -> Result<(), String> {
            let state = self
                .plugins
                .get_mut(id)
                .ok_or_else(|| format!("unknown plugin {id}"))?;
            if !state.enabled {
                return Err("plugin is not enabled".into());
            }
            if !state
                .manifest
                .capabilities
                .contains(&Capability::EmitAnalysisFacts)
            {
                state.diagnostics.rejected_facts += 1;
                return Err("fact rejected: plugin lacks analysis fact capability".into());
            }
            if fact.contains("bad-address") || fact.trim().is_empty() {
                state.diagnostics.rejected_facts += 1;
                return Err("fact rejected: validation failed".into());
            }
            Ok(())
        }

        pub fn diagnostics(&self, id: &str) -> PluginDiagnostics {
            self.plugins
                .get(id)
                .map(|state| state.diagnostics.clone())
                .unwrap_or_default()
        }
    }
}

pub mod storage {
    use crate::graph::{Cfg, Edge};
    use crate::snapshot::stable_hash;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FactVersion(pub u64);

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StoredCfg {
        pub cache_token: u64,
        pub fact_version: FactVersion,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct GraphSlice {
        pub graph_kind: String,
        pub edges: Vec<Edge>,
        pub next_page_token: Option<usize>,
        pub cache_token: u64,
    }

    #[derive(Debug, Default, Clone)]
    pub struct FactStore {
        cfg_edges: Vec<Edge>,
        cfg_cache_token: u64,
        next_version: u64,
    }

    impl FactStore {
        pub fn store_cfg(&mut self, cfg: &Cfg) -> Result<StoredCfg, String> {
            let token = cfg_token(cfg);
            if token != self.cfg_cache_token {
                self.cfg_edges = cfg.edges.clone();
                self.cfg_cache_token = token;
                self.next_version += 1;
            }
            Ok(StoredCfg {
                cache_token: self.cfg_cache_token,
                fact_version: FactVersion(self.next_version),
            })
        }

        pub fn graph_slice(
            &self,
            graph_kind: &str,
            page_token: usize,
            limit: usize,
        ) -> Result<GraphSlice, String> {
            if graph_kind != "cfg" {
                return Err("only cfg graph is stored in this prototype".into());
            }
            let limit = limit.max(1);
            let edges = self
                .cfg_edges
                .iter()
                .skip(page_token)
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            let next = page_token + edges.len();
            Ok(GraphSlice {
                graph_kind: graph_kind.into(),
                edges,
                next_page_token: (next < self.cfg_edges.len()).then_some(next),
                cache_token: self.cfg_cache_token,
            })
        }
    }

    fn cfg_token(cfg: &Cfg) -> u64 {
        let mut bytes = Vec::new();
        let mut edges = cfg.edges.clone();
        edges.sort_by_key(|edge| (edge.from, edge.to, edge.kind as u8));
        for edge in &edges {
            bytes.extend_from_slice(&edge.from.to_le_bytes());
            bytes.extend_from_slice(&edge.to.to_le_bytes());
            bytes.push(edge.kind as u8);
        }
        stable_hash(&bytes)
    }
}

pub mod api {
    use crate::analysis::{AnalysisEngine, AnalysisEvent, AnalysisFacts};
    use crate::decode::Program;
    use crate::ir::{IrProgram, Lifter};
    use crate::storage::{FactStore, GraphSlice};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CorrectionKind {
        FunctionSignature,
        Name,
        Type,
        FunctionBoundary,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProjectSummary {
        pub instruction_count: usize,
        pub function_count: usize,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CorrectionResult {
        pub fact_version: u64,
        pub invalidated_artifacts: Vec<String>,
    }

    #[derive(Debug, Clone)]
    pub struct BackendService {
        program: Program,
        ir: IrProgram,
        facts: AnalysisFacts,
        analysis: AnalysisEngine,
        store: FactStore,
        correction_version: u64,
    }

    impl BackendService {
        pub fn from_program(program: Program) -> Self {
            let ir = Lifter
                .lift_program(&program)
                .expect("program generated by built-in decoder must lift");
            let mut analysis = AnalysisEngine::default();
            let facts = analysis
                .analyze_program(&program, &ir)
                .expect("program generated by built-in decoder must analyze");
            let mut store = FactStore::default();
            let _ = store.store_cfg(&program.cfg);
            Self {
                program,
                ir,
                facts,
                analysis,
                store,
                correction_version: 0,
            }
        }

        pub fn project_summary(&self) -> ProjectSummary {
            ProjectSummary {
                instruction_count: self.program.instructions.len(),
                function_count: self.facts.functions.len(),
            }
        }

        pub fn cfg_slice(&self, page_token: usize, limit: usize) -> Result<GraphSlice, String> {
            self.store.graph_slice("cfg", page_token, limit)
        }

        pub fn submit_correction(
            &mut self,
            target: u64,
            kind: CorrectionKind,
            payload: impl Into<String>,
        ) -> Result<CorrectionResult, String> {
            let invalidated_artifacts = match kind {
                CorrectionKind::FunctionSignature => {
                    self.analysis.apply_user_signature(target, payload.into())?
                }
                CorrectionKind::Type => self.analysis.apply_user_type(target, payload.into()),
                CorrectionKind::Name => self.analysis.apply_user_name(target, payload.into()),
                CorrectionKind::FunctionBoundary => self
                    .analysis
                    .apply_function_boundary(target, payload.into()),
            };
            self.correction_version += 1;
            self.facts = self
                .analysis
                .analyze_program(&self.program, &self.ir)
                .expect("reanalyzing known-good program should succeed");
            Ok(CorrectionResult {
                fact_version: self.correction_version,
                invalidated_artifacts,
            })
        }

        pub fn events(&self) -> &[AnalysisEvent] {
            self.analysis.events()
        }
    }
}

pub mod ui {
    use crate::api::{BackendService, CorrectionKind, CorrectionResult, ProjectSummary};
    use crate::storage::GraphSlice;

    #[derive(Default)]
    pub struct ReferenceClient;

    impl ReferenceClient {
        pub fn open_project(&self, service: &BackendService) -> Result<ProjectSummary, String> {
            Ok(service.project_summary())
        }

        pub fn cfg_slice(
            &self,
            service: &BackendService,
            page_token: usize,
            limit: usize,
        ) -> Result<GraphSlice, String> {
            service.cfg_slice(page_token, limit)
        }

        pub fn submit_correction(
            &self,
            service: &mut BackendService,
            target: u64,
            kind: CorrectionKind,
            payload: impl Into<String>,
        ) -> Result<CorrectionResult, String> {
            service.submit_correction(target, kind, payload)
        }
    }
}

pub mod signatures {
    use crate::decode::Instruction;
    use crate::snapshot::stable_hash;

    pub fn semantic_signature(instructions: &[Instruction]) -> u64 {
        let mut bytes = Vec::new();
        for instruction in instructions {
            bytes.extend_from_slice(&instruction.semantic_hash.to_le_bytes());
        }
        stable_hash(&bytes)
    }
}

pub mod obfuscation {
    use crate::decode::{InstructionKind, Program};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ObfuscationFinding {
        pub address: u64,
        pub reason: String,
    }

    pub fn detect_junk_or_unknown_code(program: &Program) -> Vec<ObfuscationFinding> {
        program
            .instructions
            .iter()
            .filter(|instruction| matches!(instruction.kind, InstructionKind::Unknown))
            .map(|instruction| ObfuscationFinding {
                address: instruction.address,
                reason: "unknown instruction preserved as low-confidence code".into(),
            })
            .collect()
    }
}
