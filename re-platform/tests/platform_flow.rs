use re_platform::analysis::{AnalysisEngine, AnalysisEvent};
use re_platform::api::{BackendService, CorrectionKind};
use re_platform::arch::{Architecture, ArchitectureRegistry};
use re_platform::decode::DisassemblyEngine;
use re_platform::decompiler::Decompiler;
use re_platform::graph::EdgeKind;
use re_platform::ir::{IrLayer, Lifter};
use re_platform::loader::{BinaryFormat, LoaderRegistry, MemoryMap, Permission};
use re_platform::plugins::{Capability, PluginManager, PluginManifest, SandboxMode};
use re_platform::snapshot::BinarySnapshot;
use re_platform::storage::FactStore;
use re_platform::ui::ReferenceClient;

#[test]
fn phase1_loads_maps_decodes_and_builds_cfg_lazily() {
    let snapshot = BinarySnapshot::from_bytes(
        "tiny-fw.bin",
        vec![0x90, 0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3],
        4,
    );

    assert_eq!(snapshot.len(), 8);
    assert_eq!(snapshot.materialized_chunk_count(), 0);
    assert_eq!(snapshot.read_range(4, 2), Some(vec![0, 0]));
    assert_eq!(snapshot.materialized_chunk_count(), 1);

    let load = LoaderRegistry.load(&snapshot).expect("loads raw firmware");
    assert_eq!(load.format, BinaryFormat::RawFirmware);

    let mut map = MemoryMap::new(load.snapshot_id);
    map.add_segment(
        "rom",
        0x1000,
        0,
        snapshot.len() as u64,
        Permission::ReadExecute,
    )
    .expect("segment maps");
    assert_eq!(map.read_u8(&snapshot, 0x1000), Some(0x90));

    let decoder = ArchitectureRegistry::with_builtin_decoders()
        .decoder(Architecture::X86)
        .expect("x86 decoder is registered");
    let program = DisassemblyEngine::new(decoder)
        .analyze(&snapshot, &map, 0x1000)
        .expect("disassembly succeeds");

    assert_eq!(program.instructions.len(), 4);
    assert!(
        program
            .instructions
            .iter()
            .any(|instruction| instruction.address == 0x1007)
    );
    assert!(
        program.cfg.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Call && edge.from == 0x1001 && edge.to == 0x1007
        })
    );
    assert!(
        program
            .cfg
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Return)
    );
}

#[test]
fn phase2_lifts_ssa_discovers_functions_and_invalidates_precisely() {
    let program = sample_program();
    let ir = Lifter.lift_program(&program).expect("ir lifts");

    assert!(ir.layers.contains(&IrLayer::Raw));
    assert!(ir.layers.contains(&IrLayer::Ssa));
    assert!(!ir.values.is_empty());
    assert!(ir.memory_states.iter().any(|state| state.region == "stack"));
    assert!(ir.effects.iter().any(|effect| effect.kind == "call"));

    let mut analysis = AnalysisEngine::default();
    let facts = analysis
        .analyze_program(&program, &ir)
        .expect("analysis completes");

    assert!(
        facts
            .functions
            .iter()
            .any(|function| function.entry == 0x1000)
    );
    assert!(
        facts
            .functions
            .iter()
            .any(|function| function.entry == 0x1007)
    );

    let invalidated = analysis
        .apply_user_signature(0x1007, "int target(char *buf, size_t len)")
        .expect("user correction applies");

    assert!(
        invalidated
            .iter()
            .any(|artifact| artifact.contains("function:0x1007"))
    );
    assert!(
        !invalidated
            .iter()
            .any(|artifact| artifact.contains("function:0x2000"))
    );
    assert!(
        analysis
            .events()
            .contains(&AnalysisEvent::TypeFactChanged(0x1007))
    );
}

#[test]
fn phase3_decompiles_with_type_feedback_and_review_diagnostics() {
    let program = sample_program();
    let ir = Lifter.lift_program(&program).expect("ir lifts");
    let mut analysis = AnalysisEngine::default();
    let facts = analysis
        .analyze_program(&program, &ir)
        .expect("analysis completes");

    let output = Decompiler
        .decompile(0x1000, &program, &ir, &facts)
        .expect("decompiles");

    assert!(output.text.contains("fn sub_1000"));
    assert!(output.text.contains("call sub_1007"));
    assert!(output.low_confidence_regions.is_empty());

    let review = Decompiler.review(&output);
    assert!(
        review
            .variable_mappings
            .iter()
            .any(|mapping| mapping.contains("v0"))
    );
}

#[test]
fn phase4_sandboxes_plugins_and_rejects_corrupt_facts() {
    let mut manager = PluginManager::default();
    let manifest = PluginManifest {
        id: "x86-extra".into(),
        api_version: 1,
        sandbox: SandboxMode::Wasm,
        capabilities: vec![Capability::ReadBinary, Capability::EmitAnalysisFacts],
        deterministic: true,
    };

    manager.install(manifest).expect("plugin installs");
    manager.enable("x86-extra").expect("plugin enables");

    let rejection = manager
        .submit_fact("x86-extra", "edge:bad-address")
        .expect_err("invalid fact is rejected");

    assert!(rejection.contains("rejected"));
    assert_eq!(manager.diagnostics("x86-extra").rejected_facts, 1);
}

#[test]
fn phase5_serves_bounded_graph_slices_and_uses_cache_tokens() {
    let program = sample_program();
    let mut store = FactStore::default();
    let first = store.store_cfg(&program.cfg).expect("cfg stored");
    let second = store.store_cfg(&program.cfg).expect("cfg cache hit");

    assert_eq!(first.cache_token, second.cache_token);

    let slice = store.graph_slice("cfg", 0, 1).expect("slice fetched");
    assert_eq!(slice.edges.len(), 1);
    assert!(slice.next_page_token.is_some());
}

#[test]
fn phase6_reference_client_applies_corrections_and_observes_recomputation() {
    let program = sample_program();
    let mut service = BackendService::from_program(program);
    let client = ReferenceClient;

    let project = client.open_project(&service).expect("project opens");
    assert_eq!(project.instruction_count, 4);

    let graph = client.cfg_slice(&service, 0, 10).expect("cfg slice loads");
    assert!(!graph.edges.is_empty());

    let correction = client
        .submit_correction(
            &mut service,
            0x1007,
            CorrectionKind::FunctionSignature,
            "int target(char *buf, size_t len)",
        )
        .expect("correction accepted");

    assert!(
        correction
            .invalidated_artifacts
            .iter()
            .any(|artifact| { artifact.contains("function:0x1007") })
    );
    assert!(
        service
            .events()
            .iter()
            .any(|event| { matches!(event, AnalysisEvent::TypeFactChanged(0x1007)) })
    );
}

fn sample_program() -> re_platform::decode::Program {
    let snapshot = BinarySnapshot::from_bytes(
        "tiny-fw.bin",
        vec![0x90, 0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3],
        4,
    );
    let load = LoaderRegistry.load(&snapshot).expect("loads raw firmware");
    let mut map = MemoryMap::new(load.snapshot_id);
    map.add_segment(
        "rom",
        0x1000,
        0,
        snapshot.len() as u64,
        Permission::ReadExecute,
    )
    .expect("segment maps");
    let decoder = ArchitectureRegistry::with_builtin_decoders()
        .decoder(Architecture::X86)
        .expect("x86 decoder is registered");
    DisassemblyEngine::new(decoder)
        .analyze(&snapshot, &map, 0x1000)
        .expect("disassembly succeeds")
}
