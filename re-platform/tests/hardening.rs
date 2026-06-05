use std::process::Command;

use re_platform::api::{BackendService, CorrectionKind};
use re_platform::arch::{Architecture, ArchitectureRegistry};
use re_platform::decode::DisassemblyEngine;
use re_platform::graph::{Cfg, EdgeKind};
use re_platform::loader::{LoaderRegistry, MemoryMap, Permission};
use re_platform::snapshot::BinarySnapshot;
use re_platform::storage::FactStore;

#[test]
fn rejects_truncated_x86_control_flow_instructions() {
    let snapshot = BinarySnapshot::from_bytes("truncated.bin", vec![0xe8, 0x01], 4);
    let load = LoaderRegistry.load(&snapshot).expect("loads raw");
    let mut map = MemoryMap::new(load.snapshot_id);
    map.add_segment(
        "rom",
        0x4000,
        0,
        snapshot.len() as u64,
        Permission::ReadExecute,
    )
    .expect("maps segment");
    let decoder = ArchitectureRegistry::with_builtin_decoders()
        .decoder(Architecture::X86)
        .expect("x86 decoder exists");

    let program = DisassemblyEngine::new(decoder)
        .analyze(&snapshot, &map, 0x4000)
        .expect("analysis handles malformed bytes");

    assert!(program.instructions.is_empty());
    assert!(program.cfg.edges.is_empty());
}

#[test]
fn rejects_truncated_x86_short_branch_operands() {
    for opcode in [0xeb, 0x74] {
        let snapshot = BinarySnapshot::from_bytes("short-branch.bin", vec![opcode], 4);
        let load = LoaderRegistry.load(&snapshot).expect("loads raw");
        let mut map = MemoryMap::new(load.snapshot_id);
        map.add_segment(
            "rom",
            0x4000,
            0,
            snapshot.len() as u64,
            Permission::ReadExecute,
        )
        .expect("maps segment");
        let decoder = ArchitectureRegistry::with_builtin_decoders()
            .decoder(Architecture::X86)
            .expect("x86 decoder exists");

        let program = DisassemblyEngine::new(decoder)
            .analyze(&snapshot, &map, 0x4000)
            .expect("analysis handles malformed bytes");

        assert!(program.instructions.is_empty());
        assert!(program.cfg.edges.is_empty());
    }
}

#[test]
fn memory_map_refuses_reads_from_the_wrong_snapshot() {
    let mapped_snapshot = BinarySnapshot::from_bytes("mapped.bin", vec![0x90], 4);
    let wrong_snapshot = BinarySnapshot::from_bytes("wrong.bin", vec![0xc3], 4);
    let load = LoaderRegistry
        .load(&mapped_snapshot)
        .expect("loads mapped snapshot");
    let mut map = MemoryMap::new(load.snapshot_id);
    map.add_segment("rom", 0x1000, 0, 1, Permission::ReadExecute)
        .expect("maps segment");

    assert_eq!(map.read_u8(&mapped_snapshot, 0x1000), Some(0x90));
    assert_eq!(map.read_u8(&wrong_snapshot, 0x1000), None);
}

#[test]
fn correction_kinds_have_distinct_invalidation_semantics() {
    let program = sample_program();
    let mut service = BackendService::from_program(program);

    let rename = service
        .submit_correction(0x1007, CorrectionKind::Name, "target")
        .expect("rename applies");
    assert!(
        rename
            .invalidated_artifacts
            .iter()
            .any(|artifact| artifact == "function:0x1007")
    );
    assert!(
        !rename
            .invalidated_artifacts
            .iter()
            .any(|artifact| artifact == "type:0x1007")
    );

    let boundary = service
        .submit_correction(0x1007, CorrectionKind::FunctionBoundary, "0x1007..0x1008")
        .expect("boundary applies");
    assert!(
        boundary
            .invalidated_artifacts
            .iter()
            .any(|artifact| artifact == "cfg:0x1007")
    );

    let type_change = service
        .submit_correction(0x1007, CorrectionKind::Type, "struct packet *")
        .expect("type correction applies");
    assert!(
        type_change
            .invalidated_artifacts
            .iter()
            .any(|artifact| artifact == "type:0x1007")
    );
    assert!(
        !type_change
            .invalidated_artifacts
            .iter()
            .any(|artifact| artifact == "function:0x1007")
    );
}

#[test]
fn cfg_cache_tokens_are_order_insensitive() {
    let mut first = Cfg::default();
    first.add_edge(0x1000, 0x1001, EdgeKind::Fallthrough);
    first.add_edge(0x1001, 0x1007, EdgeKind::Call);

    let mut second = Cfg::default();
    second.add_edge(0x1001, 0x1007, EdgeKind::Call);
    second.add_edge(0x1000, 0x1001, EdgeKind::Fallthrough);

    let mut first_store = FactStore::default();
    let mut second_store = FactStore::default();
    let first_token = first_store
        .store_cfg(&first)
        .expect("stores first")
        .cache_token;
    let second_token = second_store
        .store_cfg(&second)
        .expect("stores second")
        .cache_token;

    assert_eq!(first_token, second_token);
}

#[test]
fn documented_cli_smoke_path_runs() {
    let output = Command::new(env!("CARGO_BIN_EXE_re-platform-cli"))
        .output()
        .expect("cli executes");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf8");
    assert!(stdout.contains("instructions=4"));
    assert!(stdout.contains("functions=2"));
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
