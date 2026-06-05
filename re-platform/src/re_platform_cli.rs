use re_platform::api::{BackendService, CorrectionKind};
use re_platform::arch::{Architecture, ArchitectureRegistry};
use re_platform::decode::DisassemblyEngine;
use re_platform::loader::{LoaderRegistry, MemoryMap, Permission};
use re_platform::snapshot::BinarySnapshot;
use re_platform::ui::ReferenceClient;

fn main() {
    let snapshot = BinarySnapshot::from_bytes(
        "demo-fw.bin",
        vec![0x90, 0xe8, 0x01, 0x00, 0x00, 0x00, 0xc3, 0xc3],
        4096,
    );
    let load = LoaderRegistry
        .load(&snapshot)
        .expect("demo snapshot should load");
    let mut map = MemoryMap::new(load.snapshot_id);
    map.add_segment(
        "rom",
        0x1000,
        0,
        snapshot.len() as u64,
        Permission::ReadExecute,
    )
    .expect("demo segment should map");

    let decoder = ArchitectureRegistry::with_builtin_decoders()
        .decoder(Architecture::X86)
        .expect("x86 decoder should be registered");
    let program = DisassemblyEngine::new(decoder)
        .analyze(&snapshot, &map, 0x1000)
        .expect("demo program should disassemble");

    let mut service = BackendService::from_program(program);
    let client = ReferenceClient;
    let summary = client
        .open_project(&service)
        .expect("reference client should open demo project");
    let correction = client
        .submit_correction(
            &mut service,
            0x1007,
            CorrectionKind::FunctionSignature,
            "int target(char *buf, size_t len)",
        )
        .expect("demo correction should apply");

    println!(
        "instructions={} functions={} invalidated={}",
        summary.instruction_count,
        summary.function_count,
        correction.invalidated_artifacts.len()
    );
}
