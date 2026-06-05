# Backend-First Reverse Engineering Platform Prototype

This crate is a backend-first prototype for the reverse engineering architecture plan. It keeps the core engine separate from UI concerns while exposing API contracts for graph inspection, decompiler review, plugin diagnostics, and user corrections.

Implemented slices:

- Immutable binary snapshots with chunk materialization accounting.
- Loader detection and sparse memory mapping.
- Built-in architecture registry with an x86 decoder prototype.
- Recursive-descent disassembly with CFG edge facts.
- Layered IR with raw, normalized, and SSA layers plus memory states and effects.
- Deterministic analysis facts for functions and cross references.
- Decompiler output and review diagnostics.
- Sandboxed plugin manifests, capabilities, validation, and diagnostics.
- Fact storage with graph slices and cache tokens.
- Backend service and reference client APIs for thin UI/client workflows.

Run the verification suite:

```text
cargo test
```

Run the reference CLI smoke path:

```text
cargo run --bin re-platform-cli
```
