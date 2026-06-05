# CLI Client

The reference CLI smoke path is implemented as `src/re_platform_cli.rs` and exposed by the explicit `re-platform-cli` Cargo binary target.

It builds a tiny in-memory firmware sample, runs loader, memory map, decoder, backend service, reference client, and correction flows, then prints a compact summary suitable for automation.
