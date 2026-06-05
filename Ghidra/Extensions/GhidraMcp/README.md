# Ghidra MCP Extension

`GhidraMcp` exposes a curated set of Ghidra operations to local AI tools through a loopback bridge and a stdio MCP wrapper.

## Build

From the repository root:

```powershell
./gradlew.bat :GhidraMcp:buildExtension
```

Install the generated extension zip from the module's `dist` directory using `File -> Install Extensions`, then restart Ghidra and enable the `Ghidra MCP` plugin.

## Use

1. Open a program in Ghidra.
2. Choose `Tools -> Ghidra MCP -> Start Bridge`.
3. Choose `Tools -> Ghidra MCP -> Copy Bridge Token`.
4. Configure the MCP wrapper in `mcp-server` with `GHIDRA_MCP_URL` and `GHIDRA_MCP_TOKEN`.

Read-only operations include function, symbol, string, memory block, xref, disassembly, and decompiler queries. UI-only operations can navigate, select, and highlight ranges. Annotation writes and analysis writes are disabled by default and require explicit `Tools -> Ghidra MCP` toggles plus per-call confirmation.

## Malware Analysis Safety

This extension is meant to help inspect and annotate programs already loaded into Ghidra. It does not execute malware samples, launch processes, delete files, or run arbitrary Ghidra scripts from AI instructions. Keep dangerous automation out of the MCP surface unless a future version adds a separate allowlist and confirmation model for those operations.
