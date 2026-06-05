# Ghidra MCP Extension

`GhidraMcp` exposes a curated set of Ghidra operations to local AI tools through a loopback bridge and a stdio MCP wrapper.

## Build

From the repository root:

```powershell
./gradlew.bat :GhidraMcp:build :GhidraMcp:zipExtensions
```

Install the generated extension zip from the module's `dist` directory using `File -> Install Extensions`, then restart Ghidra and enable the `Ghidra MCP` plugin.

## Use

1. Open a program in Ghidra.
2. Choose `Tools -> Ghidra MCP -> Start Bridge`.
3. Choose `Tools -> Ghidra MCP -> Copy Bridge Token`.
4. Configure the MCP wrapper in `mcp-server` with `GHIDRA_MCP_URL` and `GHIDRA_MCP_TOKEN`.

Read-only operations include function, symbol, string, memory block, xref, disassembly, and decompiler queries. UI-only operations can navigate, select, and highlight ranges. Annotation writes, AI-suite state writes, program analysis writes, and script execution are disabled by default and require separate `Tools -> Ghidra MCP` toggles plus per-call confirmation.

## AI Malware Analysis Suite

Enable the `AI malware analysis suite` plugin to open the shared analysis workspace. It adds dockable providers for agent tasks, evidence, session timeline, triage dashboard, hypotheses, evidence-backed explanations, semantic function search, decompiler diff notes, suspicious control-flow candidates, YARA drafts, config extractor drafts, type-recovery suggestions, and sandbox evidence import.

The suite keeps active-program analysis state through `AiAnalysisService`, so UI actions and MCP tools operate on the same task queue, evidence records, hypotheses, and session events for the current program. Switching programs switches the active AI session instead of mixing evidence between binaries.

### Analysis Workflow

1. Open a suspicious program in Ghidra.
2. Enable both `Ghidra MCP` and `AI malware analysis suite`.
3. Queue work with `AI Analysis -> Queue Triage Task`.
4. Run deterministic triage with `AI Analysis -> Run Triage`.
5. Review the `AI Triage Dashboard`, `AI Evidence`, and `AI Explain With Evidence` providers.
6. Track analyst assumptions in `AI Hypotheses` and link supporting evidence through MCP.
7. Use semantic search and suspicious control-flow candidates to choose functions for deeper review.
8. Draft YARA rules, config extractor specs, and type-recovery suggestions as preview artifacts.

Triage records evidence for suspicious imports, network/persistence/command strings, writable-executable blocks, high-entropy blocks, and large functions. Every generated explanation cites evidence IDs instead of relying on unsupported prose.

### Sandbox Evidence Files

`AI Sandbox Evidence Import` accepts local JSON or CSV files. JSON can be a single event object, an array of events, or an object with an `events` array. CSV uses this simple shape:

```csv
address,api,category,summary
00401234,InternetConnect,network,Observed C2 connection
00404567,RegSetValue,persistence,Observed Run key write
```

Imported runtime events become `sandbox` evidence records and are mapped back to containing functions when an address is present.

Useful MCP tools include:

- `create_agent_task`, `list_agent_tasks`, `approve_agent_task`, `cancel_agent_task`
- `run_triage`, `start_triage_task`, `list_evidence`, `get_evidence`, `explain_with_evidence`
- `export_ai_session`, `import_ai_session`
- `create_hypothesis`, `link_evidence`, `set_hypothesis_status`, `list_hypotheses`
- `semantic_function_search`, `find_suspicious_control_flow`
- `draft_yara_rule`, `draft_config_extractor`, `suggest_type_recovery`
- `import_sandbox_evidence`, `map_runtime_event_to_function`

## Malware Analysis Safety

This extension is meant to help inspect and annotate programs already loaded into Ghidra. It does not execute malware samples, launch processes, or delete files. Ghidra script execution is available only when the explicit script-execution policy toggle is enabled and the user confirms the operation. Keep dangerous automation out of the MCP surface unless a future version adds a separate allowlist and confirmation model for those operations.

Generated YARA rules, config extractors, and type-recovery output are drafts. They are shown as preview data and are not applied to the program automatically. Sandbox integration is file-based only; live debugger or sandbox streaming is intentionally deferred.

## Manual Verification

1. Run `./gradlew.bat :GhidraMcp:test :GhidraMcp:testMcpServer :GhidraMcp:build :GhidraMcp:zipExtensions :GhidraMcp:verifyMcpExtensionArtifact`.
2. Build and install the extension, then enable `Ghidra MCP` and `AI malware analysis suite`.
3. Load a small binary and run `AI Analysis -> Run Triage`.
4. Confirm the triage dashboard and evidence table populate with address/function-backed records.
5. Use `AI Explain With Evidence` to verify explanations cite evidence IDs.
6. Create a hypothesis and link evidence through MCP.
7. Draft YARA/config/type suggestions and confirm they are preview-only.
8. Import a small JSON or CSV sandbox trace and verify runtime events appear in evidence.
