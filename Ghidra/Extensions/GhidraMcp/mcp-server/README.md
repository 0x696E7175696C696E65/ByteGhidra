# Ghidra MCP Server

This package is the stdio MCP wrapper for the Ghidra MCP bridge extension. Cursor or another MCP client launches this process, and the process forwards tool calls to the local Ghidra plugin bridge.

## Setup

1. Build and install the `GhidraMcp` extension.
2. Open Ghidra, enable the `Ghidra MCP` plugin, then choose `Tools -> Ghidra MCP -> Start Bridge`.
3. Choose `Tools -> Ghidra MCP -> Copy Bridge Token`.
4. Build this wrapper:

```powershell
npm install
npm run build
```

5. Configure your MCP client with:

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "node",
      "args": ["C:/path/to/Ghidra/Extensions/GhidraMcp/mcp-server/dist/index.js"],
      "env": {
        "GHIDRA_MCP_URL": "http://127.0.0.1:18090",
        "GHIDRA_MCP_TOKEN": "paste-token-from-ghidra"
      }
    }
  }
}
```

## Safety Model

The bridge binds to `127.0.0.1` and requires the per-session token on each call. Read-only tools and UI navigation are available by default. Annotation tools such as comments, bookmarks, and renames require enabling `Tools -> Ghidra MCP -> Token Grants Annotation Writes` in Ghidra and confirming each write. AI-suite task/evidence/hypothesis changes require the separate AI-suite state-write toggle. Program analysis tools require the separate program-analysis toggle. Ghidra script listing and execution require the separate script-execution toggle and confirmation. The wrapper rejects non-loopback `GHIDRA_MCP_URL` values by default. The bridge does not expose process launch, file deletion, or unrestricted project mutation.

## AI Suite Tools

The wrapper also exposes the AI malware-analysis suite:

- Task and session tools: `create_agent_task`, `list_agent_tasks`, `approve_agent_task`, `cancel_agent_task`, `list_session_events`
- Evidence and triage tools: `run_triage`, `list_evidence`, `get_evidence`, `explain_with_evidence`
- Hypothesis tools: `create_hypothesis`, `link_evidence`, `set_hypothesis_status`, `list_hypotheses`
- Program understanding tools: `semantic_function_search`, `find_suspicious_control_flow`
- Draft generation tools: `draft_yara_rule`, `draft_config_extractor`, `suggest_type_recovery`
- Sandbox import tools: `import_sandbox_evidence`, `map_runtime_event_to_function`

`run_triage`, task changes, hypothesis changes, and sandbox imports mutate only the suite's analysis state, but they still use the bridge's AI-suite state-write policy gate. Draft generation tools return preview artifacts; they do not write files or apply types automatically.

Example tool arguments:

```json
{ "title": "Find config parser", "prompt": "Locate functions that parse network or persistence config." }
```

```json
{ "query": "network connect http beacon", "limit": 10 }
```

```json
{ "familyName": "suspect_loader" }
```

```json
{ "path": "C:/analysis/sample-sandbox-events.json" }
```

Run `run_triage` before `draft_yara_rule` or `draft_config_extractor` so the evidence store has useful strings and indicators to work from.
