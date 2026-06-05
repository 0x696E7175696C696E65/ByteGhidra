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

The bridge binds to `127.0.0.1` and requires the per-session token on each call. Read-only tools and UI navigation are available by default. Annotation tools such as comments, bookmarks, and renames require enabling `Tools -> Ghidra MCP -> Allow Annotation Writes` in Ghidra and confirming each write. Analysis tools require the separate analysis-write toggle. The wrapper rejects non-loopback `GHIDRA_MCP_URL` values by default. The first version does not expose arbitrary script execution, process launch, file deletion, or unrestricted project mutation.
