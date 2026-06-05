export type JsonSchema = Record<string, unknown>;

export interface McpTool {
  name: string;
  description: string;
  inputSchema: JsonSchema;
}

const noArgs = {
  type: "object",
  properties: {},
  additionalProperties: false,
};

const addressArg = {
  type: "object",
  properties: {
    address: { type: "string" },
  },
  required: ["address"],
  additionalProperties: false,
};

const functionSelector = {
  type: "object",
  properties: {
    address: { type: "string" },
    name: { type: "string" },
  },
  anyOf: [{ required: ["address"] }, { required: ["name"] }],
  additionalProperties: false,
};

const paginatedList = {
  type: "object",
  properties: {
    limit: { type: "integer", minimum: 1, maximum: 1000 },
    offset: { type: "integer", minimum: 0 },
  },
  additionalProperties: false,
};

const limitOnly = {
  type: "object",
  properties: {
    limit: { type: "integer", minimum: 1, maximum: 1000 },
  },
  additionalProperties: false,
};

const idArg = {
  type: "object",
  properties: {
    id: { type: "string" },
  },
  required: ["id"],
  additionalProperties: false,
};

const evidenceList = {
  type: "object",
  properties: {
    limit: { type: "integer", minimum: 1, maximum: 1000 },
    offset: { type: "integer", minimum: 0 },
    category: { type: "string" },
    severity: { type: "string" },
    source: { type: "string" },
    function: { type: "string" },
  },
  additionalProperties: false,
};

const statusList = {
  type: "object",
  properties: {
    limit: { type: "integer", minimum: 1, maximum: 1000 },
    offset: { type: "integer", minimum: 0 },
    status: { type: "string" },
  },
  additionalProperties: false,
};

export const tools: McpTool[] = [
  { name: "get_mcp_status", description: "Get bridge status, active program, policy toggles, and exposed operations", inputSchema: noArgs },
  { name: "get_current_program", description: "Get active Ghidra program metadata", inputSchema: noArgs },
  { name: "get_current_location", description: "Get current cursor location", inputSchema: noArgs },
  { name: "get_current_selection", description: "Get current selection and highlight ranges", inputSchema: noArgs },
  { name: "list_memory_blocks", description: "List memory blocks and permissions", inputSchema: noArgs },
  { name: "list_functions", description: "List functions in address order", inputSchema: paginatedList },
  { name: "get_function", description: "Get function metadata by address or name", inputSchema: functionSelector },
  { name: "get_symbols", description: "List symbols in the program", inputSchema: paginatedList },
  { name: "get_strings", description: "List defined strings", inputSchema: limitOnly },
  { name: "get_imports", description: "List imported external symbols", inputSchema: limitOnly },
  { name: "get_exports", description: "List exported entry point symbols", inputSchema: limitOnly },
  {
    name: "read_bytes",
    description: "Read raw bytes from the current program",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        size: { type: "integer", minimum: 1, maximum: 4096 },
      },
      required: ["address", "size"],
      additionalProperties: false,
    },
  },
  {
    name: "get_disassembly",
    description: "Get disassembly starting at an address",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 200 },
      },
      required: ["address"],
      additionalProperties: false,
    },
  },
  {
    name: "get_xrefs_to",
    description: "Get references to an address",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 1000 },
      },
      required: ["address"],
      additionalProperties: false,
    },
  },
  { name: "get_xrefs_from", description: "Get references from an address", inputSchema: addressArg },
  {
    name: "get_callers",
    description: "Get functions that call a selected function",
    inputSchema: {
      ...functionSelector,
      properties: { ...functionSelector.properties, limit: { type: "integer", minimum: 1, maximum: 1000 } },
    },
  },
  {
    name: "get_callees",
    description: "Get functions called by a selected function",
    inputSchema: {
      ...functionSelector,
      properties: { ...functionSelector.properties, limit: { type: "integer", minimum: 1, maximum: 1000 } },
    },
  },
  {
    name: "decompile_function",
    description: "Decompile a function by address or name",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        name: { type: "string" },
        timeoutSeconds: { type: "integer", minimum: 1, maximum: 300 },
        maxChars: { type: "integer", minimum: 100, maximum: 200000 },
      },
      anyOf: [{ required: ["address"] }, { required: ["name"] }],
      additionalProperties: false,
    },
  },
  {
    name: "rename_symbol",
    description: "Rename a function or symbol using the token-authenticated Ghidra session",
    inputSchema: {
      type: "object",
      properties: { address: { type: "string" }, name: { type: "string" } },
      required: ["address", "name"],
      additionalProperties: false,
    },
  },
  {
    name: "set_pre_comment",
    description: "Set a pre-comment using the token-authenticated Ghidra session",
    inputSchema: {
      type: "object",
      properties: { address: { type: "string" }, comment: { type: "string" } },
      required: ["address", "comment"],
      additionalProperties: false,
    },
  },
  {
    name: "set_plate_comment",
    description: "Set a plate comment using the token-authenticated Ghidra session",
    inputSchema: {
      type: "object",
      properties: { address: { type: "string" }, comment: { type: "string" } },
      required: ["address", "comment"],
      additionalProperties: false,
    },
  },
  {
    name: "add_bookmark",
    description: "Add a Ghidra bookmark using the token-authenticated Ghidra session",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        category: { type: "string" },
        comment: { type: "string" },
      },
      required: ["address", "comment"],
      additionalProperties: false,
    },
  },
  {
    name: "set_function_signature",
    description: "Apply a function signature using the token-authenticated Ghidra session",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        name: { type: "string" },
        signature: { type: "string" },
      },
      anyOf: [{ required: ["address", "signature"] }, { required: ["name", "signature"] }],
      required: ["signature"],
      additionalProperties: false,
    },
  },
  { name: "goto_address", description: "Navigate the Ghidra UI to an address", inputSchema: addressArg },
  {
    name: "list_ghidra_scripts",
    description: "List Java/Python Ghidra scripts; requires the script-execution policy toggle",
    inputSchema: {
      type: "object",
      properties: {
        extension: { type: "string", description: "Optional extension filter such as .java or .py" },
        limit: { type: "integer", minimum: 1, maximum: 5000 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "run_ghidra_script",
    description:
      "Run a policy-gated Ghidra script with full current tool/program state. Supports Java scripts and Python/PyGhidra scripts when PyGhidra is active.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Script name from Ghidra script paths" },
        path: { type: "string", description: "Absolute script file path" },
        source: { type: "string", description: "Inline script source to run from a temporary file" },
        extension: { type: "string", description: "Inline source extension, e.g. .java or .py" },
        args: { type: "array", items: { type: "string" } },
        maxOutputChars: { type: "integer", minimum: 1000, maximum: 2000000 },
      },
      anyOf: [{ required: ["name"] }, { required: ["path"] }, { required: ["source"] }],
      additionalProperties: false,
    },
  },
  {
    name: "select_range",
    description: "Select an address range in the Ghidra UI",
    inputSchema: {
      type: "object",
      properties: { start: { type: "string" }, end: { type: "string" } },
      required: ["start", "end"],
      additionalProperties: false,
    },
  },
  {
    name: "highlight_range",
    description: "Highlight an address range in the Ghidra UI",
    inputSchema: {
      type: "object",
      properties: { start: { type: "string" }, end: { type: "string" } },
      required: ["start", "end"],
      additionalProperties: false,
    },
  },
  { name: "ai_status", description: "Get AI analysis suite state counts", inputSchema: noArgs },
  {
    name: "create_agent_task",
    description: "Queue an AI-assisted analysis task inside Ghidra; requires the AI-suite state-write policy toggle",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string" },
        prompt: { type: "string" },
      },
      required: ["title"],
      additionalProperties: false,
    },
  },
  { name: "list_agent_tasks", description: "List AI agent tasks", inputSchema: statusList },
  { name: "approve_agent_task", description: "Approve a queued AI agent task; requires AI-suite state-write policy", inputSchema: idArg },
  { name: "cancel_agent_task", description: "Cancel an AI agent task; requires AI-suite state-write policy", inputSchema: idArg },
  { name: "run_triage", description: "Run evidence-backed malware triage for the active program; requires AI-suite state-write policy", inputSchema: noArgs },
  { name: "start_triage_task", description: "Start evidence-backed malware triage as a background AI task; requires AI-suite state-write policy", inputSchema: noArgs },
  { name: "list_evidence", description: "List AI analysis evidence records", inputSchema: evidenceList },
  { name: "get_evidence", description: "Get one evidence record by id", inputSchema: idArg },
  {
    name: "explain_with_evidence",
    description: "Explain a specific evidence record or top evidence records with citations",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 25 },
      },
      additionalProperties: false,
    },
  },
  { name: "list_session_events", description: "List AI analysis session timeline events", inputSchema: paginatedList },
  { name: "export_ai_session", description: "Export the active AI analysis session as JSON", inputSchema: noArgs },
  {
    name: "import_ai_session",
    description: "Import an AI analysis session JSON object; requires AI-suite state-write policy",
    inputSchema: {
      type: "object",
      properties: {
        session: { type: "object", description: "Session JSON returned by export_ai_session" },
      },
      required: ["session"],
      additionalProperties: false,
    },
  },
  {
    name: "create_hypothesis",
    description: "Create an analyst hypothesis in the AI suite; requires AI-suite state-write policy",
    inputSchema: {
      type: "object",
      properties: {
        text: { type: "string" },
      },
      required: ["text"],
      additionalProperties: false,
    },
  },
  {
    name: "link_evidence",
    description: "Link evidence to an analyst hypothesis; requires AI-suite state-write policy",
    inputSchema: {
      type: "object",
      properties: {
        hypothesisId: { type: "string" },
        evidenceId: { type: "string" },
      },
      required: ["hypothesisId", "evidenceId"],
      additionalProperties: false,
    },
  },
  {
    name: "set_hypothesis_status",
    description: "Set hypothesis status to open, supported, rejected, or needs_review; requires AI-suite state-write policy",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        status: { type: "string", enum: ["open", "supported", "rejected", "needs_review"] },
      },
      required: ["id", "status"],
      additionalProperties: false,
    },
  },
  { name: "list_hypotheses", description: "List analyst hypotheses", inputSchema: statusList },
  {
    name: "semantic_function_search",
    description: "Search functions with deterministic local semantic features",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" },
        limit: { type: "integer", minimum: 1, maximum: 100 },
      },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "find_suspicious_control_flow",
    description: "Find functions with suspicious branch density or flattened-looking control flow",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "draft_yara_rule",
    description: "Draft a YARA rule from collected evidence without applying or saving it",
    inputSchema: {
      type: "object",
      properties: {
        familyName: { type: "string" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "draft_config_extractor",
    description: "Draft a reproducible config extractor spec from collected evidence",
    inputSchema: noArgs,
  },
  {
    name: "suggest_type_recovery",
    description: "Suggest preview-only type recovery candidates for the active program",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 200 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "import_sandbox_evidence",
    description: "Import file-based sandbox evidence from a local JSON or CSV file; requires AI-suite state-write policy",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string" },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "map_runtime_event_to_function",
    description: "Map a runtime event address back to its containing Ghidra function",
    inputSchema: {
      type: "object",
      properties: {
        address: { type: "string" },
        rva: { type: "string" },
        module: { type: "string" },
        imageBase: { type: "string" },
        processId: { type: "string" },
        threadId: { type: "string" },
        timestamp: { type: "string" },
        eventType: { type: "string" },
      },
      anyOf: [{ required: ["address"] }, { required: ["rva"] }],
      additionalProperties: false,
    },
  },
  { name: "analyze_changes", description: "Run Ghidra analysis on pending changes", inputSchema: noArgs },
  { name: "analyze_all", description: "Re-run full Ghidra analysis", inputSchema: noArgs },
];
