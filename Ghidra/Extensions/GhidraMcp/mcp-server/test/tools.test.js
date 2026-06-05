const assert = require("node:assert/strict");
const test = require("node:test");

test("tool definitions expose action-first Ghidra operations", () => {
  const { tools } = require("../dist/tools.js");
  const names = tools.map(tool => tool.name);

  assert.ok(names.includes("get_current_program"));
  assert.ok(names.includes("decompile_function"));
  assert.ok(names.includes("set_pre_comment"));
  assert.ok(names.includes("goto_address"));
  assert.ok(names.includes("run_triage"));
  assert.ok(names.includes("start_triage_task"));
  assert.ok(names.includes("explain_with_evidence"));
  assert.ok(names.includes("semantic_function_search"));
  assert.ok(names.includes("draft_yara_rule"));
  assert.ok(names.includes("import_sandbox_evidence"));
});

test("tool definitions use bounded object schemas", () => {
  const { tools } = require("../dist/tools.js");

  for (const tool of tools) {
    assert.equal(tool.inputSchema.type, "object", tool.name);
    assert.equal(tool.inputSchema.additionalProperties, false, tool.name);
  }
});

test("tool argument validator rejects missing required fields and extra properties", () => {
  const { tools } = require("../dist/tools.js");
  const { validateToolArguments } = require("../dist/validator.js");
  const readBytes = tools.find(tool => tool.name === "read_bytes");

  assert.deepEqual(validateToolArguments(readBytes, { address: "00401000" }), [
    "Missing required property: size",
  ]);
  assert.deepEqual(validateToolArguments(readBytes, {
    address: "00401000",
    size: 4,
    extra: true,
  }), ["Unknown property: extra"]);
  assert.deepEqual(validateToolArguments(readBytes, { address: "00401000", size: 4 }), []);
});
