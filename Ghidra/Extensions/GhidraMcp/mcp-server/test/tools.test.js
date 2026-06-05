const assert = require("node:assert/strict");
const test = require("node:test");

test("tool definitions expose action-first Ghidra operations", () => {
  const { tools } = require("../dist/tools.js");
  const names = tools.map(tool => tool.name);

  assert.ok(names.includes("get_current_program"));
  assert.ok(names.includes("decompile_function"));
  assert.ok(names.includes("set_pre_comment"));
  assert.ok(names.includes("goto_address"));
});

test("tool definitions use bounded object schemas", () => {
  const { tools } = require("../dist/tools.js");

  for (const tool of tools) {
    assert.equal(tool.inputSchema.type, "object", tool.name);
    assert.equal(tool.inputSchema.additionalProperties, false, tool.name);
  }
});
