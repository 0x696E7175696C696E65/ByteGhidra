#!/usr/bin/env node
declare function require(name: string): any;
declare const process: {
  stdin: unknown;
  stdout: { write(chunk: string): void };
  stderr: { write(chunk: string): void };
};

import { BridgeClient } from "./bridgeClient";
import { tools } from "./tools";

const readline = require("node:readline");
const bridge = new BridgeClient();
const toolNames = new Set(tools.map(tool => tool.name));

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: unknown;
}

function write(message: unknown): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function result(id: string | number | null | undefined, value: unknown): void {
  write({ jsonrpc: "2.0", id, result: value });
}

function error(id: string | number | null | undefined, code: number, message: string): void {
  write({ jsonrpc: "2.0", id, error: { code, message } });
}

async function handle(request: JsonRpcRequest): Promise<void> {
  if (request.id === undefined || request.id === null) {
    return;
  }
  if (request.jsonrpc !== "2.0" || typeof request.method !== "string") {
    error(request.id, -32600, "Invalid JSON-RPC request");
    return;
  }

  switch (request.method) {
    case "initialize":
      result(request.id, {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "ghidra-mcp", version: "0.1.0" },
      });
      return;
    case "tools/list":
      result(request.id, { tools });
      return;
    case "tools/call": {
      if (!isPlainObject(request.params)) {
        error(request.id, -32602, "tools/call requires object params");
        return;
      }
      const name = request.params.name;
      const args = request.params.arguments ?? {};
      if (typeof name !== "string") {
        error(request.id, -32602, "tools/call requires params.name");
        return;
      }
      if (!toolNames.has(name)) {
        error(request.id, -32602, `Unknown tool: ${name}`);
        return;
      }
      if (!isPlainObject(args)) {
        error(request.id, -32602, "tools/call params.arguments must be an object");
        return;
      }
      const response = await bridge.call(name, args);
      if (!response.success) {
        result(request.id, {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(response.error ?? { code: "unknown", message: "Unknown bridge error" }, null, 2),
            },
          ],
        });
        return;
      }
      result(request.id, {
        isError: false,
        content: [
          {
            type: "text",
            text: JSON.stringify(
              { result: response.result ?? {}, truncated: Boolean(response.truncated) },
              null,
              2,
            ),
          },
        ],
      });
      return;
    }
    default:
      error(request.id, -32601, `Unsupported MCP method: ${request.method ?? ""}`);
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", (line: string) => {
  void (async () => {
    try {
      const parsed = JSON.parse(line);
      if (!isPlainObject(parsed)) {
        error(null, -32600, "Invalid JSON-RPC request");
        return;
      }
      await handle(parsed);
    }
    catch (e) {
      error(null, -32700, e instanceof Error ? e.message : String(e));
    }
  })();
});
