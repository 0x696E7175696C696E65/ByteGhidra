declare const process: {
  env: Record<string, string | undefined>;
};

declare function fetch(input: string, init?: unknown): Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
  json(): Promise<BridgeResponse>;
}>;

export interface BridgeResponse {
  success: boolean;
  result?: unknown;
  error?: {
    code: string;
    message: string;
  };
  truncated?: boolean;
}

export class BridgeClient {
  private readonly baseUrl: string;
  private readonly token: string;

  constructor(baseUrl = process.env.GHIDRA_MCP_URL ?? "http://127.0.0.1:18090", token = process.env.GHIDRA_MCP_TOKEN ?? "") {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
  }

  async call(operation: string, params: Record<string, unknown>): Promise<BridgeResponse> {
    const urlCheck = this.validateLoopbackUrl();
    if (urlCheck) {
      return urlCheck;
    }
    if (!this.token) {
      return {
        success: false,
        error: {
          code: "missing_token",
          message: "Set GHIDRA_MCP_TOKEN to the token printed by the Ghidra MCP plugin",
        },
      };
    }

    try {
      const response = await fetch(`${this.baseUrl}/execute`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "X-Ghidra-MCP-Token": this.token,
        },
        body: JSON.stringify({ operation, params }),
      });

      if (!response.ok) {
        return {
          success: false,
          error: {
            code: `http_${response.status}`,
            message: await response.text(),
          },
        };
      }

      return response.json();
    }
    catch (e) {
      return {
        success: false,
        error: {
          code: "bridge_unreachable",
          message: e instanceof Error ? e.message : String(e),
        },
      };
    }
  }

  private validateLoopbackUrl(): BridgeResponse | null {
    let parsed: URL;
    try {
      parsed = new URL(this.baseUrl);
    }
    catch {
      return {
        success: false,
        error: { code: "invalid_url", message: `Invalid GHIDRA_MCP_URL: ${this.baseUrl}` },
      };
    }
    const host = parsed.hostname.toLowerCase();
    if (host !== "127.0.0.1" && host !== "localhost" && host !== "::1" && host !== "[::1]") {
      return {
        success: false,
        error: {
          code: "unsafe_bridge_url",
          message: "GHIDRA_MCP_URL must point to a loopback host by default",
        },
      };
    }
    return null;
  }
}
