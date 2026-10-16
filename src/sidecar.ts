import { createInterface } from "node:readline";
import { SecretControlAssessmentEngine, type ComplianceFramework } from "./compliance.js";
import { AgentShieldEngine } from "./engine.js";
import { AgentCommandSandbox } from "./sandbox.js";
import type { DetectedSecret } from "./types.js";
import { AGENT_SHIELD_VERSION } from "./version.js";

export interface JsonRpcRequest {
  jsonrpc?: "2.0";
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/**
 * Language-Agnostic JSON-RPC 2.0 Stdio Sidecar Daemon:
 * Provides high-velocity sub-millisecond secret scanning, streaming redaction,
 * AST command inspection, and compliance assessment to non-Node ecosystems
 * (Python, Go, Rust, Ruby, Elixir, C++, PHP, and shell scripts).
 */
export class AgentShieldSidecar {
  private engine: AgentShieldEngine;
  private sandbox: AgentCommandSandbox;
  private startedAt: number;

  constructor(engine?: AgentShieldEngine, sandbox?: AgentCommandSandbox) {
    this.engine = engine || new AgentShieldEngine();
    this.sandbox = sandbox || new AgentCommandSandbox();
    this.startedAt = Date.now();
  }

  /**
   * Processes a single JSON-RPC 2.0 or NDJSON line and returns formatted JSON-RPC string
   */
  public async handleMessage(rawMessage: string): Promise<string> {
    const trimmed = rawMessage.trim();
    if (!trimmed) return "";

    let req: JsonRpcRequest;
    try {
      req = JSON.parse(trimmed) as JsonRpcRequest;
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const res: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32700,
          message: `Parse error: Invalid JSON payload (${errorMsg})`,
        },
      };
      return JSON.stringify(res);
    }

    const id = req.id ?? null;

    if (!req.method || typeof req.method !== "string") {
      const res: JsonRpcResponse = {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32600,
          message: "Invalid Request: 'method' must be a non-empty string.",
        },
      };
      return JSON.stringify(res);
    }

    try {
      const result = await this.dispatch(req.method, req.params || {});
      const res: JsonRpcResponse = {
        jsonrpc: "2.0",
        id,
        result,
      };
      return JSON.stringify(res);
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      const res: JsonRpcResponse = {
        jsonrpc: "2.0",
        id,
        error: {
          code: -32603,
          message: errorMsg,
        },
      };
      return JSON.stringify(res);
    }
  }

  private async dispatch(
    method: string,
    params: Record<string, unknown>,
  ): Promise<unknown> {
    switch (method) {
      case "shield.ping":
      case "ping":
        return "pong";

      case "shield.health":
      case "health":
        return {
          status: "ok",
          version: AGENT_SHIELD_VERSION,
          uptimeMs: Date.now() - this.startedAt,
          activePatternsCount: this.engine.getPatterns().length,
        };

      case "shield.scan":
      case "scan": {
        const text = String(params.text ?? "");
        const findings = this.engine.scan(text);
        return {
          hasSecrets: findings.length > 0,
          findings,
        };
      }

      case "shield.scanAndRedact":
      case "scan_and_redact":
      case "redact": {
        const text = String(params.text ?? "");
        const maskStyle = params.maskStyle as
          | "token"
          | "hash"
          | "asterisk"
          | undefined;
        return this.engine.scanAndRedact(text, { maskStyle });
      }

      case "shield.rehydrate":
      case "rehydrate": {
        const text = String(params.text ?? "");
        const rehydrated = this.engine.rehydrate(text);
        return {
          rehydratedText: rehydrated,
        };
      }

      case "shield.inspectCommand":
      case "inspect_command":
      case "sandbox": {
        const command = String(params.command ?? "");
        return this.sandbox.inspectCommand(command);
      }

      case "shield.evaluateCompliance":
      case "evaluate_compliance":
      case "compliance": {
        const findings = (params.findings || []) as DetectedSecret[];
        const blockedCount = Number(params.blockedCount ?? 0);
        const frameworks = params.frameworks as
          | ComplianceFramework[]
          | undefined;
        return SecretControlAssessmentEngine.evaluate(
          findings,
          blockedCount,
          frameworks,
        );
      }

      default:
        throw new Error(
          `Method '${method}' not found. Supported methods: shield.scan, shield.scanAndRedact, shield.rehydrate, shield.inspectCommand, shield.evaluateCompliance, shield.health, shield.ping`,
        );
    }
  }

  /**
   * Starts a persistent stdio server listening on line-delimited JSON-RPC from input stream
   */
  public startStdioServer(
    input: NodeJS.ReadableStream = process.stdin,
    output: NodeJS.WritableStream = process.stdout,
  ): { close: () => void } {
    const rl = createInterface({
      input,
      terminal: false,
    });

    rl.on("line", async (line) => {
      const response = await this.handleMessage(line);
      if (response) {
        output.write(`${response}\n`);
      }
    });

    return {
      close: () => {
        rl.close();
      },
    };
  }
}
