/**
 * Transparent MCP Wrapper (agentshield wrap <server...>)
 *
 * Sits seamlessly between AI Coding IDEs (Cursor, Claude Desktop, Antigravity)
 * and third-party MCP servers, performing in-flight zero-config validation of:
 * - File access & path traversals (blocking writes/reads to .env, .ssh, .aws, credentials)
 * - Shell command executions inside tools (blocking container escapes, env dumps)
 * - Network egress destinations (blocking cloud metadata IMDS and loopback bypasses)
 * - Tool responses (recursively scrubbing leaked secrets before context ingestion)
 */

import { spawn, type ChildProcess } from "node:child_process";
import { platform } from "node:os";
import readline from "node:readline";
import { AgentShieldEngine } from "./engine.js";
import { evaluateNetworkEgress } from "./egress-filter.js";
import { McpProxyInterceptor } from "./mcp-proxy.js";
import type { McpJsonRpcRequest } from "./mcp-types.js";
import { AgentCommandSandbox } from "./sandbox.js";
import { recordBlockedCallEvent } from "./top-monitor.js";

export interface McpWrapperOptions {
  engine?: AgentShieldEngine;
  sandbox?: AgentCommandSandbox;
  blockedTools?: string[];
  allowedWorkspace?: string;
  onBlock?: (tool: string, reason: string) => void;
  silent?: boolean;
}

const PROTECTED_FILE_PATTERNS = [
  /(?:^|[\/\\\s])\.env(?:\.[a-zA-Z0-9_\-]+)?$/i,
  /(?:^|[\/\\\s])id_rsa(?:$|\.)/i,
  /(?:^|[\/\\\s])id_ed25519(?:$|\.)/i,
  /(?:^|[\/\\\s])\.aws[\/\\](?:credentials|config)$/i,
  /(?:^|[\/\\\s])\.gnupg[\/\\]/i,
  /(?:^|[\/\\\s])\.config[\/\\]gcloud[\/\\]/i,
  /(?:^|[\/\\\s])\.netrc$/i,
  /(?:^|[\/\\\s])\/etc\/(?:shadow|master\.passwd)$/i,
];

export class TransparentMcpWrapper {
  private engine: AgentShieldEngine;
  private sandbox: AgentCommandSandbox;
  private proxy: McpProxyInterceptor;
  private options: McpWrapperOptions;

  constructor(options: McpWrapperOptions = {}) {
    this.options = options;
    this.engine = options.engine || new AgentShieldEngine();
    this.sandbox = options.sandbox || new AgentCommandSandbox();
    this.proxy = new McpProxyInterceptor(this.engine, options.blockedTools || []);
  }

  /**
   * Inspects a single tool call request before forwarding to the child MCP server
   */
  public inspectToolCall(request: McpJsonRpcRequest): { isBlocked: boolean; reason?: string } {
    if (request.method !== "tools/call" || !request.params) {
      return { isBlocked: false };
    }

    const toolName = request.params.name || "";
    const args = request.params.arguments || {};

    // 1. File Modification & Sensitive Path Inspection
    const pathKeys = [
      "path",
      "filePath",
      "file",
      "filename",
      "uri",
      "target",
      "dest",
      "destination",
      "source",
    ];
    for (const key of pathKeys) {
      const val = args[key];
      if (typeof val === "string") {
        for (const pattern of PROTECTED_FILE_PATTERNS) {
          if (pattern.test(val)) {
            const reason = `[AgentShield MCP Sandbox] Blocked tool '${toolName}': access to protected path '${val}' is forbidden by security policy.`;
            recordBlockedCallEvent({
              category: "protected_file_access",
              command: `${toolName} path=${val}`,
              action: "BLOCKED",
              mechanism: "mcp_wrapper_firewall",
            });
            return { isBlocked: true, reason };
          }
        }
      }
    }

    // 2. Command Execution Tools (bash, terminal, exec)
    const cmdKeys = ["command", "cmd", "script", "exec"];
    for (const key of cmdKeys) {
      const cmdVal = args[key];
      if (typeof cmdVal === "string") {
        const check = this.sandbox.evaluateContainerConfinement(cmdVal);
        if (check.isBlocked) {
          const reason = `[AgentShield MCP Sandbox] Blocked execution in tool '${toolName}': ${check.reason}`;
          recordBlockedCallEvent({
            category: check.category || "command_injection",
            command: `${toolName} ${cmdVal.slice(0, 30)}`,
            action: "BLOCKED",
            mechanism: "mcp_wrapper_firewall",
          });
          return { isBlocked: true, reason };
        }
      }
    }

    // 3. Network Outbound Tools (fetch, http, request)
    const urlKeys = ["url", "endpoint", "uri", "host"];
    for (const key of urlKeys) {
      const urlVal = args[key];
      if (typeof urlVal === "string" && /^https?:\/\//i.test(urlVal)) {
        const egress = evaluateNetworkEgress(urlVal);
        if (egress.isBlocked) {
          const reason = `[AgentShield MCP Sandbox] Blocked network request in tool '${toolName}': ${egress.reason}`;
          recordBlockedCallEvent({
            category: egress.category || "metadata_imds",
            command: `${toolName} url=${urlVal}`,
            action: "BLOCKED",
            mechanism: "mcp_wrapper_firewall",
          });
          return { isBlocked: true, reason };
        }
      }
    }

    return { isBlocked: false };
  }

  /**
   * Spawns the wrapped MCP server child process and transparently mediates stdio streams
   */
  public start(command: string, commandArgs: string[]): ChildProcess {
    const child = spawn(command, commandArgs, {
      stdio: ["pipe", "pipe", "inherit"],
      shell: platform() === "win32",
    });

    // Inbound: IDE -> AgentShield -> MCP Server
    const stdinRl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: false,
    });

    stdinRl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;

      try {
        const request: McpJsonRpcRequest = JSON.parse(trimmed);

        // Perform security inspection on tool calls
        const verdict = this.inspectToolCall(request);
        if (verdict.isBlocked) {
          if (!this.options.silent) {
            console.error(`\n🚨 [AgentShield MCP Wrap] ${verdict.reason}`);
          }
          if (this.options.onBlock) {
            this.options.onBlock(request.params?.name || "unknown", verdict.reason || "Blocked");
          }

          // Return JSON-RPC error response directly to IDE without forwarding to server
          const errorResponse = {
            jsonrpc: "2.0",
            id: request.id ?? null,
            error: {
              code: -32603,
              message: verdict.reason,
            },
          };
          process.stdout.write(`${JSON.stringify(errorResponse)}\n`);
          return;
        }

        // Scrub any secrets in tool arguments before server delivery
        const scrubbed = this.proxy.inspectRequest(trimmed);
        const payloadToSend = scrubbed.sanitizedPayload || trimmed;
        child.stdin?.write(`${payloadToSend}\n`);
      } catch {
        // Passthrough non-JSON lines cleanly
        child.stdin?.write(`${trimmed}\n`);
      }
    });

    // Outbound: MCP Server -> AgentShield -> IDE
    if (child.stdout) {
      const stdoutRl = readline.createInterface({
        input: child.stdout,
        terminal: false,
      });

      stdoutRl.on("line", (line) => {
        const trimmed = line.trim();
        if (!trimmed) return;

        try {
          // Recursively scrub any credentials from MCP responses before delivering to LLM context
          const verdict = this.proxy.inspectResponse(trimmed);
          const cleanPayload = verdict.sanitizedPayload || trimmed;
          process.stdout.write(`${cleanPayload}\n`);
        } catch {
          process.stdout.write(`${trimmed}\n`);
        }
      });
    }

    child.on("close", (code) => {
      process.exit(code ?? 0);
    });

    child.on("error", (err) => {
      console.error(`❌ [AgentShield MCP Wrapper] Child process error: ${err.message}`);
      process.exit(1);
    });

    const cleanup = () => {
      try {
        child.kill();
      } catch {
        // Ignored
      }
    };

    process.on("SIGINT", cleanup);
    process.on("SIGTERM", cleanup);

    return child;
  }
}

/**
 * CLI Entrypoint helper for `agentshield wrap <server-cmd> [args...]`
 */
export function runMcpWrapper(args: string[]): void {
  if (args.length === 0) {
    console.error("❌ Error: No target MCP server command provided.");
    console.error("Usage: agentshield wrap <command> [args...]");
    console.error(
      "Example: agentshield wrap npx -y @modelcontextprotocol/server-filesystem ./workspace",
    );
    process.exit(1);
  }

  const [command, ...commandArgs] = args;
  const wrapper = new TransparentMcpWrapper();
  wrapper.start(command, commandArgs);
}
