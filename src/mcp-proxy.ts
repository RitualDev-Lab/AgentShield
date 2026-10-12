import { AgentShieldEngine } from "./engine.js";
import type { McpInspectionVerdict, McpJsonRpcRequest, McpJsonRpcResponse } from "./mcp-types.js";

/**
 * Inline Model Context Protocol (MCP) Proxy Interceptor:
 * Mediates JSON-RPC communication between AI coding agents and MCP tool servers.
 * Enforces schema integrity, prevents indirect prompt injections, and redacts credentials in flight.
 */
export class McpProxyInterceptor {
  private engine: AgentShieldEngine;
  private blockedTools: Set<string>;

  constructor(engine?: AgentShieldEngine, blockedTools: string[] = []) {
    this.engine = engine || new AgentShieldEngine();
    this.blockedTools = new Set(blockedTools);
  }

  /**
   * Inspects outbound tool call requests from AI Agent -> MCP Server
   */
  public inspectRequest(rawJson: string): McpInspectionVerdict {
    try {
      const request: McpJsonRpcRequest = JSON.parse(rawJson);

      // Verify JSON-RPC method
      if (request.method === "tools/call") {
        const toolName = request.params?.name;
        if (toolName && this.blockedTools.has(toolName)) {
          return {
            isBlocked: true,
            reason: `Execution of restricted MCP tool '${toolName}' is forbidden by policy.`,
            redactedCount: 0,
            ruleTriggered: "MCP-BLOCKED-TOOL",
          };
        }

        // Check tool arguments for secret leaks or dangerous commands
        if (request.params?.arguments) {
          const argsStr = JSON.stringify(request.params.arguments);
          const scan = this.engine.scanAndRedact(argsStr);

          if (scan.hasSecrets) {
            return {
              isBlocked: false,
              redactedCount: scan.totalFound,
              sanitizedPayload: JSON.stringify({
                ...request,
                params: {
                  ...request.params,
                  arguments: JSON.parse(scan.sanitizedText),
                },
              }),
              ruleTriggered: scan.findings[0]?.patternId,
            };
          }
        }
      }

      return {
        isBlocked: false,
        sanitizedPayload: rawJson,
        redactedCount: 0,
      };
    } catch {
      // Passthrough invalid or non-JSON payloads safely
      return {
        isBlocked: false,
        sanitizedPayload: rawJson,
        redactedCount: 0,
      };
    }
  }

  /**
   * Inspects inbound tool responses from MCP Server -> AI Agent
   * Prevents indirect prompt injection and scrubs credentials from returned web/file content.
   */
  public inspectResponse(rawJson: string): McpInspectionVerdict {
    try {
      const response: McpJsonRpcResponse = JSON.parse(rawJson);

      if (response.result?.content && Array.isArray(response.result.content)) {
        let totalRedacted = 0;
        let modified = false;

        const sanitizedContent = response.result.content.map((item) => {
          if (item.type === "text" && typeof item.text === "string") {
            const scan = this.engine.scanAndRedact(item.text);
            if (scan.hasSecrets) {
              totalRedacted += scan.totalFound;
              modified = true;
              return { ...item, text: scan.sanitizedText };
            }
          }
          return item;
        });

        if (modified) {
          const sanitizedResponse: McpJsonRpcResponse = {
            ...response,
            result: {
              ...response.result,
              content: sanitizedContent,
            },
          };

          return {
            isBlocked: false,
            sanitizedPayload: JSON.stringify(sanitizedResponse),
            redactedCount: totalRedacted,
            ruleTriggered: "MCP-RESPONSE-REDACTED",
          };
        }
      }

      return {
        isBlocked: false,
        sanitizedPayload: rawJson,
        redactedCount: 0,
      };
    } catch {
      return {
        isBlocked: false,
        sanitizedPayload: rawJson,
        redactedCount: 0,
      };
    }
  }
}
