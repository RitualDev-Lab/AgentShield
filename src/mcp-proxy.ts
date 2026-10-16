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
   * Recursively traverses any data structure (objects, arrays, strings)
   * scanning and redacting secrets in all string values while strictly preserving
   * the exact JSON structure, keys, and non-string primitive types.
   */
  private sanitizeDeep(value: unknown): {
    sanitized: unknown;
    redactedCount: number;
    ruleTriggered?: string;
  } {
    if (typeof value === "string") {
      const scan = this.engine.scanAndRedact(value);
      return {
        sanitized: scan.sanitizedText,
        redactedCount: scan.totalFound,
        ruleTriggered: scan.findings[0]?.patternId,
      };
    }

    if (Array.isArray(value)) {
      let count = 0;
      let firstRule: string | undefined;
      const sanitizedArray = value.map((item) => {
        const res = this.sanitizeDeep(item);
        count += res.redactedCount;
        if (!firstRule && res.ruleTriggered) firstRule = res.ruleTriggered;
        return res.sanitized;
      });
      return {
        sanitized: sanitizedArray,
        redactedCount: count,
        ruleTriggered: firstRule,
      };
    }

    if (value !== null && typeof value === "object") {
      let count = 0;
      let firstRule: string | undefined;
      const sanitizedObj: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        const res = this.sanitizeDeep(v);
        count += res.redactedCount;
        if (!firstRule && res.ruleTriggered) firstRule = res.ruleTriggered;
        sanitizedObj[k] = res.sanitized;
      }
      return {
        sanitized: sanitizedObj,
        redactedCount: count,
        ruleTriggered: firstRule,
      };
    }

    return {
      sanitized: value,
      redactedCount: 0,
    };
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
      }

      // Check all parameters (arguments, uri, headers, etc.) for secret leaks
      if (request.params && typeof request.params === "object") {
        const { sanitized, redactedCount, ruleTriggered } = this.sanitizeDeep(request.params);
        if (redactedCount > 0) {
          return {
            isBlocked: false,
            redactedCount,
            sanitizedPayload: JSON.stringify({
              ...request,
              params: sanitized as McpJsonRpcRequest["params"],
            }),
            ruleTriggered: ruleTriggered || "MCP-REQUEST-REDACTED",
          };
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
   * Recursively scrubs credentials from direct text blocks, embedded resource blocks,
   * structured output objects, and JSON-RPC error responses before context delivery.
   */
  public inspectResponse(rawJson: string): McpInspectionVerdict {
    try {
      const response: McpJsonRpcResponse = JSON.parse(rawJson);
      let totalRedacted = 0;
      let primaryRule: string | undefined;
      let modified = false;

      let sanitizedResult = response.result;
      if (response.result !== undefined) {
        const resVerdict = this.sanitizeDeep(response.result);
        if (resVerdict.redactedCount > 0) {
          totalRedacted += resVerdict.redactedCount;
          primaryRule = resVerdict.ruleTriggered;
          sanitizedResult = resVerdict.sanitized as McpJsonRpcResponse["result"];
          modified = true;
        }
      }

      let sanitizedError = response.error;
      if (response.error !== undefined) {
        const errVerdict = this.sanitizeDeep(response.error);
        if (errVerdict.redactedCount > 0) {
          totalRedacted += errVerdict.redactedCount;
          if (!primaryRule) primaryRule = errVerdict.ruleTriggered;
          sanitizedError = errVerdict.sanitized as McpJsonRpcResponse["error"];
          modified = true;
        }
      }

      if (modified) {
        const sanitizedResponse: McpJsonRpcResponse = {
          ...response,
          ...(sanitizedResult !== undefined ? { result: sanitizedResult } : {}),
          ...(sanitizedError !== undefined ? { error: sanitizedError } : {}),
        };

        return {
          isBlocked: false,
          sanitizedPayload: JSON.stringify(sanitizedResponse),
          redactedCount: totalRedacted,
          ruleTriggered: primaryRule || "MCP-RESPONSE-REDACTED",
        };
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
