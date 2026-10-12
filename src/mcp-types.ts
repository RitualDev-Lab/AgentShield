export interface McpJsonRpcRequest {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
    [key: string]: unknown;
  };
}

export interface McpJsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number;
  result?: {
    content?: Array<{
      type: string;
      text?: string;
      [key: string]: unknown;
    }>;
    isError?: boolean;
    [key: string]: unknown;
  };
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface McpInspectionVerdict {
  isBlocked: boolean;
  reason?: string;
  sanitizedPayload?: string;
  redactedCount: number;
  ruleTriggered?: string;
}

export interface NativeAutomataMatch {
  patternId: string;
  start: number;
  end: number;
  matchedText: string;
}
