import assert from "node:assert";
import { describe, it } from "node:test";
import { TransparentMcpWrapper } from "../src/mcp-wrapper.js";
import type { McpJsonRpcRequest } from "../src/mcp-types.js";

describe("AgentShield Transparent MCP Wrapper Suite", () => {
  const wrapper = new TransparentMcpWrapper({ silent: true });

  describe("1. In-Flight File Access & Path Traversal Validation", () => {
    it("blocks tool calls writing or editing .env and secret files", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-1",
        method: "tools/call",
        params: {
          name: "write_file",
          arguments: {
            path: "/workspace/.env",
            content: "DATABASE_URL=postgres://...",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
      assert.ok(verdict.reason?.includes("protected path"));
    });

    it("blocks tool calls attempting to read ssh private keys", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-2",
        method: "tools/call",
        params: {
          name: "read_file",
          arguments: {
            filePath: "~/.ssh/id_rsa",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
      assert.ok(verdict.reason?.includes("forbidden"));
    });

    it("blocks tool calls targeting AWS credential stores", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-3",
        method: "tools/call",
        params: {
          name: "filesystem_write",
          arguments: {
            dest: "C:\\Users\\Admin\\.aws\\credentials",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
    });

    it("permits legitimate project file modifications", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-4",
        method: "tools/call",
        params: {
          name: "write_file",
          arguments: {
            path: "src/utils.ts",
            content: "export const add = (a, b) => a + b;",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, false);
    });
  });

  describe("2. Tool Shell Command Inspection", () => {
    it("blocks container breakout and nsenter attempts inside terminal tools", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-5",
        method: "tools/call",
        params: {
          name: "execute_command",
          arguments: {
            command: "nsenter --target 1 --mount /bin/sh",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
      assert.ok(verdict.reason?.includes("container"));
    });

    it("blocks env dump commands inside shell execution tools", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-6",
        method: "tools/call",
        params: {
          name: "bash",
          arguments: {
            script: "printenv | sort",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
      assert.ok(verdict.reason?.includes("environment"));
    });

    it("permits standard dev terminal commands", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-7",
        method: "tools/call",
        params: {
          name: "execute_command",
          arguments: {
            command: "npm test",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, false);
    });
  });

  describe("3. Network Egress Filtering in Tool Arguments", () => {
    it("blocks network request tools targeting cloud metadata IMDS", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-8",
        method: "tools/call",
        params: {
          name: "fetch",
          arguments: {
            url: "http://169.254.169.254/latest/meta-data/",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
      assert.ok(verdict.reason?.includes("metadata"));
    });

    it("blocks network request tools targeting unapproved C2 webhooks", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-9",
        method: "tools/call",
        params: {
          name: "http_request",
          arguments: {
            url: "https://my-token.webhook.site/collect",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, true);
      assert.ok(verdict.reason?.includes("C2 or exfiltration"));
    });

    it("permits legitimate outbound API calls", () => {
      const req: McpJsonRpcRequest = {
        jsonrpc: "2.0",
        id: "call-10",
        method: "tools/call",
        params: {
          name: "fetch",
          arguments: {
            url: "https://api.github.com/zen",
          },
        },
      };

      const verdict = wrapper.inspectToolCall(req);
      assert.strictEqual(verdict.isBlocked, false);
    });
  });
});
