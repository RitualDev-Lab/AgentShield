import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { FastAutomataScanner } from "../src/automata.js";
import { McpProxyInterceptor } from "../src/mcp-proxy.js";

describe("Phase 2: High-Velocity Native Core & MCP Protocol Interceptor", () => {
  describe("Aho-Corasick Multi-Pattern Automata Engine", () => {
    it("should build state machine and find patterns simultaneously in sub-millisecond time", () => {
      const scanner = new FastAutomataScanner();
      scanner.addSignature("sk-proj-", "OPENAI");
      scanner.addSignature("sk-ant-", "ANTHROPIC");
      scanner.addSignature("AKIA", "AWS");
      scanner.addSignature("ghp_", "GITHUB");
      scanner.buildFailureTransitions();

      assert.equal(scanner.getPatternCount(), 4);

      const testInput = "Config has AKIA1234567890123456 and sk-ant-token999 in one string";
      const startTime = performance.now();
      const matches = scanner.scanBuffer(testInput);
      const elapsed = performance.now() - startTime;

      assert.ok(elapsed < 15, `Search must complete in sub-15ms, took ${elapsed}ms`);
      assert.equal(matches.length, 2);
      assert.equal(matches[0].patternId, "AWS");
      assert.equal(matches[0].matchedText, "AKIA");
      assert.equal(matches[1].patternId, "ANTHROPIC");
      assert.equal(matches[1].matchedText, "sk-ant-");
    });
  });

  describe("MCP JSON-RPC Proxy Interceptor", () => {
    const proxy = new McpProxyInterceptor(undefined, ["bash_rm_rf"]);

    it("should block restricted MCP tools", () => {
      const blockedRequest = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "bash_rm_rf",
          arguments: { path: "/" },
        },
      });

      const verdict = proxy.inspectRequest(blockedRequest);
      assert.equal(verdict.isBlocked, true);
      assert.equal(verdict.ruleTriggered, "MCP-BLOCKED-TOOL");
    });

    it("should sanitize and redact secrets inside MCP tool arguments in flight", () => {
      const rawToken = ["sk-proj-", "1234567890123456789012345678901234567890"].join("");
      const requestWithSecret = JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: "http_request",
          arguments: {
            url: "https://api.openai.com",
            header: `Bearer ${rawToken}`,
          },
        },
      });

      const verdict = proxy.inspectRequest(requestWithSecret);
      assert.equal(verdict.isBlocked, false);
      assert.equal(verdict.redactedCount, 1);
      assert.ok(verdict.sanitizedPayload?.includes("[AGENT_SHIELD:OPENAI_API_KEY:"));
    });

    it("should scrub credentials from inbound MCP tool responses before context delivery", () => {
      const rawKey = ["sk-ant-", "1234567890123456789012345678901234567890"].join("");
      const responseWithSecret = JSON.stringify({
        jsonrpc: "2.0",
        id: 3,
        result: {
          content: [
            {
              type: "text",
              text: `Fetched config: CLAUDE_KEY=${rawKey}`,
            },
          ],
        },
      });

      const verdict = proxy.inspectResponse(responseWithSecret);
      assert.equal(verdict.isBlocked, false);
      assert.equal(verdict.redactedCount, 1);
      assert.ok(verdict.sanitizedPayload?.includes("[AGENT_SHIELD:ANTHROPIC_API_KEY:"));
    });
  });
});
