import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createAgentShieldMcpServer } from "../src/mcp-server.js";

describe("AgentShield Official MCP Server Suite", () => {
  test("creates McpServer instance with registered tools", () => {
    const server = createAgentShieldMcpServer();
    assert.ok(server, "McpServer instance should be defined");
  });
});
