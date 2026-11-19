#!/usr/bin/env node
import { runAgentShieldMcpStdio } from "../dist/mcp-server.js";

runAgentShieldMcpStdio().catch((err) => {
  console.error("Fatal error starting AgentShield MCP server:", err);
  process.exit(1);
});
