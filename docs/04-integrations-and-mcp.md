# 04 — Integrations & MCP Wrapping

## Wrapping Any MCP Server
Wrap any third-party MCP server in Claude Desktop, Cursor, or Windsurf without modifying upstream code:
```json
{
  "mcpServers": {
    "github-protected": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/agentshield", "wrap", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

## Importing the Shared Core Redactor SDK
```ts
import { redactText, redactStagedDiff } from "@ritualdev-lab/agentshield/core-redactor";

const result = redactText(agentOutput, { maxScanMs: 25, entropyThreshold: 4.5 });
```

## Python SDK (`agentshield-python` v0.2.2)
Python teams can install the synchronized `agentshield-python` package to protect LangChain, CrewAI, and AutoGen tool pipelines with matching redaction policies.

## GitHub Actions PR Gate
Use `RitualDev-Lab/AgentShield` directly in CI (`npx @ritualdev-lab/agentshield ci --base origin/main --sarif agentshield.sarif`) to block leaked credentials before merge.
