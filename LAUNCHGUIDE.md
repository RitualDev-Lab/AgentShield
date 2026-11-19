---
name: agentshield
title: AgentShield
tagline: Zero-leak secret defense, prompt injection blocker & kernel sandbox for AI agents
description: Enterprise-grade runtime security, credential interception, and kernel sandboxing MCP proxy for Claude Desktop, Cursor, and autonomous AI agents. Blocks 60+ secret formats (API keys, SSH keys, database credentials), neutralizes prompt injection payloads, and enforces OS isolation (Linux Landlock, macOS Seatbelt, Windows AppContainer).
category: Security
use_cases:
  - Secret Leak Prevention
  - Prompt Injection Defense
  - OS Kernel Sandboxing
  - AI Security Proxy & Redactor
  - CI/CD Security Compliance
getting_started:
  - "Wrap an upstream MCP server with security guardrails: wrap <command>"
  - "Verify local cryptographic audit ledger: agentshield ledger verify"
  - "Tool: agentshield_scan: Scans prompt text or tool outputs for 60+ credential patterns and high-entropy secrets"
  - "Tool: agentshield_wrap: Sandboxes upstream tool invocations with strict read-only filesystem barriers"
tags:
  - security
  - ai-agents
  - dlp
  - prompt-injection
  - credential-defense
  - mcp
  - sandboxing
  - cursor
  - claude
documentation_url: https://ritualdev.in/agentshield
repository: https://github.com/RitualDev-Lab/AgentShield
homepage: https://ritualdev.in/agentshield
npm: "@ritualdev-lab/agentshield"
pypi: agentshield-defense
transport: stdio
command: npx
args: ["-y", "@ritualdev-lab/agentshield"]
pricing:
  type: freemium
  license: Apache-2.0
environment_variables:
  - name: AGENTSHIELD_AIR_GAPPED
    required: false
    docs_url: https://ritualdev.in/agentshield
    description: Set to '1' to enforce strict local offline operation with zero telemetry.
  - name: AGENTSHIELD_AUDIT_LOG
    required: false
    docs_url: https://ritualdev.in/agentshield
    description: Custom file path for the tamper-evident HMAC-SHA256 audit ledger.
---

# AgentShield MCP Security Server

**AgentShield** provides client-side runtime security, credential interception, and kernel isolation for AI coding assistants and autonomous agents.

## Setup Requirements

**None.** AgentShield runs 100% locally with zero required external API keys or cloud tokens.

## Quick Installation

```json
{
  "mcpServers": {
    "agentshield": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/agentshield"]
    }
  }
}
```

## Wrapping Any MCP Server

Protect any third-party MCP server in Claude Desktop or Cursor without changing upstream code:

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
