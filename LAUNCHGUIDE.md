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
  - "Scan text for secrets and credentials: agentshield_scan text: 'export API_KEY=test-sample-token'"
  - "Verify local cryptographic audit ledger: agentshield_verify_ledger"
  - "Inspect host OS sandbox readiness: agentshield_doctor"
  - "Tool: agentshield_scan: Scans prompt text or tool outputs for 60+ credential patterns and high-entropy secrets"
  - "Tool: agentshield_verify_ledger: Verifies HMAC-SHA256 and Ed25519 tamper-evident audit ledger"
  - "Tool: agentshield_doctor: Inspects active OS kernel sandbox mechanisms (Landlock, Seatbelt, AppContainer)"
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
args: ["-y", "@ritualdev-lab/agentshield", "mcp"]
pricing:
  type: freemium
  license: Apache-2.0
environment_variables: []
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
      "args": ["-y", "@ritualdev-lab/agentshield", "mcp"]
    }
  }
}
```

## Exposed Tools

1. `agentshield_scan`: Scan prompt text or tool outputs for 60+ sensitive credential formats (AWS keys, OpenAI tokens, SSH keys) and high-entropy secrets.
2. `agentshield_verify_ledger`: Verify the local HMAC-SHA256 and Ed25519 tamper-evident audit ledger for compliance.
3. `agentshield_doctor`: Inspect host OS kernel sandbox capabilities (Linux Landlock/bwrap, macOS Seatbelt, Windows AppContainer) and security readiness.
