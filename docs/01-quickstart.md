# 01 — AgentShield Quickstart

**AgentShield (`@ritualdev-lab/agentshield` v0.2.2)** is an enterprise-grade, zero-leak secret redactor, hardware-sealed audit ledger, and OS-level execution sandbox for autonomous AI coding agents (Claude Code, Cursor, Windsurf, Antigravity).

## 1. Run the 10-Second Interactive Demo
```bash
npx @ritualdev-lab/agentshield demo
```

## 2. Diagnose Your Host Sandbox & Crypto Capabilities
Verify Linux Landlock LSM / Bubblewrap / AppArmor userns, macOS Seatbelt / Keychain, Windows DPAPI, and Ed25519 signing readiness:
```bash
npx @ritualdev-lab/agentshield doctor
```

## 3. Protect Your Workspace & Git Commits
```bash
# Install automatic git pre-commit secret shield
npx @ritualdev-lab/agentshield hook install

# Configure Claude Code PreToolUse hook
npx @ritualdev-lab/agentshield init-claude

# Configure Cursor / Windsurf workspace rules
npx @ritualdev-lab/agentshield init-cursor
```

## 4. Sandbox & Redact Agent Commands
```bash
npx @ritualdev-lab/agentshield exec "npm test" --kernel
```

## Next Steps
- [02 — Architecture](02-architecture.md)
- [03 — Configuration & CLI Reference](03-configuration-and-cli.md)
- [04 — Integrations & MCP Wrapping](04-integrations-and-mcp.md)
- [05 — Enterprise VPC & Security](05-enterprise-vpc-and-security.md)
