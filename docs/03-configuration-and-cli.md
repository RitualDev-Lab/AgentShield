# 03 — AgentShield Configuration & CLI Reference

## Unified CLI Commands

| Command | Description |
| :--- | :--- |
| `agentshield doctor [--json]` | Run cross-platform sandbox, kernel, and Ed25519 diagnostics. |
| `agentshield scan <path> [--json]` | Scan files or directories for leaked secrets. |
| `agentshield redact <path>` | Output secret-redacted text to stdout. |
| `agentshield exec <cmd> [--kernel]` | Sandbox and intercept agent shell execution. |
| `agentshield wrap <server...>` | Transparent zero-config MCP stdio security wrapper. |
| `agentshield ledger verify [path] [--pub-key <pem>]` | Verify Ed25519 asymmetric signatures and hash-chain integrity offline. |
| `agentshield db-proxy [args...]` | Unified platform bridge to `@ritualdev-lab/dbshield`. |
| `agentshield compact [args...]` | Unified platform bridge to `@ritualdev-lab/skillprism`. |
| `agentshield ci [--base origin/main] [--sarif out.sarif]` | CI/CD pull request leak gate with OASIS SARIF 2.1.0 output. |

## Environment Variables

| Variable | Purpose |
| :--- | :--- |
| `AGENTSHIELD_AIR_GAPPED=1` | Strict zero-egress air-gapped execution mode. |
| `AGENTSHIELD_KEYSTORE` | Override Ed25519 keystore backend (`macos-keychain`, `linux-keyring`, `windows-dpapi`, `file-0600`, `memory`). |
| `AGENTSHIELD_LEDGER_KEY` | Optional supplemental HMAC chain salt for legacy compatibility. |
