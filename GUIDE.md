# 📖 AgentShield Complete Run & Integration Guide

> **Enterprise-Grade Zero-Leak Secret Defense & Shell Sandbox for Autonomous AI Coding Agents**  
> *Official documentation for local developers, DevOps engineers, and autonomous AI agents.*

---

## 📑 Table of Contents

1. [Introduction & Architecture](#1-introduction--architecture)
2. [Prerequisites & System Requirements](#2-prerequisites--system-requirements)
3. [Instant 30-Second Quickstart (Zero Install)](#3-instant-30-second-quickstart-zero-install)
4. [CLI Command Reference (With Examples)](#4-cli-command-reference-with-examples)
   - [Scanning Files (`agentshield scan`)](#41-scanning-files-for-leaked-secrets)
   - [Redacting & Sanitizing (`agentshield redact`)](#42-redacting-secrets-in-flight)
   - [Stream / Terminal Pipe Redaction (`agentshield stream`)](#43-real-time-stream-redaction)
   - [AST Shell Command Sandboxing (`agentshield exec`)](#44-autonomous-agent-shell-sandbox)
   - [Git Pre-Commit Hook Gate (`agentshield hook`)](#45-git-pre-commit-gate)
   - [CI/CD & Pull Request Gate (`agentshield ci`)](#46-cicd-pipeline--pull-request-gate)
   - [Enterprise Compliance Audit (`agentshield compliance`)](#47-enterprise-regulatory-compliance-audit)
   - [Agent Configuration Audit (`agentshield audit`)](#48-agent-workspace-permission-audit)
   - [MCP Tool Proxy (`agentshield mcp-proxy`)](#49-model-context-protocol-mcp-filter-proxy)
   - [Cryptographic Audit Ledger (`agentshield ledger`)](#410-tamper-evident-hmac-ledger-verification)
5. [AI Coding Agent Integration (Claude, Cursor, Windsurf, Codex, Antigravity)](#5-ai-coding-agent-integration)
6. [GitHub Actions Workflow Setup](#6-github-actions-workflow-setup)
7. [Custom Configuration (`.agentshield.json`)](#7-custom-configuration-agentshieldjson)
8. [Programmatic TypeScript / Node.js SDK](#8-programmatic-typescript--nodejs-sdk)
9. [Troubleshooting & FAQ](#9-troubleshooting--faq)

---

## 1. Introduction & Architecture

Modern AI coding agents (**Claude Code**, **Cursor**, **Windsurf**, **OpenAI Codex**, **Google Antigravity**) have autonomous shell access to read files, run terminal commands, and commit code. Without safety guardrails, agents can:
1. Dump `.env` or production credentials into LLM prompt contexts.
2. Leak ephemeral API keys, database credentials, or auth tokens via subshell exfiltration.
3. Commit hardcoded test credentials into Git history and pull requests.

**AgentShield** acts as a local-first, deterministic security perimeter:
- **Zero Cloud Exfiltration**: All scanning, redaction, AST parsing, and validation occur 100% locally on your machine.
- **AST Shell Sandboxing**: Intercepts obfuscated bypasses (`sh -c $'cat\t.env'`, base64 decoding, command substitutions, `< .env` redirects).
- **Shannon Entropy Scanner**: Detects high-entropy arbitrary passwords and custom API tokens without requiring regex headers.
- **Deterministic Surrogate Tokens**: Replaces secrets with reversible surrogate hashes `[AGENT_SHIELD:TYPE:hash]` so agents can reason over configs without viewing cleartext credentials.

---

## 2. Prerequisites & System Requirements

- **Node.js**: v20.0.0 or higher (`node -v`)
- **Package Manager**: npm, pnpm, yarn, or bun
- **Operating Systems**: macOS, Linux, Windows (PowerShell & WSL)
- **Git**: Git 2.20+ (optional, for pre-commit hooks and CI diff checks)

---

## 3. Instant 30-Second Quickstart (Zero Install)

You can run AgentShield immediately with `npx` without installing any global packages:

```bash
# 1. Check your codebase or .env file for leaked secrets
npx agentshield scan .env

# 2. Install pre-commit guard into your current git repository
npx agentshield hook git-install

# 3. Test the agent sandbox against sensitive file access
npx agentshield exec "cat .env"
```

To install AgentShield globally or as a project dependency:

```bash
# Global CLI installation
npm install -g agentshield

# Project development dependency
npm install -D agentshield
# or
pnpm add -D agentshield
```

---

## 4. CLI Command Reference (With Examples)

### 4.1 Scanning Files for Leaked Secrets
Scan any file, configuration, or log for exposed credentials:

```bash
# Scan a specific file
npx agentshield scan .env
npx agentshield scan config/secrets.yaml

# Output structured JSON for tooling / scripts
npx agentshield scan .env --json
```

**Example Output:**
```text
🛡️  AgentShield Secret Audit Report
File: .env
Found: 2 exposed credential(s)

  [CRITICAL] OpenAI API Key
  Location: Line 14, Col 19
  Pattern:  sk-proj-************************************

  [HIGH] AWS Access Key ID
  Location: Line 22, Col 16
  Pattern:  AKIA****************

❌ Audit Failed: Secrets detected. Run 'agentshield redact .env' to sanitize.
```

---

### 4.2 Redacting Secrets In-Flight
Sanitize a file or text with deterministic, non-leaking surrogate tokens:

```bash
# Redact secrets and print sanitized output to stdout
npx agentshield redact server.js

# Custom surrogate formatting styles (token, hash, asterisk)
npx agentshield redact server.js --style asterisk
npx agentshield redact server.js --style hash
```

**Surrogate Token Formats:**
- `token` (default): `[AGENT_SHIELD:OPENAI_API_KEY:4a7f9b8c1d2e3f40]`
- `hash`: `[REDACTED_SHA256:4a7f9b8c1d2e3f40]`
- `asterisk`: `sk-proj-********************************`

---

### 4.3 Real-Time Stream Redaction
Pipe terminal output, build logs, or AI agent input streams through AgentShield:

```bash
# Pipe environment dump through real-time redactor
env | npx agentshield stream

# Pipe AI agent standard input/output
claude-code | npx agentshield stream
```

---

### 4.4 Autonomous Agent Shell Sandbox
Safely wrap bash execution for autonomous agents. If an agent tries to read `.env`, dump environment variables, or run exfiltration commands, AgentShield aborts the process before execution:

```bash
# Block direct reading of sensitive environment files
npx agentshield exec "cat .env"
# 🚨 [AgentShield Sandbox Block] Blocked attempt to read raw .env file directly.

# Block obfuscated ANSI-C escapes and tab bypasses
npx agentshield exec "sh -c $'cat\t.env'"
# 🚨 [AgentShield Sandbox Block] Blocked obfuscated ANSI-C escape subshell targeting .env file.

# Block shell variable dumping
npx agentshield exec "printenv"
# 🚨 [AgentShield Sandbox Block] Blocked unconstrained environment variable dump.

# Allowed safe developer commands execute transparently:
npx agentshield exec "npm test"
npx agentshield exec "git status"
```

---

### 4.5 Git Pre-Commit Gate
Prevent developers or agents from committing secrets into local Git history:

```bash
# Install automatic pre-commit hook into .git/hooks/pre-commit
npx agentshield hook git-install

# Manually audit currently staged files
npx agentshield hook check
```

**What the hook does:**
1. Audits all files staged in `git diff --cached --name-only`.
2. Scans each file against both regular expressions and Shannon entropy thresholds.
3. Automatically rejects the commit with a non-zero exit code if secrets are detected.
4. Protects subdirectories (e.g. `packages/backend/.env`) and Git worktrees safely.

---

### 4.6 CI/CD Pipeline & Pull Request Gate
Audit entire git diffs in pull requests and generate compliance reports:

```bash
# Audit diff against base branch (default: origin/main)
npx agentshield ci --base origin/main

# Generate Markdown report artifact for GitHub Actions summary
npx agentshield ci --base origin/main --report security-report.md

# Export findings in OASIS SARIF format for GitHub Security Code Scanning tab
npx agentshield ci --base origin/main --sarif results.sarif
```

---

### 4.7 Enterprise Regulatory Compliance Audit
Generate formal audit reports mapped to industry cybersecurity frameworks:

```bash
npx agentshield compliance .env
```

**Supported Regulatory Frameworks:**
- **SOC 2 Type II**: CC6.1 (Logical Access Controls & Key Management)
- **PCI-DSS v4.0**: Requirement 3.4 (Protection of Cardholder Data & Auth Tokens)
- **HIPAA**: 45 CFR § 164.312(a)(1) (Technical Safeguards - Access Control)
- **ISO/IEC 27001:2022**: Control A.8.28 (Secure Coding & Secret Management)

---

### 4.8 Agent Workspace Permission Audit
Inspect configuration files in your repository for risky agent permissions:

```bash
npx agentshield audit
```
Audits `.claude/skills/`, Cursor rules (`.cursorrules`), Windsurf configurations, and MCP settings for overly permissive shell scopes or unencrypted credentials.

---

### 4.9 Model Context Protocol (MCP) Filter Proxy
Run a transparent inline JSON-RPC proxy to intercept and sanitize tool calls made by MCP agents:

```bash
npx agentshield mcp-proxy
```
Inspects all incoming and outgoing tool arguments, replacing cleartext secrets with surrogate tokens before forwarding payloads to external tools or LLM context windows.

---

### 4.10 Tamper-Evident HMAC Ledger Verification
AgentShield logs all intercepted leaks into an append-only cryptographic ledger (`.agentshield/ledger.jsonl`). Verify ledger integrity against tampering:

```bash
npx agentshield ledger verify
```
Validates the HMAC-SHA256 hash chain across all log entries to prove security audit trail authenticity.

---

## 5. AI Coding Agent Integration

AgentShield provides seamless integration across leading autonomous coding environments:

### 5.1 Claude Code
Add AgentShield execution wrapper or install the universal skill:
```bash
# In Claude Code session, prepend shell executions:
npx agentshield exec "<command>"
```
Or place [SKILL.md](file:///D:/Repos/AgentShield/SKILL.md) in your project's `.claude/skills/agentshield/SKILL.md`.

### 5.2 Cursor & Windsurf
Add the following instruction to your project's `.cursorrules` or `.windsurfrules`:
```markdown
Before executing bash commands that interact with configuration files or environment variables, run them through:
`npx agentshield exec "<command>"`
Run `npx agentshield hook check` before finalizing any git commits.
```

### 5.3 Google Antigravity
The repository includes native [SKILL.md](file:///D:/Repos/AgentShield/SKILL.md). In Antigravity sessions, the agent automatically triggers the skill to intercept commands and inspect secrets.

---

## 6. GitHub Actions Workflow Setup

To run AgentShield automatically on every Pull Request and Push, add this workflow file to `.github/workflows/agentshield.yml`:

```yaml
name: AgentShield Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  secret-audit:
    name: Zero-Leak Secret Defense
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run AgentShield Action Gate
        uses: RitualDev-Lab/AgentShield@v1
        with:
          fail_on_leak: "true"
          base_ref: "origin/main"
          sarif_file: "results.sarif"

      - name: Upload SARIF to GitHub Security Tab
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## 7. Custom Configuration (`.agentshield.json`)

Customize detection rules, ignore paths, and entropy thresholds in `.agentshield.json` at your project root:

```json
{
  "version": "1.0",
  "entropy": {
    "enabled": true,
    "threshold": 4.5,
    "minLength": 20
  },
  "redaction": {
    "style": "token",
    "prefix": "AGENT_SHIELD"
  },
  "sandbox": {
    "blockedFiles": [
      ".env",
      ".env.*",
      "*.pem",
      "*.key",
      "id_rsa",
      "credentials.json"
    ],
    "blockedCommands": [
      "printenv",
      "export -p"
    ]
  },
  "ignorePaths": [
    "node_modules/**",
    "dist/**",
    "tests/fixtures/**",
    "*.min.js"
  ],
  "customPatterns": [
    {
      "id": "INTERNAL_TOKEN",
      "name": "Internal Corp Token",
      "regex": "corp_sec_[a-zA-Z0-9]{32}",
      "severity": "CRITICAL"
    }
  ]
}
```

---

## 8. Programmatic TypeScript / Node.js SDK

You can also import AgentShield directly into custom TypeScript/JavaScript backends or agent pipelines:

```typescript
import { 
  AgentShieldEngine, 
  AgentCommandSandbox, 
  VaultInjector, 
  ComplianceEngine 
} from "agentshield";

// 1. Initialize Engine
const shield = new AgentShieldEngine();

// 2. Scan and redact LLM input prompt
const rawPrompt = "Connect to DB using postgres://admin:superSecretP@ss123@db.internal:5432/prod";
const result = shield.scanAndRedact(rawPrompt);

console.log(result.hasSecrets); // true
console.log(result.sanitizedText);
// "Connect to DB using postgres://admin:[AGENT_SHIELD:GENERIC_PASSWORD:8f2a1b]@db.internal:5432/prod"

// 3. Local Rehydration (When receiving LLM response back)
const restoredPrompt = shield.rehydrate(result.sanitizedText);

// 4. Test Shell Sandbox
const sandbox = new AgentCommandSandbox();
const check = sandbox.inspect("cat .env");
console.log(check.allowed); // false
console.log(check.reason);  // "Blocked attempt to read raw .env file"
```

---

## 9. Troubleshooting & FAQ

### Q: Why did the pre-commit hook block my commit?
**A:** AgentShield detected a high-entropy string or recognized secret header in your staged diff. Run `npx agentshield hook check` to see the exact file and line number. If it is a false positive test fixture, add the path to `ignorePaths` in `.agentshield.json`.

### Q: Can AgentShield run in offline / air-gapped environments?
**A:** Yes. AgentShield has zero telemetry, does not send data over any network, and operates 100% locally on your machine.

### Q: What is the difference between regex matching and Shannon Entropy?
**A:** Regex matching catches structured keys with known prefixes (`AKIA...`, `sk-proj-...`). Shannon Entropy ($H \ge 4.5$) catches arbitrary random high-entropy strings, such as database passwords, hex tokens, and base64 hashes that do not follow a vendor prefix.

---

## 🔗 Official Links & Resources

- 🌐 **Interactive Documentation & Playground**: [https://agentshield.ritualdev.in/](https://agentshield.ritualdev.in/)
- 📚 **DevShelf Verified Developer Tools Hub**: [https://devshelf.ritualdev.in/](https://devshelf.ritualdev.in/)
- 🐙 **GitHub Repository**: [https://github.com/RitualDev-Lab/AgentShield](https://github.com/RitualDev-Lab/AgentShield)
- 💬 **GitHub Discussions**: [https://github.com/RitualDev-Lab/AgentShield/discussions](https://github.com/RitualDev-Lab/AgentShield/discussions)
- 🐛 **Issue Tracker**: [https://github.com/RitualDev-Lab/AgentShield/issues](https://github.com/RitualDev-Lab/AgentShield/issues)
