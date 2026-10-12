<div align="center">

# 🛡️ AgentShield

**Enterprise-Grade Zero-Leak Secret Defense & Sandbox for Autonomous AI Coding Agents**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Runtime](https://img.shields.io/badge/Node-%3E%3D20.0.0-emerald.svg)](https://nodejs.org)
[![Tested](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](tests/)

*Stop AI coding assistants from leaking `.env`, cloud credentials, API tokens, and private keys into shell history, commit messages, or LLM context.*

</div>

---

## ⚡ The Problem
Autonomous coding agents (**Claude Code**, **Cursor**, **Windsurf**, **Codex**, **Antigravity**) are granted shell and file-access permissions. During debugging and prompt execution, agents routinely:
1. `cat .env` or read configuration files, dumping private keys into their LLM context window.
2. Output high-entropy database passwords or Stripe secrets into stdout.
3. Commit unredacted test tokens or cloud access keys into Git history.

**AgentShield** acts as a deterministic, local-first zero-leak defense layer that intercepts, audits, and redacts credentials before they escape to model providers or git repositories.

---

## 🚀 Quick Start

### 1. Instant File Audit
```bash
# Scan any file for credential leaks
npx agentshield scan .env

# Scan with structured JSON output for CI pipelines
npx agentshield scan src/config.ts --json
```

### 2. Autonomous Agent Command Sandbox
```bash
# Wrap agent terminal executions: blocks 'cat .env', 'printenv', or secret exfiltration
npx agentshield exec "cat .env"
# Output: 🚨 [AgentShield Sandbox Block] Blocked attempt to read raw .env or private credential file...
```

### 3. Pre-Commit Zero-Leak Gate
```bash
# Install automated git pre-commit hook in your repo
npx agentshield hook git-install

# Or manually audit staged files before commit
npx agentshield hook check
```

### 4. CI/CD Pull Request Gate & GitHub Action
Run AgentShield on pull requests to fail jobs when unredacted secrets are introduced in git diffs:

```yaml
name: Security Audit
on: [pull_request, push]

jobs:
  agent-shield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: RitualDev-Lab/AgentShield@v1
        with:
          fail_on_leak: "true"
```

Or run via CLI in any CI runner:
```bash
npx agentshield ci --base origin/main --report .agentshield-report.md
```

### 5. Team Configuration (`.agentshield.json`)
Teams can define custom secret patterns, allowlists, and entropy thresholds:

```json
{
  "version": "1.0.0",
  "maskStyle": "token",
  "customPatterns": [
    {
      "id": "corp-api-key",
      "name": "Internal Corp Key",
      "regex": "CORP_SECRET_[A-Za-z0-9]{16}",
      "severity": "critical"
    }
  ]
}
```

### 6. Enterprise Compliance Audit (SOC2, PCI-DSS, HIPAA, ISO27001)
Audit repositories and files directly against regulatory cybersecurity controls:

```bash
npx agentshield compliance .env
# Output:
# 📋 [ENTERPRISE COMPLIANCE AUDIT] Status: NON_COMPLIANT (Score: 25%)
#   ❌ [SOC2] CC6.1: Logical Access Controls & Credential Integrity
#   ❌ [PCI_DSS] Req-3.4: Protection of Authentication & Cardholder Tokens
```

### 7. SIEM Exporter (CEF / JSON / Syslog)
Export real-time agent leak and command blocking telemetry to Splunk, Datadog, or Microsoft Sentinel in Common Event Format (CEF) and Syslog RFC 5424.

### 8. Zero-Trust Vault Injection
Keep zero credentials in local `.env` files. Ephemeral surrogate tokens (`[VAULT_INJECTED:KEY:hash]`) are surfaced to the agent shell and rehydrated only at runtime boundaries.

### 9. Stream Redaction (Pipe Filter)
```bash
# Redact secrets on the fly from any terminal output
cat server.log | npx agentshield stream
```

---

## 🤖 AI Agent Skill Integration

AgentShield includes a plug-and-play **Agent Skill** (`SKILL.md`) for:
- **Claude Code**: Add as custom skill in `.claude/skills/`
- **Cursor / Windsurf / Codex**: Direct CLI hook execution
- **Antigravity**: Load as workspace security skill

---

## 🧩 Programmatic SDK Usage

```typescript
import {
  AgentShieldEngine,
  AgentCommandSandbox,
  GitPreCommitGate,
  CiGateRunner,
  ComplianceEngine,
  SiemExporter,
  VaultInjector,
} from "agentshield";

const shield = new AgentShieldEngine();

// Scan & Redact
const sampleToken = ["sk-proj-", "1234567890123456789012345678901234567890"].join("");
const rawPrompt = `Use my key ${sampleToken} to test the API`;
const result = shield.scanAndRedact(rawPrompt);

console.log(result.hasSecrets); // true
console.log(result.sanitizedText);
// "Use my key [AGENT_SHIELD:OPENAI_API_KEY:c2stcH] to test the API"

// Rehydrate when receiving the response back locally
const restored = shield.rehydrate(result.sanitizedText);
```

---

## 🛡️ Built-in Detections
- 🤖 **AI & LLM Keys**: OpenAI (`sk-proj-*`), Anthropic Claude (`sk-ant-*`), Google Gemini (`AIzaSy*`), Hugging Face (`hf_*`)
- ☁️ **Cloud Providers**: AWS Access Key ID (`AKIA*`), AWS Secret Access Keys
- 💳 **Payments & SaaS**: Stripe Live & Test keys (`sk_live_*`), Slack Incoming Webhooks
- 🐙 **VCS**: GitHub Personal Access Tokens (`ghp_*`, `github_pat_*`)
- 🔐 **Cryptography**: PEM/OpenSSH private key blocks, JSON Web Tokens (JWT)
- 📊 **Mathematical Entropy**: Shannon Entropy scoring to catch high-entropy unknown passwords.

---

## 🗺️ Roadmap & Phases
- [x] **Phase 1: Core Detection Engine & Community CLI** (Shannon Entropy, Pattern Engine, Redaction Vault)
- [x] **Phase 2: Autonomous Agent Shell Sandbox & Pre-commit Gate** (Bash/PowerShell interceptor, Git Gate, SKILL.md)
- [x] **Phase 3: Team Collaboration & CI/CD Security Gate** (GitHub Action, PR diff auditing, `.agentshield.json`)
- [x] **Phase 4: Enterprise Control Plane** (Centralized compliance, SIEM export, Vault zero-trust injection)

---

## 👥 Built by RitualDev Lab
AgentShield is an open-source initiative by [RitualDev Lab](https://github.com/RitualDev-Lab).
