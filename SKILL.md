---
name: agent-shield
description: Enterprise-grade Zero-Leak Secret Defense & Sandbox for AI Coding Assistants. Intercepts credentials, audits git diffs, and prevents .env leakage.
version: 0.3.0
author: RitualDev Lab
license: Apache-2.0
---

# 🛡️ AgentShield AI Skill

This skill equips autonomous AI coding agents (Antigravity, Claude Code, Cursor, Windsurf, Codex) with zero-leak credential defense, OS-level micro-jail sandboxing, and real-time streaming redaction.

## Directives for AI Agents

When developing, testing, or modifying code:
1. **Never dump raw credential files**:
   - DO NOT run `cat .env`, `type .env`, or print private key files into terminal logs.
   - Use mock or sanitized dummy values when writing automated tests.
2. **Pre-Flight Commit Verification**:
   - Before executing `git commit` or opening a PR, always audit staged files:
     ```bash
     npx @ritualdev-lab/agentshield hook check
     ```
   - If secrets or `.env` files are detected, unstage or redact them before proceeding.
3. **OS Micro-Jail Execution Sandbox**:
   - Wrap sensitive or dynamic script executions with AgentShield OS micro-jails:
     - **Linux**: Bubblewrap (`bwrap`) container isolation with `--unshare-all` and read-only system mounts.
     - **Windows**: Low-Integrity AppContainer boundary runner with restricted DACLs.
     - **macOS**: Apple Seatbelt (`sandbox-exec`) system call mediation.
     ```bash
     npx @ritualdev-lab/agentshield exec "<command>"
     ```
4. **Stream Redaction**:
   - When inspecting logs or executing tasks that might output tokens:
     ```bash
     <command> | npx @ritualdev-lab/agentshield stream
     ```

## 🛸 Antigravity Custom Extension Profile

AgentShield provides seamless integration with Google Antigravity agents via `.agentshield.json`:

```json
{
  "antigravity": {
    "enabled": true,
    "profile": "high-assurance-agent",
    "interceptTools": ["run_command", "write_file", "edit_file"],
    "enforceSandbox": true,
    "requireIsolation": false,
    "quarantineOnCanaryTrip": true,
    "protectedPatterns": [
      "\\.env(?:\\.[a-zA-Z0-9_-]+)?",
      "id_rsa(?:\\.pub)?",
      "id_ed25519",
      "\\.aws[\\/]credentials",
      "\\.ssh[\\/].*"
    ],
    "hooks": {
      "preCommand": "agentshield exec",
      "preWrite": "agentshield scan",
      "auditLog": ".agentshield/antigravity.audit.log"
    }
  }
}
```

### Antigravity Tool Hooks:
- **`run_command`**: Evaluated against the AST pre-flight firewall and container micro-jail rules. Malicious attempts to read `.env`, exfiltrate keys via `curl`, or elevate container privileges are blocked with exit code 1.
- **`write_file` & `edit_file`**: Files matching protected patterns (`.env`, `id_rsa`) are guarded against accidental overwrite or secret exposure.
- **Canary Tripwires**: Any access to canary assets (`AWS_SECRET_ACCESS_KEY_CANARY`, `OPENAI_API_KEY_CANARY`) instantly locks session into quarantine mode.

