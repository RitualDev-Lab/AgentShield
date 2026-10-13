---
name: agent-shield
description: Enterprise-grade Zero-Leak Secret Defense & Sandbox for AI Coding Assistants. Intercepts credentials, audits git diffs, and prevents .env leakage.
version: 0.2.0
author: RitualDev Lab
license: Apache-2.0
---

# 🛡️ AgentShield AI Skill

This skill equips autonomous AI coding agents (Claude Code, Cursor, Windsurf, Codex, Antigravity) with zero-leak credential defense.

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
3. **Execution Sandbox**:
   - Wrap sensitive or dynamic script executions with AgentShield:
     ```bash
     npx @ritualdev-lab/agentshield exec "<command>"
     ```
4. **Stream Redaction**:
   - When inspecting logs that might contain tokens:
     ```bash
     <command> | npx @ritualdev-lab/agentshield stream
     ```
