# Non-Dilutive Grant Dossier & Foundation Application Package

## 🎯 Executive Overview

**Project**: AgentShield  
**Canonical Domain**: [https://agentshield.ritualdev.in/](https://agentshield.ritualdev.in/)  
**Primary Repository**: [https://github.com/RitualDev-Lab/AgentShield](https://github.com/RitualDev-Lab/AgentShield)  
**License**: Apache-2.0 (OSI-Approved, Open-Source Certified)  
**Classification**: AI Agentic Cybersecurity, Supply Chain Defense, Zero-Leak Secret Interception, AST Sandbox

---

## 🏛️ Target Foundations & Grant Mapping

```
                                  AgentShield Security Engine
                                               │
             ┌─────────────────────────────────┼─────────────────────────────────┐
             │                                 │                                 │
             ▼                                 ▼                                 ▼
   NLnet Foundation (NGI Zero)       OpenSSF (Linux Foundation)      Mozilla Technology Fund (MTF)
   • Zero-leak agent sandbox         • Supply chain CI/CD gates      • Privacy & User Sovereignty
   • Air-gapped Shannon entropy      • OASIS SARIF 2.1.0 GHAS        • Guardrails for Claude & Cursor
   • Decentralized tokenization      • Alpha-Omega audit compliance  • Public-interest AI defense
```

---

## 1. NLnet Foundation — NGI Zero Entrust Application

### Proposal Title:
*AgentShield: Deterministic Zero-Leak Credential Interception and Kernel Confinement for Autonomous AI Agents*

### Abstract:
Autonomous AI agents (such as Claude Code, Cursor, and windsurf) interact directly with developer filesystems and execution terminals. Traditional security scanners run asynchronously in post-commit CI or batch audits—well after an LLM context window has already ingested sensitive production tokens (`.env`, private keys, API secrets).

AgentShield solves this by introducing a deterministic, in-flight interception proxy and AST command sandbox that sanitizes prompts and blocks exfiltration before tokens escape the local host machine. With zero cloud dependency, 100% offline mathematical entropy verification, and native SARIF 2.1.0 reporting, AgentShield restores developer data sovereignty in the age of agentic software engineering.

### Milestone Schedule & Funding Allocation:
| Milestone | Technical Objective | Deliverables | Verification Metric |
| :--- | :--- | :--- | :--- |
| **M1: Core Sandbox & Engine Hardening** | Sub-millisecond Aho-Corasick multi-pattern regex engine and Shannon entropy tokenization. | `src/engine.ts`, `src/entropy.ts`, and offline test suite. | >50 MB/sec throughput, <1ms scan latency. |
| **M2: Stdio Interception & Cross-Platform Isolation** | Windows PowerShell, macOS sandbox-exec, and Linux Landlock/Bubblewrap micro-confinement profiles. | `src/interceptor.ts`, `src/kernel.ts`. | 100% containment of raw `.env` access attempts across all 3 major OS environments. |
| **M3: Open CI/CD Gates & SARIF Standardization** | Zero-dependency GitHub Marketplace Action, pre-commit hook integrations, and SARIF 2.1.0 static analysis exporter. | `action.yml`, `src/sarif.ts`, `src/ci.ts`. | Automatic GitHub Advanced Security (GHAS) code scanning alert generation. |
| **M4: Public Transparency & Community Bounties** | Public write-ahead cryptographic HMAC audit ledger and bug bounty disbursement program. | `src/ledger.ts`, `SECURITY.md`, public audit endpoint. | 100% verifiable HMAC chained ledger for community audits. |

---

## 2. OpenSSF (Open Source Security Foundation) — Alpha-Omega Grant

### Focus Area:
*Securing the AI-Augmented Software Development Lifecycle (SDLC) and Developer Environments*

### Problem Statement:
Developer environments are increasingly orchestrated by autonomous AI reasoning loops. A single compromised prompt or hallucinated command can cause an AI agent to dump `.env` files into public pull request review bots or execute unverified third-party scripts.

### AgentShield Intervention:
1. **Developer Machine Protection**: Automatic Git pre-commit hooks (`agentshield hook git-install`) prevent accidental secret staging.
2. **CI/CD Security Gate**: GitHub Marketplace Action blocks PRs containing leaked credentials and emits inline SARIF 2.1.0 annotations.
3. **Enterprise Compliance**: Automated compliance crosswalk mapping findings directly to **OWASP Top 10 for LLMs (LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure)** and **MITRE ATLAS (AML.T0043, AML.T0054)**.

---

## 3. Mozilla Technology Fund (MTF) — Trustworthy AI

### Focus Area:
*User Agency, Privacy Safeguards, and Countering Automated Exploitation in Generative AI*

### Impact Statement:
AgentShield puts control back into the hands of developers and end-users. Unlike SaaS AI security wrappers that proxy your codebase through proprietary remote clouds, AgentShield runs entirely on the user's local workstation. The local surrogate tokenization algorithm substitutes live secrets with ephemeral deterministic identifiers before LLM ingestion, allowing the user to inspect and rehydrate secrets safely without proprietary vendors ever capturing sensitive credentials.

---

## 4. Technical Compliance & Open Standards Verification Matrix

| Standard / Framework | Regulatory Requirement | AgentShield Implementation | Verification Test File |
| :--- | :--- | :--- | :--- |
| **OWASP LLM02** | Sensitive Information Disclosure | Deterministic in-flight tokenization & surrogate substitution | `tests/engine.test.ts` |
| **OWASP LLM08** | Excessive Agency | AST shell sandbox command blocking (`cat .env`, curl exfiltration) | `tests/sandbox.test.ts` |
| **MITRE ATLAS AML.T0043** | LLM Information Extraction | Shannon entropy regex tokenizer & canary honeypot tripwires | `tests/canary.test.ts` |
| **OASIS SARIF 2.1.0** | Static Analysis Interchange Format | Standardized JSON schema export for GitHub Code Scanning | `tests/sarif.test.ts` |
| **SOC 2 Type II / ISO 27001** | Audit Trail & Integrity | Cryptographic HMAC-SHA256 write-ahead tamper-evident ledger | `tests/ledger.test.ts` |
