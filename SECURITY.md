# Security Policy & Community Bug Bounty Program

## 🛡️ Commitment to Security

As an enterprise security and zero-leak defense layer for autonomous AI agents, **AgentShield** treats the security of our regex engine, Shannon entropy tokenizer, AST sandbox, and kernel isolation with the highest priority.

We actively reward ethical security researchers, white-hat hackers, and community developers who discover bypasses, jailbreaks, or sandbox escapes through our **Community Vulnerability & Bug Bounty Program**.

---

## 🏆 Vulnerability Bounty Reward Tiers

Bounties are paid directly via **Dodo Payments / UPI / GitHub Sponsors** from the **AgentShield Security Defense Fund**:

| Severity Tier | Qualifying Vulnerabilities | Bounty Reward (USD) | Recognition |
| :--- | :--- | :--- | :--- |
| **🚨 Critical** | • Full AST Shell Sandbox Breakout (executing forbidden commands)<br>• Arbitrary OS code execution from untrusted LLM prompt inputs<br>• Tamper-evident write-ahead audit ledger forgery | **\$250 – \$500** | Hall of Fame ★ Top Hero + Custom Hall Badge + Release Notes |
| **⚠️ High** | • Deterministic bypass of secret redaction for major cloud API keys (OpenAI, AWS, Anthropic, Stripe)<br>• Stdio streaming inter-chunk leakage without redaction<br>• Enterprise SSO JWT token bypass or privilege escalation | **\$100 – \$200** | Hall of Fame + Security Advisory Credit |
| **🟡 Medium** | • Regular expression denial-of-service (ReDoS) leading to agent crash<br>• Obfuscated ANSI-C escape subshell bypass not caught by sandbox<br>• Environment variable leak through unorthodox shell redirection | **\$50** | Security Advisory Credit |
| **🔵 Low / Informational** | • Minor configuration weaknesses or false-positive edge cases | Recognition | Contributor Credit |

---

## 🧪 Local PoC Verification Runner (`bounty-verify`)

Before reporting, you can locally verify whether your exploit payload or bypass executes against the AgentShield engine:

```bash
# Run local PoC exploit check
npx @ritualdev-lab/agentshield bounty-verify <exploit-file-or-command>

# Example: Testing command sandbox evasion
npx @ritualdev-lab/agentshield bounty-verify "cat .env"
```

---

## 📦 Supported Versions

Only the latest active major and minor releases receive security patches, bug fixes, and bounty eligibility:

| Version | Supported | Bounty Eligible |
| :--- | :---: | :---: |
| `0.1.x` | :white_check_mark: | :white_check_mark: Yes |
| `< 0.1` | :x: | :x: No |

---

## 🚨 Submitting a Security Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues, discussions, or social media.**

### Coordinated Submission Process:
1. **GitHub Private Security Advisory (Preferred):**
   - Submit through [AgentShield Security Advisory](https://github.com/RitualDev-Lab/AgentShield/security/advisories/new).
2. **Encrypted Email:**
   - Email reproduction details to **`security@ritualdev.lab`** or RitualDev Lab maintainers.

### Submission Requirements:
- **Title**: Clear description of the vulnerability (e.g. `[Sandbox Bypass] Bash brace expansion evades .env read block`).
- **Reproducible PoC**: Minimal shell script, payload, or file that demonstrates the leak/breakout.
- **Environment**: Node.js version, OS (Linux, macOS, Windows), and agent runtime (Cursor, Claude Code, etc.).
- **Payment Details**: Dodo Payments email, PayPal, or UPI ID for bounty disbursement.

---

## ⏱️ Response Timeline & SLA

- **Acknowledgment:** Within **24 hours**.
- **Triage & Reproducibility:** Within **48 hours**.
- **Fix & Patch Release:** Within **5 business days** for Critical, **10 business days** for High.
- **Bounty Disbursement:** Immediately upon confirmation and merge of the mitigation patch.
- **Coordinated Disclosure:** 90-day window with public credit in CVE / GitHub Advisory notes.
