# Open Governance Charter & Project Stewardship

## 🌟 Mission & Guiding Principles

The mission of **AgentShield** is to provide a neutral, open-source, air-gapped, and zero-compromise security foundation that protects developers, enterprises, and individual maintainers from credential exfiltration and unauthorized command execution caused by autonomous AI coding agents.

### Core Tenets:
1. **Local-First & Zero Telemetry Leak**: The security defense engine must function 100% locally and offline without mandatory third-party network egress or external server callbacks.
2. **Deterministic Neutrality**: Security verdicts (redaction, AST command interception, git hooks) are mathematically deterministic, transparent, and grounded in Shannon entropy and standardized regex patterns.
3. **Open Standards Alignment**: The project adheres strictly to OASIS SARIF 2.1.0, OWASP Top 10 for LLM Applications (LLM01–LLM10), MITRE ATLAS, and Linux Foundation OpenSSF standards.
4. **Community Stewardship**: Governance is distributed, collaborative, and vendor-neutral under the Apache 2.0 License.

---

## 🏛️ Governance Structure

AgentShield follows a **Maintainer-Council Stewardship** model:

```
                      ┌────────────────────────────────────────┐
                      │          Community Assembly            │
                      │   (Contributors, Researchers, Users)   │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │          Core Maintainers              │
                      │  (Architecture, PR Reviews, Releases)  │
                      └──────────────────┬─────────────────────┘
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │       Security & Bounty Council        │
                      │ (CVE Triage, Disclosures, Grants Fund) │
                      └────────────────────────────────────────┘
```

### Roles and Responsibilities:
- **Contributors**: Anyone who submits code, tests, documentation, or secret pattern definitions via Pull Requests. After 3 accepted pull requests, contributors are eligible for Contributor status and voting in RFCs.
- **Core Maintainers**: Responsible for architectural direction, reviewing pull requests, cutting semantic releases (`vX.Y.Z`), and maintaining project infrastructure.
- **Security & Bounty Council**: Independent working group responsible for triaging incoming private security advisories within 24 hours, coordinating CVE disclosures, and administering the **AgentShield Security Defense Fund**.

---

## 🗳️ Decision-Making Process & RFCs

- **Consensus Seeking**: Normal code contributions, documentation improvements, and bug fixes require approval from at least one Core Maintainer.
- **Request for Comments (RFC)**: Major architectural changes (e.g. adding new tokenization algorithms, breaking CLI syntax, modifying the kernel sandbox, or changing grant disbursements) require an RFC filed under GitHub Discussions with a 7-day open community review period.
- **Voting**: If consensus cannot be reached, active Core Maintainers vote on an RFC where a 2/3 majority decides the outcome.

---

## 💰 Fiscal Sponsorship & Grant Management

All financial contributions, direct donations via Dodo Payments / RoleNest, and non-dilutive foundation grants (NLnet, OpenSSF, Mozilla) are managed according to the following fiscal guidelines:

1. **Defense Fund Ring-Fencing**: At least **60%** of community donation funds are earmarked specifically for Community Security Bounties and ethical researcher rewards.
2. **Infrastructure & Testing**: Up to **25%** funds continuous cross-platform automated fuzzing infrastructure (Windows, macOS, Ubuntu runner fleets across Node.js versions).
3. **Open Transparency**: Every disbursement and grant milestones report is cryptographically recorded in the project's public ledger and published in quarterly transparency reports.
4. **No Commercial Paywalls**: Core features, secret patterns, and local sandboxing capabilities will remain 100% free and open-source in perpetuity.

---

## 📜 Amendments

Amendments to this Governance Charter may be proposed by any contributor and require a formal RFC review and unanimous approval by the Core Maintainers.
