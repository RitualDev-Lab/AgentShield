# 🏛️ Enterprise Service Level Agreement (SLA) & Incident Response Addendum

> **Effective Date**: November 2026  
> **Vendor Entity**: RitualDev Lab (`ritualdev.in`)  
> **Applies to**: AgentShield Enterprise, DBShield Guardrails, and Enterprise Governance Suite  
> **Canonical Online Version**: [https://ritualdev.in/sla](https://ritualdev.in/sla)

---

## 1. Scope & Objective

This Enterprise Service Level Agreement ("SLA") is an addendum to the Master Services Agreement ("MSA") entered into between **RitualDev Lab** ("Vendor") and the **Customer**. 

This document defines guaranteed response times, availability targets, severity classification criteria, escalation workflows, and financial service credits for enterprise support and incident remediation covering:
- **AgentShield Kernel & AST Micro-Sandbox** (Kubernetes Helm deployments, Docker daemons, workstation CLI).
- **DBShield Wire Proxy** (Database mutation guardrails and Model Context Protocol proxies).
- **Enterprise Governance Suite** (SIEM event streaming, audit logs, and private VPC infrastructure).

---

## 2. Severity Classification & Response Time Guarantees

All support tickets and security advisories dispatched by Customer are categorized according to the severity matrix below:

| Severity Level | Definition | Coverage Hours | Initial Triage Response SLA | Status Update Cadence | Primary Ingestion Channel |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **P1 — Critical** | Total containment failure, active zero-day exploit in agent runtime, verified credential exfiltration, or complete deployment outage. | **24/7/365** | **&lt; 1 Hour** | Every 2 hours until mitigated | `security@ritualdev.in`<br>*(Subject: `[P1-CRITICAL]`)* |
| **P2 — High** | Core security feature or AST normalizer failure without direct exploit, false-positive halting continuous deployment CI/CD pipeline, SIEM exporter failure. | Mon–Fri<br>9:00 AM – 8:00 PM IST/UTC | **&lt; 4 Hours** | Every 6 hours until resolved | `support@ritualdev.in`<br>*(Subject: `[P2-HIGH]`)* |
| **P3 — Standard** | General technical support, custom regex rule crafting, architecture integration guidance, non-blocking configuration inquiries. | Standard Business Days | **&lt; 1 Business Day** *(24h)* | As needed upon milestone | `support@ritualdev.in`<br>`developer@ritualdev.in` |

---

## 3. High Availability & Fail-Safe Architecture

1. **Local-First / Customer VPC Uptime**:
   - Because AgentShield and DBShield operate as **strictly local-first, air-gapped runtimes** without cloud vendor dependencies, engine availability is guaranteed to **99.95%** within customer Kubernetes and VM environments.
2. **Safe-Fail Default**:
   - In the event of daemon memory exhaustion, segmentation fault, or unexpected container termination, subshell interception locks by default. Commands are safely blocked until the daemon self-heals, preventing unprotected fallback leaks.

---

## 4. Multi-Tier Engineering Escalation Ladder

```
[Customer Incident Dispatch]
        │
        ▼ (T+0 to T+60m)
[Tier 1: Solutions Engineering Dispatch]
  • Initial diagnostic triage, log intake, reproduction in isolated sandbox.
        │
        ▼ (T+1h to T+4h)
[Tier 2: Senior Security & Kernel Engineers]
  • AST parser patching, linear-time regex optimization, emergency hotfix build.
        │
        ▼ (T+4h+)
[Tier 3: Core Architecture Lead & Executive Notification]
  • Executive coordination, cryptographically signed private patch release, joint post-mortem.
```

---

## 5. Enterprise Service Credits & Financial Remedies

If Vendor fails to meet the guaranteed P1 or P2 initial response SLA during any calendar month, Customer is entitled to claim service credits applied against the subsequent billing cycle:

| SLA Metric Breach | Service Credit (% of Monthly Service Fee) |
| :--- | :---: |
| **P1 Initial Response exceeds 1 Hour** (up to 3 hours) | **10% Credit** |
| **P1 Initial Response exceeds 3 Hours** | **25% Credit** |
| **Containerized Daemon Uptime drops below 99.9%** | **25% Credit** |
| **Containerized Daemon Uptime drops below 99.0%** | **50% Credit** |

*Service credits represent the sole and exclusive financial remedy for operational SLA breaches.*

---

## 6. Exclusions

SLA commitments do not apply to service interruptions resulting from:
- Customer-managed infrastructure outages, AWS/GCP/Azure VPC routing partitions, or host OS kernel panics.
- Unauthorized modifications, decompilation, or alterations of AgentShield binary distributions.
- External upstream AI provider outages (e.g., Anthropic Claude API, OpenAI API downtime).
- Force majeure events beyond reasonable commercial control.

---

## 7. Official Dispatch Directory

- **Security & P1 Incidents**: [`security@ritualdev.in`](mailto:security@ritualdev.in)
- **Technical Support & P2 Incidents**: [`support@ritualdev.in`](mailto:support@ritualdev.in)
- **Developer API & Integration**: [`developer@ritualdev.in`](mailto:developer@ritualdev.in)
- **General Inquiries & Billing**: [`hello@ritualdev.in`](mailto:hello@ritualdev.in)
- **Online Canonical URL**: [https://ritualdev.in/sla](https://ritualdev.in/sla)
