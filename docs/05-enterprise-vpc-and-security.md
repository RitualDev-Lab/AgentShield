# 05 — Enterprise VPC & Security Controls

## Air-Gapped Private VPC Deployment
AgentShield ships with production Helm charts and Terraform modules (AWS, Azure, GCP) maintained canonically in [`RitualDev-Lab/enterprise-governance-suite`](https://github.com/RitualDev-Lab/enterprise-governance-suite) and mirrored in [`RitualDev-Lab/agentshield-helm`](https://github.com/RitualDev-Lab/agentshield-helm):
- Zero outbound internet egress (`NetworkPolicy` restricted to RFC 1918 CIDRs).
- Non-root UID `10001`, read-only root filesystem, `cap_drop: [ALL]`, Seccomp `RuntimeDefault`.
- Self-hostable `agent-defense-hub` control plane supporting Okta OIDC / Entra SAML 2.0 SSO, 3-role RBAC (`Admin`, `Approver`, `Developer`), Ed25519 policy signing, and CEF/Splunk/Datadog SIEM forwarding.

## Compliance Alignment & Verification
- Maps secret-prevention and audit-integrity controls to **SOC 2 CC6.1/CC6.8**, **ISO 27001 A.8.24**, and **OWASP LLM06**.
- Hardware-sealed Ed25519 audit ledgers can be verified offline by external auditors via `agentshield ledger verify <path> --pub-key <signer.pub.pem>`.
- Responsible vulnerability disclosure: see [SECURITY.md](../SECURITY.md) or `security@ritualdev.in`.
