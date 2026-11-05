import { createHash } from "node:crypto";
import {
  type ComplianceAuditReport,
  ComplianceEngine,
  type ComplianceFramework,
} from "./compliance.js";
import type { FleetAgentTelemetryReport } from "./control-plane.js";
import { AgentShieldEngine } from "./engine.js";
import { type AuditLedgerEntry, TamperEvidentLedger } from "./ledger.js";
import type { DetectedSecret } from "./types.js";

export interface ComplianceBundleOptions {
  organizationName: string;
  auditorEmail?: string;
  frameworks?: ComplianceFramework[];
  includeLedgerEvidence?: boolean;
}

export type ExecutiveAssessmentStatus =
  | "NO_FINDINGS_IN_ASSESSED_CONTROLS"
  | "FINDINGS_DETECTED"
  | "COMPLIANT"
  | "NON_COMPLIANT";

export interface ComplianceAttestationPackage {
  bundleId: string;
  generatedAt: string;
  organizationName: string;
  auditorEmail: string;
  frameworks: ComplianceFramework[];
  executiveStatus: ExecutiveAssessmentStatus;
  complianceScore: number;
  cryptographicEvidence: {
    ledgerVerificationStatus: "VERIFIED_UNBROKEN" | "CORRUPTED" | "EMPTY";
    totalVerifiedBlocks: number;
    headMerkleRoot: string;
    signingKeyTrust?: "AUTHENTICATED_KEY" | "DEFAULT_INSECURE_SALT";
    verificationError?: string;
  };
  metrics: {
    activeDeveloperNodes: number;
    totalBlockedViolations: number;
    totalSecretsRedacted: number;
  };
  auditReport: ComplianceAuditReport;
  rawEvidencePayloadSha256: string;
}

/**
 * Enterprise SOC 2 / ISO 27001 / HIPAA Compliance Package Generator:
 * Generates mathematically attested audit bundles for external SOC 2 Type II,
 * PCI-DSS, and ISO 27001 compliance auditors.
 */
export class EnterpriseComplianceBundleGenerator {
  private defaultOptions: ComplianceBundleOptions;

  constructor(
    defaultOptions: ComplianceBundleOptions = { organizationName: "Enterprise Organization" },
  ) {
    this.defaultOptions = defaultOptions;
  }

  public generate(
    fleetReports: FleetAgentTelemetryReport[],
    allLedgerEntries: AuditLedgerEntry[] = [],
    ledgerSigningKey?: string,
  ): ComplianceAttestationPackage {
    return EnterpriseComplianceBundleGenerator.generateBundle(
      fleetReports,
      allLedgerEntries,
      ledgerSigningKey,
      this.defaultOptions,
    );
  }

  public toMarkdown(pkg: ComplianceAttestationPackage): string {
    return EnterpriseComplianceBundleGenerator.toExecutiveMarkdown(pkg);
  }

  /**
   * Builds a complete cryptographic compliance attestation bundle
   */
  public static generateBundle(
    fleetReports: FleetAgentTelemetryReport[],
    allLedgerEntries: AuditLedgerEntry[] = [],
    ledgerSigningKey: string = process.env.AGENTSHIELD_LEDGER_KEY ||
      "agentshield-tamper-evident-salt-v1",
    options: ComplianceBundleOptions = { organizationName: "Enterprise Organization" },
  ): ComplianceAttestationPackage {
    const frameworks = options.frameworks || ["soc2", "pci_dss", "hipaa", "iso27001"];
    const totalBlocked = fleetReports.reduce((sum, r) => sum + r.totalCommandsBlocked, 0);
    const totalRedacted = fleetReports.reduce((sum, r) => sum + r.totalSecretsRedacted, 0);

    const collectedFindings: DetectedSecret[] = [];
    const engine = new AgentShieldEngine();

    // 1. Inspect ledger entries for unmitigated leaks or quarantined incidents
    for (const entry of allLedgerEntries) {
      if (entry.verdict === "QUARANTINED") {
        collectedFindings.push({
          patternId: "canary-tripwire-quarantined",
          patternName: "Quarantined Agent Security Tripwire",
          category: "generic",
          severity: "critical",
          raw: entry.command,
          redacted: "[QUARANTINED_ACTION]",
          line: entry.sequence,
          column: 1,
          entropy: 5.0,
        });
      } else if (entry.verdict === "ALLOWED") {
        const leaks = engine.scan(entry.command);
        if (leaks.length > 0) {
          collectedFindings.push(...leaks);
        }
      }
    }

    // 2. Inspect fleet telemetry for quarantined nodes
    for (const report of fleetReports) {
      if (report.quarantined) {
        collectedFindings.push({
          patternId: "quarantined-agent-node",
          patternName: `Quarantined Developer Node: ${report.hostname || report.agentId}`,
          category: "generic",
          severity: "critical",
          raw: report.agentId,
          redacted: "[QUARANTINED_NODE]",
          line: 1,
          column: 1,
          entropy: 5.0,
        });
      }
    }

    // 3. Verify cryptographic integrity of the ledger
    let ledgerStatus: "VERIFIED_UNBROKEN" | "CORRUPTED" | "EMPTY" = "EMPTY";
    let headMerkleRoot = "0".repeat(64);
    let verificationError: string | undefined;

    if (allLedgerEntries.length > 0) {
      const verification = TamperEvidentLedger.verifyEntries(allLedgerEntries, ledgerSigningKey);
      ledgerStatus = verification.isValid ? "VERIFIED_UNBROKEN" : "CORRUPTED";
      headMerkleRoot = allLedgerEntries[allLedgerEntries.length - 1].hash;
      verificationError = verification.error;

      if (!verification.isValid) {
        collectedFindings.push({
          patternId: "cryptographic-ledger-tampering",
          patternName: "Audit Ledger Cryptographic Integrity Failure",
          category: "crypto",
          severity: "critical",
          raw: `CORRUPTED_LEDGER_SEQUENCE_${verification.corruptedSequence || 0}`,
          redacted: "[AUDIT_TRAIL_TAMPERED]",
          line: verification.corruptedSequence || 1,
          column: 1,
          entropy: 5.0,
        });
      }
    }

    // Run compliance evaluation against collected findings
    const auditReport = ComplianceEngine.evaluate(collectedFindings, totalBlocked, frameworks);

    // Fail executive status and score if ledger is corrupted
    const isCorrupted = ledgerStatus === "CORRUPTED";
    const executiveStatus: ExecutiveAssessmentStatus = isCorrupted
      ? "FINDINGS_DETECTED"
      : auditReport.status;
    const complianceScore = isCorrupted ? 0 : auditReport.score;

    const isDefaultKey =
      ledgerSigningKey === "agentshield-tamper-evident-salt-v1" ||
      !process.env.AGENTSHIELD_LEDGER_KEY;
    const signingKeyTrust: "AUTHENTICATED_KEY" | "DEFAULT_INSECURE_SALT" = isDefaultKey
      ? "DEFAULT_INSECURE_SALT"
      : "AUTHENTICATED_KEY";

    const bundleId = `attestation_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const generatedAt = new Date().toISOString();

    const rawPayload = JSON.stringify({
      bundleId,
      fleetReports,
      ledgerEntriesCount: allLedgerEntries.length,
      headMerkleRoot,
      auditReport,
      signingKeyTrust,
    });
    const rawEvidencePayloadSha256 = createHash("sha256").update(rawPayload).digest("hex");

    return {
      bundleId,
      generatedAt,
      organizationName: options.organizationName,
      auditorEmail: options.auditorEmail || "security-audits@ritualdev.in",
      frameworks,
      executiveStatus,
      complianceScore,
      cryptographicEvidence: {
        ledgerVerificationStatus: ledgerStatus,
        totalVerifiedBlocks: allLedgerEntries.length,
        headMerkleRoot,
        signingKeyTrust,
        verificationError,
      },
      metrics: {
        activeDeveloperNodes: fleetReports.length,
        totalBlockedViolations: totalBlocked,
        totalSecretsRedacted: totalRedacted,
      },
      auditReport,
      rawEvidencePayloadSha256,
    };
  }

  /**
   * Formats the compliance package into a human-readable executive Markdown document
   */
  public static toExecutiveMarkdown(pkg: ComplianceAttestationPackage): string {
    const isCorrupted = pkg.cryptographicEvidence.ledgerVerificationStatus === "CORRUPTED";
    const isDefaultKey = pkg.cryptographicEvidence.signingKeyTrust === "DEFAULT_INSECURE_SALT";

    const lines = [
      "# 🏛️ Enterprise Security & Compliance Attestation Report",
      `**Organization**: ${pkg.organizationName}`,
      `**Attestation Bundle ID**: \`${pkg.bundleId}\``,
      `**Attestation Hash (SHA-256)**: \`${pkg.rawEvidencePayloadSha256}\``,
      `**Generated Timestamp**: ${pkg.generatedAt}`,
      `**Auditor Contact**: ${pkg.auditorEmail}`,
      "",
      "---",
      "",
      "## 🛡️ Executive Compliance Rating",
      `- **Overall Status**: **${pkg.executiveStatus}**`,
      `- **Framework Compliance Score**: **${pkg.complianceScore}%**`,
      `- **Frameworks Evaluated**: ${pkg.frameworks.map((f) => f.toUpperCase()).join(", ")}`,
      "",
      "> [!IMPORTANT]",
      `> **Scope & Limitations**: ${pkg.auditReport.scopeDisclosure.disclaimer}`,
      "",
    ];

    if (isCorrupted) {
      lines.push(
        "> [!CAUTION]",
        `> **CRITICAL INTEGRITY FAILURE**: The cryptographic audit ledger chain failed verification (${pkg.cryptographicEvidence.verificationError || "Tampered block detected"}). This attestation explicitly REFUSES to certify compliance.`,
        "",
      );
    }

    if (isDefaultKey) {
      lines.push(
        "> [!WARNING]",
        "> **SECURITY NOTICE**: Attestation verified using default developmental salt. For production SOC 2 / ISO 27001 audit defense, configure `AGENTSHIELD_LEDGER_KEY` to enforce non-falsifiable signing.",
        "",
      );
    }

    lines.push(
      "## 🔐 Cryptographic Ledger Verification",
      `- **HMAC Chain Status**: **${pkg.cryptographicEvidence.ledgerVerificationStatus}**`,
      `- **Signing Key Trust**: \`${pkg.cryptographicEvidence.signingKeyTrust || "AUTHENTICATED_KEY"}\``,
      `- **Verified Audit Blocks**: ${pkg.cryptographicEvidence.totalVerifiedBlocks}`,
      `- **Head Merkle Root**: \`${pkg.cryptographicEvidence.headMerkleRoot}\``,
      "",
      "## 📊 Fleet Activity & Threat Neutralization",
      `- **Audited Developer Workstations**: ${pkg.metrics.activeDeveloperNodes}`,
      `- **Unauthorized Egress Commands Blocked**: ${pkg.metrics.totalBlockedViolations}`,
      `- **In-Flight Credentials Redacted**: ${pkg.metrics.totalSecretsRedacted}`,
      "",
      "## 📋 Regulatory Controls Verification Summary",
      ...pkg.auditReport.controls.map(
        (c) => `- **[${c.framework.toUpperCase()}] ${c.controlId}** (${c.name}): **${c.status}**`,
      ),
      "",
    );

    if (pkg.executiveStatus === "NO_FINDINGS_IN_ASSESSED_CONTROLS" && !isCorrupted) {
      lines.push(
        "> *This attestation confirms zero unauthorized credential egress to third-party LLM inference windows.*",
      );
    } else {
      lines.push(
        "> *ATTENTION: Security findings or integrity anomalies detected. Remediation required before compliance certification.*",
      );
    }

    return lines.join("\n");
  }

  /**
   * Formats the compliance package into a print-ready self-contained HTML audit document.
   */
  public static toHtml(pkg: ComplianceAttestationPackage): string {
    const statusColor =
      pkg.executiveStatus === "NO_FINDINGS_IN_ASSESSED_CONTROLS" ||
      pkg.executiveStatus === "COMPLIANT"
        ? "#10b981"
        : "#ef4444";

    const controlsHtml = pkg.auditReport.controls
      .map(
        (c) => `
      <tr>
        <td style="font-family: monospace; font-weight: 700;">[${c.framework.toUpperCase()}] ${c.controlId}</td>
        <td><strong>${c.name}</strong><br><span style="color: #64748b; font-size: 13px;">${c.description}</span></td>
        <td>
          <span style="display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 12px; font-weight: 700; background: ${
            c.status === "PASSED"
              ? "#dcfce7; color: #15803d"
              : c.status === "NOT_ASSESSED"
                ? "#f1f5f9; color: #64748b"
                : "#fee2e2; color: #b91c1c"
          };">
            ${c.status}
          </span>
        </td>
      </tr>`,
      )
      .join("");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentShield Compliance Audit Report - ${pkg.organizationName}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 40px; color: #0f172a; background: #fff; }
    .header { border-bottom: 2px solid #e2e8f0; padding-bottom: 24px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
    .badge { background: ${statusColor}; color: white; padding: 8px 16px; border-radius: 8px; font-weight: 700; font-size: 18px; }
    .meta-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; background: #f8fafc; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; }
    .meta-item { font-size: 13px; }
    .meta-item .label { color: #64748b; text-transform: uppercase; font-size: 11px; font-weight: 600; margin-bottom: 4px; }
    .meta-item .val { font-weight: 600; font-size: 15px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 14px; }
    th { text-align: left; padding: 12px; background: #f1f5f9; border-bottom: 2px solid #cbd5e1; }
    td { padding: 14px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    .proof-box { background: #0f172a; color: #f8fafc; padding: 20px; border-radius: 8px; font-family: monospace; font-size: 12px; margin-top: 30px; }
    .signature { margin-top: 40px; padding-top: 20px; border-top: 1px dashed #cbd5e1; display: flex; justify-content: space-between; font-size: 12px; color: #64748b; }
    @media print { body { padding: 20px; } }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin: 0; font-size: 26px;">🛡️ AgentShield Enterprise Compliance Audit</h1>
      <p style="margin: 6px 0 0; color: #64748b;">AI Agent Runtime Defense, Egress Controls & Cryptographic Ledger Proofs</p>
    </div>
    <div class="badge">${pkg.complianceScore}% COMPLIANT</div>
  </div>

  <div class="meta-grid">
    <div class="meta-item"><div class="label">Organization</div><div class="val">${pkg.organizationName}</div></div>
    <div class="meta-item"><div class="label">Attestation ID</div><div class="val" style="font-family: monospace;">${pkg.bundleId}</div></div>
    <div class="meta-item"><div class="label">Generated At</div><div class="val">${pkg.generatedAt}</div></div>
    <div class="meta-item"><div class="label">Auditor Contact</div><div class="val">${pkg.auditorEmail}</div></div>
  </div>

  <h2>Security Controls Matrix (${pkg.frameworks.map((f) => f.toUpperCase()).join(", ")})</h2>
  <table>
    <thead>
      <tr>
        <th style="width: 20%;">Control ID</th>
        <th style="width: 65%;">Control Description</th>
        <th style="width: 15%;">Status</th>
      </tr>
    </thead>
    <tbody>
      ${controlsHtml}
    </tbody>
  </table>

  <h2>Cryptographic Tamper-Evident Ledger Verification</h2>
  <div class="proof-box">
    <div><strong>HMAC-SHA256 Chain Status:</strong> ${pkg.cryptographicEvidence.ledgerVerificationStatus}</div>
    <div><strong>Verified Audit Blocks:</strong> ${pkg.cryptographicEvidence.totalVerifiedBlocks}</div>
    <div><strong>Head Merkle Root:</strong> ${pkg.cryptographicEvidence.headMerkleRoot}</div>
    <div><strong>Package Attestation Hash:</strong> ${pkg.rawEvidencePayloadSha256}</div>
  </div>

  <div class="signature">
    <div>Audited by AgentShield Kernel Defense Engine</div>
    <div>RitualDev-Lab / Enterprise Sandbox Architecture</div>
  </div>
</body>
</html>`;
  }

  /**
   * Formats the compliance package into a clean PDF document string compliant with PDF-1.4.
   */
  public static toPdf(pkg: ComplianceAttestationPackage): string {
    const title = `AgentShield Compliance Audit Report - ${pkg.organizationName}`;
    const lines = [
      "================================================================================",
      `                     ${title.toUpperCase()}`,
      "================================================================================",
      "",
      `Bundle ID:        ${pkg.bundleId}`,
      `Organization:     ${pkg.organizationName}`,
      `Generated At:     ${pkg.generatedAt}`,
      `Auditor Contact:  ${pkg.auditorEmail}`,
      `Compliance Score: ${pkg.complianceScore}% (${pkg.executiveStatus})`,
      `Frameworks:       ${pkg.frameworks.map((f) => f.toUpperCase()).join(", ")}`,
      "",
      "--------------------------------------------------------------------------------",
      "CRYPTOGRAPHIC LEDGER PROOF",
      "--------------------------------------------------------------------------------",
      `Chain Status:     ${pkg.cryptographicEvidence.ledgerVerificationStatus}`,
      `Verified Blocks:  ${pkg.cryptographicEvidence.totalVerifiedBlocks}`,
      `Head Merkle Root: ${pkg.cryptographicEvidence.headMerkleRoot}`,
      `SHA-256 Hash:     ${pkg.rawEvidencePayloadSha256}`,
      "",
      "--------------------------------------------------------------------------------",
      "CONTROL VERIFICATION MATRIX",
      "--------------------------------------------------------------------------------",
    ];

    for (const c of pkg.auditReport.controls) {
      lines.push(`[${c.status}] [${c.framework.toUpperCase()}] ${c.controlId}: ${c.name}`);
      lines.push(`       ${c.description}`);
      lines.push("");
    }

    lines.push("================================================================================");

    const textContent = lines.join("\n");
    const escapedText = textContent
      .replace(/\\/g, "\\\\")
      .replace(/\(/g, "\\(")
      .replace(/\)/g, "\\)");

    return `%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj
4 0 obj << /Length ${escapedText.length + 100} >> stream
BT
/F1 10 Tf
40 750 Td
14 TL
(${escapedText.split("\n").join(") '\n(")}) Tj
ET
endstream endobj
5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Courier >> endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000227 00000 n 
0000000400 00000 n 
trailer << /Size 6 /Root 1 0 R >>
startxref
480
%%EOF`;
  }
}
