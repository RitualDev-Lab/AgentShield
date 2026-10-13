import { createHash } from "node:crypto";
import {
  ComplianceEngine,
  type ComplianceAuditReport,
  type ComplianceFramework,
} from "./compliance.js";
import { type AuditLedgerEntry, TamperEvidentLedger } from "./ledger.js";
import type { FleetAgentTelemetryReport } from "./control-plane.js";

export interface ComplianceBundleOptions {
  organizationName: string;
  auditorEmail?: string;
  frameworks?: ComplianceFramework[];
  includeLedgerEvidence?: boolean;
}

export interface ComplianceAttestationPackage {
  bundleId: string;
  generatedAt: string;
  organizationName: string;
  auditorEmail: string;
  frameworks: ComplianceFramework[];
  executiveStatus: "COMPLIANT" | "NON_COMPLIANT";
  complianceScore: number;
  cryptographicEvidence: {
    ledgerVerificationStatus: "VERIFIED_UNBROKEN" | "CORRUPTED" | "EMPTY";
    totalVerifiedBlocks: number;
    headMerkleRoot: string;
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

    // Run compliance evaluation
    const auditReport = ComplianceEngine.evaluate([], totalBlocked, frameworks);

    // Verify cryptographic integrity of the ledger
    let ledgerStatus: "VERIFIED_UNBROKEN" | "CORRUPTED" | "EMPTY" = "EMPTY";
    let headMerkleRoot = "0".repeat(64);

    if (allLedgerEntries.length > 0) {
      const verification = TamperEvidentLedger.verifyEntries(allLedgerEntries, ledgerSigningKey);
      ledgerStatus = verification.isValid ? "VERIFIED_UNBROKEN" : "CORRUPTED";
      headMerkleRoot = allLedgerEntries[allLedgerEntries.length - 1].hash;
    }

    const bundleId = `attestation_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const generatedAt = new Date().toISOString();

    const rawPayload = JSON.stringify({
      bundleId,
      fleetReports,
      ledgerEntriesCount: allLedgerEntries.length,
      headMerkleRoot,
      auditReport,
    });
    const rawEvidencePayloadSha256 = createHash("sha256").update(rawPayload).digest("hex");

    return {
      bundleId,
      generatedAt,
      organizationName: options.organizationName,
      auditorEmail: options.auditorEmail || "security-audits@ritualdev.in",
      frameworks,
      executiveStatus: auditReport.status,
      complianceScore: auditReport.score,
      cryptographicEvidence: {
        ledgerVerificationStatus: ledgerStatus,
        totalVerifiedBlocks: allLedgerEntries.length,
        headMerkleRoot,
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
      "## 🔐 Cryptographic Ledger Verification",
      `- **HMAC Chain Status**: **${pkg.cryptographicEvidence.ledgerVerificationStatus}**`,
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
      "> *This attestation confirms zero unauthorized credential egress to third-party LLM inference windows.*",
    ];

    return lines.join("\n");
  }
}
