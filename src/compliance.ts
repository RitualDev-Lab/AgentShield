import type { DetectedSecret } from "./types.js";

export type ComplianceFramework = "soc2" | "pci_dss" | "hipaa" | "iso27001";

export interface ComplianceControl {
  framework: ComplianceFramework;
  controlId: string;
  name: string;
  description: string;
  status: "PASSED" | "FAILED" | "WARNING";
  violations: string[];
}

export interface ComplianceAuditReport {
  timestamp: string;
  status: "COMPLIANT" | "NON_COMPLIANT";
  score: number; // 0-100%
  frameworks: ComplianceFramework[];
  controls: ComplianceControl[];
  summary: {
    totalPassed: number;
    totalFailed: number;
    totalViolations: number;
  };
}

export class ComplianceEngine {
  private defaultFrameworks: ComplianceFramework[];

  constructor(defaultFrameworks: ComplianceFramework[] = ["soc2", "pci_dss", "hipaa", "iso27001"]) {
    this.defaultFrameworks = defaultFrameworks;
  }

  public audit(findings: DetectedSecret[], blockedCommandsCount = 0): ComplianceAuditReport {
    return ComplianceEngine.evaluate(findings, blockedCommandsCount, this.defaultFrameworks);
  }

  /**
   * Evaluates detected secrets and agent actions against enterprise compliance standards:
   * - SOC 2 Type II: CC6.1, CC6.6 (Logical Access Controls & Boundary Protection)
   * - PCI-DSS v4.0: Requirement 3 & 8 (Protect Stored Account Data & Authenticate Access)
   * - HIPAA Security Rule: 45 CFR § 164.312 (Technical Safeguards)
   * - ISO/IEC 27001:2022: Control A.8.24 (Use of Cryptography) & A.8.28 (Secure Coding)
   */
  public static evaluate(
    findings: DetectedSecret[],
    blockedCommandsCount = 0,
    requestedFrameworks: ComplianceFramework[] = ["soc2", "pci_dss", "hipaa", "iso27001"],
  ): ComplianceAuditReport {
    const controls: ComplianceControl[] = [];

    // SOC 2 CC6.1 - Logical Access Controls
    const soc2Violations: string[] = [];
    for (const f of findings) {
      if (f.category === "cloud" || f.category === "vcs" || f.severity === "critical") {
        soc2Violations.push(
          `Unmasked credential found: ${f.patternName} in ${f.file || "workspace stream"}`,
        );
      }
    }
    controls.push({
      framework: "soc2",
      controlId: "CC6.1",
      name: "Logical Access Controls & Credential Integrity",
      description: "Restricts access to credentials and prevents credential exposure.",
      status: soc2Violations.length === 0 ? "PASSED" : "FAILED",
      violations: soc2Violations,
    });

    // PCI-DSS Req 3.4 - Render Primary Account Data and Secrets Unreadable
    const pciViolations: string[] = [];
    for (const f of findings) {
      if (f.category === "saas" || f.category === "crypto" || f.patternId.includes("stripe")) {
        pciViolations.push(`Payment / cryptographic token exposed in cleartext: ${f.patternName}`);
      }
    }
    controls.push({
      framework: "pci_dss",
      controlId: "Req-3.4",
      name: "Protection of Authentication & Cardholder Tokens",
      description:
        "Cryptographic keys and payment credentials must never appear in unencrypted stores or agent logs.",
      status: pciViolations.length === 0 ? "PASSED" : "FAILED",
      violations: pciViolations,
    });

    // HIPAA § 164.312(a)(1) - Technical Access Controls
    const hipaaViolations: string[] = [];
    if (findings.length > 0) {
      hipaaViolations.push(
        `${findings.length} exposed token(s) can allow unauthorized entry into protected systems.`,
      );
    }
    controls.push({
      framework: "hipaa",
      controlId: "§164.312(a)(1)",
      name: "Technical Safeguards - Access Control & Authentication",
      description:
        "Ensure electronic protected health information is not exposed via compromised environment credentials.",
      status: hipaaViolations.length === 0 ? "PASSED" : "FAILED",
      violations: hipaaViolations,
    });

    // ISO/IEC 27001 A.8.28 - Secure Coding & Agent Sandbox
    const isoViolations: string[] = [];
    if (findings.length > 0) {
      isoViolations.push(
        "Code/diff contains hardcoded secret tokens in violation of secure engineering rules.",
      );
    }
    controls.push({
      framework: "iso27001",
      controlId: "A.8.28",
      name: "Secure Coding & Secret Management",
      description: "Enforces zero hardcoded credentials and active agent boundary protection.",
      status: isoViolations.length === 0 ? "PASSED" : "FAILED",
      violations: isoViolations,
    });

    // Filter controls for requested frameworks
    const activeControls = controls.filter((c) => requestedFrameworks.includes(c.framework));

    const totalPassed = activeControls.filter((c) => c.status === "PASSED").length;
    const totalFailed = activeControls.filter((c) => c.status === "FAILED").length;
    const totalViolations = activeControls.reduce((sum, c) => sum + c.violations.length, 0);

    const score =
      activeControls.length > 0 ? Math.round((totalPassed / activeControls.length) * 100) : 100;

    return {
      timestamp: new Date().toISOString(),
      status: totalFailed === 0 ? "COMPLIANT" : "NON_COMPLIANT",
      score,
      frameworks: requestedFrameworks,
      controls: activeControls,
      summary: {
        totalPassed,
        totalFailed,
        totalViolations,
      },
    };
  }
}
