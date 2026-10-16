import type { DetectedSecret } from "./types.js";

export type ComplianceFramework = "soc2" | "pci_dss" | "hipaa" | "iso27001";
export type ControlStatus = "PASSED" | "FAILED" | "WARNING" | "NOT_ASSESSED";

export interface AssessedControl {
  framework: ComplianceFramework;
  controlId: string;
  name: string;
  description: string;
  status: "PASSED" | "FAILED" | "WARNING";
  violations: string[];
  assessedAspect: string;
}

export type ComplianceControl = AssessedControl;

export interface UnassessedControl {
  framework: ComplianceFramework;
  controlId: string;
  name: string;
  description: string;
  status: "NOT_ASSESSED";
  reason: string;
  requiredExternalEvidence: string[];
}

export interface AssessmentScopeDisclosure {
  scope: string;
  disclaimer: string;
  assessedAspects: string[];
  limitations: string[];
  requiredExternalEvidence: string[];
}

export interface SecretControlAssessmentReport {
  timestamp: string;
  assessmentTitle: string;
  /**
   * Scope-honest status:
   * - "NO_FINDINGS_IN_ASSESSED_CONTROLS": No credential leaks detected across assessed rules.
   * - "FINDINGS_DETECTED": In-flight or static secret exposures detected in assessed controls.
   */
  status: "NO_FINDINGS_IN_ASSESSED_CONTROLS" | "FINDINGS_DETECTED";
  /** Legacy alias for backwards compatibility */
  legacyStatus: "COMPLIANT" | "NON_COMPLIANT";
  /** Control satisfaction percentage for assessed controls only (0-100%) */
  score: number;
  frameworks: ComplianceFramework[];
  /** Technical controls directly evaluated against secret detection telemetry */
  assessedControls: AssessedControl[];
  /** Broader framework controls that cannot be assessed by secret scanning alone */
  unassessedControls: UnassessedControl[];
  /** Combined controls list for backwards compatibility */
  controls: (AssessedControl | UnassessedControl)[];
  summary: {
    totalPassed: number;
    totalFailed: number;
    totalViolations: number;
    totalAssessed: number;
    totalUnassessed: number;
  };
  assessedControlsSummary: {
    totalAssessedPassed: number;
    totalAssessedFailed: number;
    totalAssessedViolations: number;
  };
  scopeDisclosure: AssessmentScopeDisclosure;
}

export type ComplianceAuditReport = SecretControlAssessmentReport;

/**
 * Scope-Honest Secret-Control Assessment Engine:
 * Assesses technical secret detection and redaction controls against security frameworks.
 *
 * IMPORTANT SCOPE DISCLAIMER:
 * This engine only evaluates automated secret scanning and command interception.
 * It does NOT establish overall organizational compliance with SOC 2, HIPAA, PCI-DSS, or ISO 27001.
 * Broader organizational, administrative, and physical controls are explicitly marked NOT_ASSESSED.
 */
export class SecretControlAssessmentEngine {
  private defaultFrameworks: ComplianceFramework[];

  constructor(defaultFrameworks: ComplianceFramework[] = ["soc2", "pci_dss", "hipaa", "iso27001"]) {
    this.defaultFrameworks = defaultFrameworks;
  }

  public audit(
    findings: DetectedSecret[],
    blockedCommandsCount = 0,
  ): SecretControlAssessmentReport {
    return SecretControlAssessmentEngine.evaluate(
      findings,
      blockedCommandsCount,
      this.defaultFrameworks,
    );
  }

  /**
   * Evaluates detected secrets against specific secret-handling controls in standard frameworks
   */
  public static evaluate(
    findings: DetectedSecret[],
    blockedCommandsCount = 0,
    requestedFrameworks: ComplianceFramework[] = ["soc2", "pci_dss", "hipaa", "iso27001"],
  ): SecretControlAssessmentReport {
    const assessed: AssessedControl[] = [];
    const unassessed: UnassessedControl[] = [];

    // ==========================================
    // 1. SOC 2 Type II
    // ==========================================
    if (requestedFrameworks.includes("soc2")) {
      // CC6.1 - Logical Access Controls
      const cc61Violations: string[] = [];
      for (const f of findings) {
        if (f.category === "cloud" || f.category === "vcs" || f.severity === "critical") {
          cc61Violations.push(
            `Exposed authentication token: ${f.patternName} in ${f.file || "workspace stream"}`,
          );
        }
      }
      assessed.push({
        framework: "soc2",
        controlId: "CC6.1",
        name: "Logical Access Controls & Credential Integrity",
        description:
          "Restricts access to system credentials and prevents cleartext key exposure in code and streams.",
        status: cc61Violations.length === 0 ? "PASSED" : "FAILED",
        violations: cc61Violations,
        assessedAspect:
          "Static file scanning and streaming buffer redaction for cloud/VCS credentials.",
      });

      // CC6.6 - Boundary Protection & Egress Filtering
      const cc66Violations: string[] = [];
      if (findings.some((f) => f.severity === "critical")) {
        cc66Violations.push(
          "Critical credential found in outbound data flow or command arguments.",
        );
      }
      assessed.push({
        framework: "soc2",
        controlId: "CC6.6",
        name: "Boundary Protection & Unauthorized Egress Controls",
        description: "Prevents unauthorized transmission of credentials beyond system boundaries.",
        status: cc66Violations.length === 0 ? "PASSED" : "FAILED",
        violations: cc66Violations,
        assessedAspect:
          "Real-time stdio stream interception and pre-execution command firewalling.",
      });

      // Broader SOC 2 controls not assessed
      unassessed.push(
        {
          framework: "soc2",
          controlId: "CC1.1",
          name: "Integrity & Ethical Values (Governance)",
          description:
            "Tone at the top, human resources background checks, and organizational ethics.",
          status: "NOT_ASSESSED",
          reason: "Organizational governance cannot be evaluated by automated secret scanning.",
          requiredExternalEvidence: [
            "Formal employee code of conduct sign-offs",
            "HR background check verification records",
            "Board oversight meeting minutes",
          ],
        },
        {
          framework: "soc2",
          controlId: "CC5.2",
          name: "Risk Assessment & Vendor Management",
          description: "Identification and mitigation of third-party vendor and operational risks.",
          status: "NOT_ASSESSED",
          reason:
            "Requires third-party vendor risk assessments and annual organizational risk review.",
          requiredExternalEvidence: [
            "Annual vendor security assessments (SIG/CAIQ)",
            "Formal risk register and remediation tracking",
          ],
        },
        {
          framework: "soc2",
          controlId: "CC7.2",
          name: "Vulnerability & Patch Management",
          description:
            "Monitoring and remediating vulnerabilities across cloud infrastructure and OS hosts.",
          status: "NOT_ASSESSED",
          reason: "Host and OS patch levels require infrastructure scanner telemetry.",
          requiredExternalEvidence: [
            "Infrastructure vulnerability scan reports",
            "Patch deployment SLA compliance metrics",
          ],
        },
      );
    }

    // ==========================================
    // 2. PCI-DSS v4.0
    // ==========================================
    if (requestedFrameworks.includes("pci_dss")) {
      // Req 3.4 - Render Cardholder Authentication Tokens Unreadable
      const pciViolations: string[] = [];
      for (const f of findings) {
        if (f.category === "saas" || f.category === "crypto" || f.patternId.includes("stripe")) {
          pciViolations.push(
            `Payment gateway / cryptographic secret exposed in cleartext: ${f.patternName}`,
          );
        }
      }
      assessed.push({
        framework: "pci_dss",
        controlId: "Req-3.4",
        name: "Protection of Authentication & Payment Gateway Secrets",
        description:
          "Payment processor keys and cryptographic material must never appear in unencrypted stores or agent logs.",
        status: pciViolations.length === 0 ? "PASSED" : "FAILED",
        violations: pciViolations,
        assessedAspect:
          "Automated detection of Stripe, payment gateway tokens, and private key blocks.",
      });

      // Req 8.3 - Strong Authentication Credential Management
      const req83Violations: string[] = [];
      for (const f of findings) {
        if (f.category === "ai" || f.category === "cloud") {
          req83Violations.push(`API access key exposed in workspace: ${f.patternName}`);
        }
      }
      assessed.push({
        framework: "pci_dss",
        controlId: "Req-8.3",
        name: "Strong Authentication Credential Management",
        description:
          "Ensures developer tokens and system API keys are not stored or transferred insecurely.",
        status: req83Violations.length === 0 ? "PASSED" : "FAILED",
        violations: req83Violations,
        assessedAspect:
          "Scanning workspace files and outbound commands for hardcoded authentication keys.",
      });

      // Broader PCI-DSS controls not assessed
      unassessed.push(
        {
          framework: "pci_dss",
          controlId: "Req-9.1",
          name: "Physical Access Restrictions to Cardholder Data",
          description: "Restricts physical access to servers, workstations, and network equipment.",
          status: "NOT_ASSESSED",
          reason: "Physical data center and workstation controls require on-site inspection.",
          requiredExternalEvidence: [
            "Facility badge entry logs and CCTV surveillance records",
            "Visitor access registers and escort protocols",
          ],
        },
        {
          framework: "pci_dss",
          controlId: "Req-12.1",
          name: "Information Security Policy Governance",
          description: "Documented organizational security policy reviewed annually by leadership.",
          status: "NOT_ASSESSED",
          reason: "Policy governance requires formal organizational documentation.",
          requiredExternalEvidence: [
            "Executive-approved information security policy",
            "Annual security awareness training logs",
            "Formal QSA Report on Compliance (ROC) or Attestation of Compliance (AOC)",
          ],
        },
      );
    }

    // ==========================================
    // 3. HIPAA Security Rule (45 CFR § 164)
    // ==========================================
    if (requestedFrameworks.includes("hipaa")) {
      // § 164.312(a)(1) - Technical Access Controls
      const hipaaViolations: string[] = [];
      if (findings.length > 0) {
        hipaaViolations.push(
          `${findings.length} credential exposure(s) could permit unauthorized electronic access to protected systems.`,
        );
      }
      assessed.push({
        framework: "hipaa",
        controlId: "§164.312(a)(1)",
        name: "Technical Safeguards - Access Control & Authentication",
        description:
          "Restricts access to systems maintaining ePHI by preventing credential compromise.",
        status: hipaaViolations.length === 0 ? "PASSED" : "FAILED",
        violations: hipaaViolations,
        assessedAspect:
          "Detection and redaction of credentials granting entry into ePHI environments.",
      });

      // Broader HIPAA controls not assessed
      unassessed.push(
        {
          framework: "hipaa",
          controlId: "§164.308(a)(1)",
          name: "Administrative Safeguards - Security Management & Risk Analysis",
          description:
            "Formal risk analysis, sanction policies, and Business Associate Agreements (BAAs).",
          status: "NOT_ASSESSED",
          reason:
            "Legal agreements and administrative policies require organizational documentation.",
          requiredExternalEvidence: [
            "Signed Business Associate Agreements (BAAs) with all sub-processors and cloud vendors",
            "Comprehensive enterprise HIPAA security risk assessment",
            "Workforce training and breach notification policy",
          ],
        },
        {
          framework: "hipaa",
          controlId: "§164.310(a)(1)",
          name: "Physical Safeguards - Facility Access & Device Security",
          description: "Physical safeguards for workstations, laptops, and data storage media.",
          status: "NOT_ASSESSED",
          reason:
            "Hardware encryption policies and physical facility access require external verification.",
          requiredExternalEvidence: [
            "Full-disk encryption (BitLocker/FileVault) fleet compliance reports",
            "Secure media disposal and decommissioning logs",
          ],
        },
      );
    }

    // ==========================================
    // 4. ISO/IEC 27001:2022
    // ==========================================
    if (requestedFrameworks.includes("iso27001")) {
      // A.8.28 - Secure Coding & Secret Management
      const a828Violations: string[] = [];
      if (findings.length > 0) {
        a828Violations.push(
          "Source code or repository diff contains plaintext secrets in violation of secure engineering rules.",
        );
      }
      assessed.push({
        framework: "iso27001",
        controlId: "A.8.28",
        name: "Secure Coding & Secret Management",
        description:
          "Enforces elimination of hardcoded secrets from development repositories and agent workspaces.",
        status: a828Violations.length === 0 ? "PASSED" : "FAILED",
        violations: a828Violations,
        assessedAspect: "Static diff and workspace secret analysis against hardcoded secrets.",
      });

      // A.8.24 - Use of Cryptography & Key Management
      const a824Violations: string[] = [];
      for (const f of findings) {
        if (f.category === "crypto" || f.patternId.includes("private-key")) {
          a824Violations.push(`Cryptographic private key exposed in repository: ${f.patternName}`);
        }
      }
      assessed.push({
        framework: "iso27001",
        controlId: "A.8.24",
        name: "Use of Cryptography & Key Protection",
        description: "Ensures cryptographic keys are protected against unauthorized disclosure.",
        status: a824Violations.length === 0 ? "PASSED" : "FAILED",
        violations: a824Violations,
        assessedAspect: "Boundary-aware scanning for unencrypted private key blocks.",
      });

      // Broader ISO 27001 controls not assessed
      unassessed.push(
        {
          framework: "iso27001",
          controlId: "A.5.1",
          name: "Policies for Information Security (ISMS Governance)",
          description:
            "Management direction and support for information security in accordance with business requirements.",
          status: "NOT_ASSESSED",
          reason:
            "Information Security Management System (ISMS) policies require executive adoption.",
          requiredExternalEvidence: [
            "Management-approved Information Security Policy Manual",
            "Internal ISMS audit records and management review minutes",
          ],
        },
        {
          framework: "iso27001",
          controlId: "A.6.1",
          name: "Internal Organization & Screening",
          description: "Screening of candidate employees and ongoing security responsibilities.",
          status: "NOT_ASSESSED",
          reason: "Personnel screening and background verification require HR documentation.",
          requiredExternalEvidence: [
            "Documented pre-employment screening process and verification logs",
            "Signed confidentiality and intellectual property agreements",
            "Formal ISO/IEC 27001 certificate issued by an accredited certification body",
          ],
        },
      );
    }

    // Calculations across assessed controls
    const totalAssessedPassed = assessed.filter((c) => c.status === "PASSED").length;
    const totalAssessedFailed = assessed.filter((c) => c.status === "FAILED").length;
    const totalAssessedViolations = assessed.reduce((sum, c) => sum + c.violations.length, 0);
    const score =
      assessed.length > 0 ? Math.round((totalAssessedPassed / assessed.length) * 100) : 100;

    const status: "NO_FINDINGS_IN_ASSESSED_CONTROLS" | "FINDINGS_DETECTED" =
      totalAssessedFailed === 0 ? "NO_FINDINGS_IN_ASSESSED_CONTROLS" : "FINDINGS_DETECTED";

    const legacyStatus: "COMPLIANT" | "NON_COMPLIANT" =
      totalAssessedFailed === 0 ? "COMPLIANT" : "NON_COMPLIANT";

    const scopeDisclosure: AssessmentScopeDisclosure = {
      scope:
        "Technical secret detection, real-time streaming token redaction, and CLI command firewall.",
      disclaimer:
        "Notice: This report reflects only the results of automated secret detection across assessed technical controls ('NO_FINDINGS_IN_ASSESSED_CONTROLS'). It does NOT establish overall organizational SOC 2, HIPAA, PCI-DSS, or ISO 27001 compliance. Overall compliance requires an accredited third-party audit firm, administrative governance, physical safeguards, and operational policies.",
      assessedAspects: [
        "In-flight credential redaction in stdout/stderr streams",
        "Static scanning of source code, git diffs, and configuration files",
        "Pre-execution command sandbox firewall against credential theft",
      ],
      limitations: [
        "Does not evaluate network perimeter security, host firewalls, or cloud IAM role boundaries.",
        "Does not inspect database encryption-at-rest or hardware key management (HSM).",
        "Does not evaluate human resources, background screening, or physical facility security.",
        "Does not replace an independent CPA SOC 2 report, PCI QSA ROC/AOC, or ISO 27001 registrar audit.",
      ],
      requiredExternalEvidence: [
        "SOC 2 Type II: Independent examination report by an accredited CPA firm (AICPA SSAE 18).",
        "PCI-DSS v4.0: Qualified Security Assessor (QSA) Attestation of Compliance (AOC).",
        "HIPAA: Executed Business Associate Agreements (BAAs), risk analysis documentation, and physical security logs.",
        "ISO/IEC 27001: Certificate of Registration issued by an accredited certification body following Stage 1 & 2 audits.",
      ],
    };

    return {
      timestamp: new Date().toISOString(),
      assessmentTitle: "Secret-Control Assessment Report",
      status,
      legacyStatus,
      score,
      frameworks: requestedFrameworks,
      assessedControls: assessed,
      unassessedControls: unassessed,
      controls: [...assessed, ...unassessed],
      summary: {
        totalPassed: totalAssessedPassed,
        totalFailed: totalAssessedFailed,
        totalViolations: totalAssessedViolations,
        totalAssessed: assessed.length,
        totalUnassessed: unassessed.length,
      },
      assessedControlsSummary: {
        totalAssessedPassed,
        totalAssessedFailed,
        totalAssessedViolations,
      },
      scopeDisclosure,
    };
  }

  /**
   * Formats a scope-honest Markdown report explaining assessed vs unassessed controls,
   * explicit limitations, and external audit evidence needed for true compliance.
   */
  public static toAssessmentMarkdown(report: SecretControlAssessmentReport): string {
    const lines = [
      "# 📋 AgentShield Secret-Control Assessment Report",
      `**Assessment Title**: ${report.assessmentTitle}`,
      `**Generated Timestamp**: ${report.timestamp}`,
      `**Assessed Controls Result**: **${report.status}**`,
      `**Assessed Controls Pass Rate**: **${report.score}%** (${report.summary.totalPassed}/${report.summary.totalAssessed} controls passed)`,
      `**Evaluated Frameworks**: ${report.frameworks.map((f) => f.toUpperCase()).join(", ")}`,
      "",
      "> [!IMPORTANT]",
      "> **Assessment Scope & Compliance Disclaimer**:",
      `> ${report.scopeDisclosure.disclaimer}`,
      "",
      "---",
      "",
      "## 🛡️ Assessed Technical Controls",
      "",
      ...report.assessedControls.map((c) => {
        const icon = c.status === "PASSED" ? "✅" : "❌";
        const violationBlock =
          c.violations.length > 0
            ? c.violations.map((v) => `  - ⚠️ ${v}`).join("\n")
            : "  - *No credential findings detected.*";
        return `### ${icon} [${c.framework.toUpperCase()}] ${c.controlId}: ${c.name}
- **Status**: **${c.status}**
- **Description**: ${c.description}
- **Assessed Technical Aspect**: ${c.assessedAspect}
- **Findings / Violations**:
${violationBlock}
`;
      }),
      "---",
      "",
      "## ⏸️ Broader Regulatory Controls (Not Assessed by Secret Scanning)",
      "The following controls are mandated by the selected frameworks but require external, organizational, or physical evidence beyond automated secret detection:",
      "",
      ...report.unassessedControls.map((c) => {
        return `### ⏸️ [${c.framework.toUpperCase()}] ${c.controlId}: ${c.name}
- **Status**: **NOT ASSESSED**
- **Reason**: ${c.reason}
- **Required External Evidence**:
${c.requiredExternalEvidence.map((e) => `  - 📄 ${e}`).join("\n")}
`;
      }),
      "---",
      "",
      "## 📑 Scope, Limitations & Required External Audit Evidence",
      "",
      "### Assessed Scope",
      `- ${report.scopeDisclosure.scope}`,
      ...report.scopeDisclosure.assessedAspects.map((a) => `- ${a}`),
      "",
      "### Operational Limitations",
      ...report.scopeDisclosure.limitations.map((l) => `- ${l}`),
      "",
      "### Required Evidence for Organizational Compliance",
      ...report.scopeDisclosure.requiredExternalEvidence.map((e) => `- ${e}`),
    ];

    return lines.join("\n");
  }
}

// Backwards-compatible alias
export { SecretControlAssessmentEngine as ComplianceEngine };
