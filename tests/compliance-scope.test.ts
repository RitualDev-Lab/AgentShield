import assert from "node:assert";
import { describe, it } from "node:test";
import {
  ComplianceEngine,
  SecretControlAssessmentEngine,
  type ComplianceFramework,
  type DetectedSecret,
} from "../src/index.js";

describe("A3 Regression: Scope-Honest Secret-Control Assessment Engine", () => {
  describe("1. Scope-Honest Status & Disclaimer Evaluation", () => {
    it("reports 'NO_FINDINGS_IN_ASSESSED_CONTROLS' (not overall compliance) on clean scan", () => {
      const report = SecretControlAssessmentEngine.evaluate([]);

      assert.strictEqual(report.status, "NO_FINDINGS_IN_ASSESSED_CONTROLS");
      assert.strictEqual(report.legacyStatus, "COMPLIANT");
      assert.strictEqual(report.score, 100);
      assert.strictEqual(report.summary.totalViolations, 0);
      assert.strictEqual(report.summary.totalFailed, 0);

      // Verify scope disclosure
      assert.ok(report.scopeDisclosure);
      assert.ok(
        report.scopeDisclosure.disclaimer.includes(
          "does NOT establish overall organizational",
        ),
      );
      assert.ok(
        report.scopeDisclosure.disclaimer.includes(
          "NO_FINDINGS_IN_ASSESSED_CONTROLS",
        ),
      );
      assert.ok(report.scopeDisclosure.limitations.length >= 3);
      assert.ok(report.scopeDisclosure.requiredExternalEvidence.length >= 4);
    });

    it("marks broader non-secret controls as 'NOT_ASSESSED'", () => {
      const report = SecretControlAssessmentEngine.evaluate([], 0, [
        "soc2",
        "pci_dss",
        "hipaa",
        "iso27001",
      ]);

      assert.ok(report.unassessedControls.length >= 6);

      // Verify every unassessed control has status NOT_ASSESSED and required external evidence
      for (const ctrl of report.unassessedControls) {
        assert.strictEqual(ctrl.status, "NOT_ASSESSED");
        assert.ok(
          ctrl.reason.length > 0,
          `Control ${ctrl.controlId} must document unassessed reason`,
        );
        assert.ok(
          ctrl.requiredExternalEvidence.length > 0,
          `Control ${ctrl.controlId} must document required external evidence`,
        );
      }

      // Check specific standard controls
      const soc2Ethical = report.unassessedControls.find(
        (c) => c.controlId === "CC1.1",
      );
      assert.ok(soc2Ethical);
      assert.ok(
        soc2Ethical.requiredExternalEvidence.some((e) =>
          e.includes("code of conduct"),
        ),
      );

      const pciPhysical = report.unassessedControls.find(
        (c) => c.controlId === "Req-9.1",
      );
      assert.ok(pciPhysical);
      assert.ok(
        pciPhysical.requiredExternalEvidence.some((e) =>
          e.includes("badge entry"),
        ),
      );

      const hipaaBaa = report.unassessedControls.find(
        (c) => c.controlId === "§164.308(a)(1)",
      );
      assert.ok(hipaaBaa);
      assert.ok(
        hipaaBaa.requiredExternalEvidence.some((e) =>
          e.includes("Business Associate Agreements"),
        ),
      );

      const isoGovernance = report.unassessedControls.find(
        (c) => c.controlId === "A.5.1",
      );
      assert.ok(isoGovernance);
      assert.ok(
        isoGovernance.requiredExternalEvidence.some((e) =>
          e.includes("Information Security Policy"),
        ),
      );
    });
  });

  describe("2. Technical Control Violations on Leaked Findings", () => {
    it("reports 'FINDINGS_DETECTED' and decreases assessed control score on leaks", () => {
      const mockFindings: DetectedSecret[] = [
        {
          patternId: "mock-stripe",
          patternName: "Stripe Live Secret Key",
          category: "saas",
          severity: "critical",
          raw: "stripe-raw",
          redacted: "[REDACTED]",
          line: 1,
          column: 1,
        },
        {
          patternId: "mock-aws",
          patternName: "AWS Access Key",
          category: "cloud",
          severity: "critical",
          raw: "aws-raw",
          redacted: "[REDACTED]",
          line: 5,
          column: 1,
        },
      ];

      const report = SecretControlAssessmentEngine.evaluate(mockFindings);

      assert.strictEqual(report.status, "FINDINGS_DETECTED");
      assert.strictEqual(report.legacyStatus, "NON_COMPLIANT");
      assert.ok(report.score < 100);
      assert.ok(report.summary.totalFailed > 0);
      assert.ok(report.summary.totalViolations >= 2);

      // Verify PCI DSS Req-3.4 and SOC2 CC6.1 failed
      const pciReq34 = report.assessedControls.find(
        (c) => c.controlId === "Req-3.4",
      );
      assert.strictEqual(pciReq34?.status, "FAILED");
      assert.ok(pciReq34?.violations.length > 0);

      const soc2CC61 = report.assessedControls.find(
        (c) => c.controlId === "CC6.1",
      );
      assert.strictEqual(soc2CC61?.status, "FAILED");
      assert.ok(soc2CC61?.violations.length > 0);
    });
  });

  describe("3. Framework Selection Filtering & Markdown Formatting", () => {
    it("filters assessed and unassessed controls to only requested frameworks", () => {
      const frameworks: ComplianceFramework[] = ["soc2"];
      const report = SecretControlAssessmentEngine.evaluate(
        [],
        0,
        frameworks,
      );

      assert.deepStrictEqual(report.frameworks, ["soc2"]);
      assert.ok(report.assessedControls.every((c) => c.framework === "soc2"));
      assert.ok(report.unassessedControls.every((c) => c.framework === "soc2"));
    });

    it("generates scope-honest Markdown report with explicit disclaimers", () => {
      const report = SecretControlAssessmentEngine.evaluate([]);
      const md = SecretControlAssessmentEngine.toAssessmentMarkdown(report);

      assert.ok(md.includes("# 📋 AgentShield Secret-Control Assessment Report"));
      assert.ok(md.includes("NO_FINDINGS_IN_ASSESSED_CONTROLS"));
      assert.ok(md.includes("Assessment Scope & Compliance Disclaimer"));
      assert.ok(md.includes("## 🛡️ Assessed Technical Controls"));
      assert.ok(
        md.includes(
          "## ⏸️ Broader Regulatory Controls (Not Assessed by Secret Scanning)",
        ),
      );
      assert.ok(
        md.includes(
          "## 📑 Scope, Limitations & Required External Audit Evidence",
        ),
      );
    });

    it("maintains backwards-compatible ComplianceEngine alias and controls array", () => {
      const report = ComplianceEngine.evaluate([]);
      assert.ok(Array.isArray(report.controls));
      assert.strictEqual(
        report.controls.length,
        report.assessedControls.length + report.unassessedControls.length,
      );
      assert.strictEqual(typeof report.summary.totalPassed, "number");
      assert.strictEqual(typeof report.summary.totalFailed, "number");
    });
  });
});
