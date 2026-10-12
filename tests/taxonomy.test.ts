import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentConfigAuditor } from "../src/auditor.js";
import { STANDARD_SIGMA_RULES } from "../src/rules.js";
import { SarifFormatter } from "../src/sarif.js";
import type { DetectedSecret } from "../src/types.js";

describe("Phase 1: Rule Taxonomy & Static Configuration Hardening", () => {
  describe("Sigma-AI Rule Corpus", () => {
    it("should provide standardized rules with MITRE and OWASP LLM tags", () => {
      assert.ok(STANDARD_SIGMA_RULES.length >= 7);

      const openaiRule = STANDARD_SIGMA_RULES.find((r) => r.meta.id === "AS-SIGMA-001");
      assert.ok(openaiRule);
      assert.equal(openaiRule.meta.severity, "critical");
      assert.ok(openaiRule.meta.tags.owaspLlm?.includes("LLM06"));
      assert.ok(openaiRule.meta.tags.mitreAtlas?.includes("AML.T0024"));
    });

    it("should validate all rules have non-empty regex patterns", () => {
      for (const rule of STANDARD_SIGMA_RULES) {
        assert.ok(rule.detection.regex.length > 0);
        assert.ok(new RegExp(rule.detection.regex));
      }
    });
  });

  describe("Agent Configuration Auditor", () => {
    it("should audit workspace without crashing", () => {
      const auditor = new AgentConfigAuditor(process.cwd());
      const report = auditor.auditWorkspace();
      assert.ok(typeof report.passed === "boolean");
      assert.ok(Array.isArray(report.issues));
    });
  });

  describe("SARIF 2.1.0 Formatter", () => {
    it("should format secret findings and config issues into valid SARIF schema", () => {
      const mockSecret: DetectedSecret & { file: string } = {
        patternId: "AS-SIGMA-001",
        patternName: "OpenAI Secret Key",
        category: "ai",
        severity: "critical",
        raw: "mock-raw-secret",
        redacted: "[AGENT_SHIELD:OPENAI_API_KEY:mock]",
        line: 10,
        column: 5,
        file: "src/api.ts",
      };

      const sarif = SarifFormatter.generateSarif([mockSecret], []);
      assert.equal(sarif.version, "2.1.0");
      assert.equal(sarif.runs.length, 1);
      assert.equal(sarif.runs[0].tool.driver.name, "AgentShield");
      assert.equal(sarif.runs[0].results.length, 1);

      const res = sarif.runs[0].results[0];
      assert.equal(res.ruleId, "AS-SIGMA-001");
      assert.equal(res.level, "error");
      assert.equal(res.locations?.[0].physicalLocation.artifactLocation.uri, "src/api.ts");
    });
  });
});
