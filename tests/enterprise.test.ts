import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ComplianceEngine } from "../src/compliance.js";
import { SiemExporter } from "../src/siem.js";
import type { DetectedSecret } from "../src/types.js";
import { VaultInjector } from "../src/vault.js";

describe("Phase 4: Enterprise Control Plane", () => {
  describe("SIEM Exporter (CEF / JSON / Syslog)", () => {
    const mockFinding: DetectedSecret = {
      patternId: "openai-api-key",
      patternName: "OpenAI Secret Key",
      category: "ai",
      severity: "critical",
      raw: "mock-raw-secret",
      redacted: "[AGENT_SHIELD:OPENAI_API_KEY:mock]",
      line: 12,
      column: 4,
      file: "agent-session.log",
    };

    it("should format secret finding into Common Event Format (CEF)", () => {
      const event = SiemExporter.createSecretLeakEvent(mockFinding, {
        actor: "claude-code-agent",
        source: "agent-daemon",
      });

      const cef = SiemExporter.toCef(event);
      assert.ok(cef.startsWith("CEF:0|RitualDev|AgentShield|1.0.0|SECRET_LEAK_DETECTED|"));
      assert.ok(cef.includes("suser=claude-code-agent"));
      assert.ok(cef.includes("fname=agent-session.log"));
    });

    it("should format command block event into Syslog format", () => {
      const event = SiemExporter.createCommandBlockedEvent("cat .env", "Blocked read of .env", {
        actor: "windsurf-agent",
      });

      const syslog = SiemExporter.toSyslog(event);
      assert.ok(syslog.includes("<134>1"));
      assert.ok(syslog.includes("windsurf-agent"));
      assert.ok(syslog.includes("COMMAND_BLOCKED"));
    });
  });

  describe("Compliance Engine (SOC2, PCI-DSS, HIPAA, ISO27001)", () => {
    it("should return COMPLIANT when 0 secrets are detected", () => {
      const report = ComplianceEngine.evaluate([]);
      assert.equal(report.status, "COMPLIANT");
      assert.equal(report.score, 100);
      assert.equal(report.summary.totalViolations, 0);
    });

    it("should flag SOC2 and PCI-DSS violations on leaked credentials", () => {
      const finding: DetectedSecret = {
        patternId: "stripe-live-key",
        patternName: "Stripe Live Secret Key",
        category: "saas",
        severity: "critical",
        raw: "mock-stripe",
        redacted: "[AGENT_SHIELD:STRIPE:mock]",
        line: 1,
        column: 1,
        file: "checkout.ts",
      };

      const report = ComplianceEngine.evaluate([finding]);
      assert.equal(report.status, "NON_COMPLIANT");
      assert.ok(report.score < 100);
      assert.ok(report.summary.totalViolations > 0);

      const pciControl = report.controls.find((c) => c.framework === "pci_dss");
      assert.equal(pciControl?.status, "FAILED");
    });
  });

  describe("Zero-Trust Vault Injector", () => {
    it("should replace plaintext secrets with surrogate tokens", () => {
      const vault = new VaultInjector({
        OPENAI_API_KEY: "mock-openai-secret-token",
        DATABASE_URL: "postgres://admin:pass@db:5432/main",
      });

      const { safeEnv, mapping } = vault.injectSafeEnvironment(["OPENAI_API_KEY", "DATABASE_URL"]);

      // Agent sees only surrogate tokens, never cleartext
      assert.ok(safeEnv.OPENAI_API_KEY.startsWith("[VAULT_INJECTED:OPENAI_API_KEY:"));
      assert.ok(safeEnv.DATABASE_URL.startsWith("[VAULT_INJECTED:DATABASE_URL:"));

      // Mapping resolves surrogate back at execution proxy boundary
      const resolved = vault.resolveSurrogate(safeEnv.OPENAI_API_KEY, mapping);
      assert.equal(resolved, "mock-openai-secret-token");
    });
  });
});
