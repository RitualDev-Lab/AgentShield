import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ComplianceEngine } from "../src/compliance.js";
import { EnterpriseControlPlane, type FleetAgentTelemetryReport } from "../src/control-plane.js";

describe("Phase 5: Enterprise Distribution, IDE Marketplace & Control Plane", () => {
  const controlPlane = new EnterpriseControlPlane({
    policyVersion: "2026.2.0-LTS",
    enforceKernelSandbox: true,
  });

  it("should initialize default fleet policies", () => {
    const policy = controlPlane.getActivePolicy();
    assert.equal(policy.policyVersion, "2026.2.0-LTS");
    assert.equal(policy.enforceKernelSandbox, true);
    assert.ok(policy.allowedEgressDomains.some((d) => d === "github.com"));
  });

  it("should synchronize node telemetry and trigger alerts for blocked or quarantined agents", () => {
    const report: FleetAgentTelemetryReport = {
      agentId: "agent-dev-node-042",
      agentRuntime: "claude-code",
      hostname: "engineer-workstation-linux",
      timestamp: new Date().toISOString(),
      totalCommandsExecuted: 12,
      totalCommandsBlocked: 2,
      totalSecretsRedacted: 5,
      complianceScore: 100,
      quarantined: false,
      ledgerEntries: [],
    };

    const sync = controlPlane.syncTelemetry(report);
    assert.equal(sync.synchronized, true);
    assert.equal(sync.remoteAlertsDispatched, 1);
  });

  it("should generate executive compliance attestation bundle", () => {
    const compliance = ComplianceEngine.evaluate([]);
    const reports: FleetAgentTelemetryReport[] = [
      {
        agentId: "node-1",
        agentRuntime: "cursor",
        hostname: "dev1",
        timestamp: new Date().toISOString(),
        totalCommandsExecuted: 40,
        totalCommandsBlocked: 1,
        totalSecretsRedacted: 2,
        complianceScore: 100,
        quarantined: false,
        ledgerEntries: [],
      },
    ];

    const attestation = controlPlane.generateExecutiveAttestation(reports, compliance);
    assert.ok(attestation.includes("Executive Compliance Attestation"));
    assert.ok(attestation.includes("Active Developer Nodes"));
    assert.ok(attestation.includes("Total Unauthorized Commands Blocked"));
    assert.ok(attestation.includes("HMAC Write-Ahead Ledger"));
  });
});
