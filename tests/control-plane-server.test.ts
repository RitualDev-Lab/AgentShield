import assert from "node:assert";
import { describe, it, before, after } from "node:test";
import { ControlPlaneServer } from "../src/control-plane-server.js";
import { fetchRemotePolicy, type RemotePolicyPayload } from "../src/remote-policy.js";

describe("Phase 2: SaaS Control Plane Server MVP Suite", () => {
  let server: ControlPlaneServer;
  let port: number;

  before(async () => {
    server = new ControlPlaneServer({
      port: 0, // Random available port
      initialPolicy: {
        policyVersion: "2026.4.1",
        orgId: "org_test_saas_cluster",
        name: "Test SaaS Organization",
        allowlist: ["safe-token-org-1"],
        customPatterns: [
          {
            id: "saas-test-rule",
            name: "SaaS Test Rule",
            regex: "\\bSAAS_[A-Z0-9]{12}\\b",
          },
        ],
        updatedAt: new Date().toISOString(),
      },
    });
    port = await server.start();
  });

  after(async () => {
    await server.stop();
  });

  it("should answer health check on /api/v1/health", async () => {
    const res = await fetch(`http://localhost:${port}/api/v1/health`);
    assert.strictEqual(res.status, 200);
    const data = (await res.json()) as { status: string; service: string };
    assert.strictEqual(data.status, "healthy");
    assert.strictEqual(data.service, "agentshield-control-plane");
  });

  it("should serve provisioned organization policies via GET /api/v1/policies/:orgId", async () => {
    const res = await fetch(`http://localhost:${port}/api/v1/policies/org_test_saas_cluster`);
    assert.strictEqual(res.status, 200);
    const policy = (await res.json()) as RemotePolicyPayload;
    assert.strictEqual(policy.orgId, "org_test_saas_cluster");
    assert.strictEqual(policy.policyVersion, "2026.4.1");
    assert.strictEqual(policy.customPatterns?.[0].id, "saas-test-rule");
  });

  it("should allow updating policies dynamically via PUT /api/v1/policies/:orgId", async () => {
    const updatedPolicy: RemotePolicyPayload = {
      policyVersion: "2026.5.0-hotfix",
      orgId: "org_test_saas_cluster",
      name: "Updated Security Policy",
      allowlist: ["new-safe-token"],
      entropyThreshold: 4.8,
      maskStyle: "asterisk",
      customPatterns: [
        {
          id: "hotfix-zero-day",
          name: "Hotfix Zero Day Rule",
          regex: "\\bHOTFIX_[A-Z0-9]{16}\\b",
        },
      ],
      updatedAt: new Date().toISOString(),
    };

    const putRes = await fetch(`http://localhost:${port}/api/v1/policies/org_test_saas_cluster`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(updatedPolicy),
    });
    assert.strictEqual(putRes.status, 200);

    // Verify GET reflects update immediately
    const getRes = await fetch(`http://localhost:${port}/api/v1/policies/org_test_saas_cluster`);
    const policy = (await getRes.json()) as RemotePolicyPayload;
    assert.strictEqual(policy.policyVersion, "2026.5.0-hotfix");
    assert.strictEqual(policy.maskStyle, "asterisk");
    assert.strictEqual(policy.customPatterns?.[0].id, "hotfix-zero-day");
  });

  it("should receive fleet heartbeat pings via POST /api/v1/telemetry/heartbeat", async () => {
    const heartbeatPayload = {
      agentId: "agent-node-042",
      agentRuntime: "claude-code",
      hostname: "dev-macbook-pro.local",
      timestamp: new Date().toISOString(),
      totalCommandsExecuted: 15,
      totalCommandsBlocked: 2,
      totalSecretsRedacted: 5,
      complianceScore: 98,
      quarantined: false,
      ledgerEntries: [],
    };

    const res = await fetch(`http://localhost:${port}/api/v1/telemetry/heartbeat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(heartbeatPayload),
    });
    assert.strictEqual(res.status, 200);
    const data = (await res.json()) as { success: boolean; registeredNodes: number };
    assert.strictEqual(data.success, true);
    assert.strictEqual(data.registeredNodes, 1);
  });

  it("should receive incident telemetry and surface in /api/v1/incidents", async () => {
    const incidentPayload = {
      orgId: "org_test_saas_cluster",
      agentId: "agent-node-042",
      agentRuntime: "cursor",
      hostname: "dev-workstation.lan",
      command: "cat .env",
      ruleCategory: "env_read",
      reason: "Blocked attempt to read raw .env into inference context",
      severity: "critical",
    };

    const postRes = await fetch(`http://localhost:${port}/api/v1/telemetry/incident`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(incidentPayload),
    });
    assert.strictEqual(postRes.status, 200);

    const getRes = await fetch(`http://localhost:${port}/api/v1/incidents`);
    const data = (await getRes.json()) as {
      incidents: Array<{ command: string; severity: string }>;
    };
    assert.strictEqual(data.incidents.length > 0, true);
    assert.strictEqual(data.incidents[0].command, "cat .env");
    assert.strictEqual(data.incidents[0].severity, "critical");
  });

  it("should return fleet overview statistics via GET /api/v1/overview", async () => {
    const res = await fetch(`http://localhost:${port}/api/v1/overview`);
    assert.strictEqual(res.status, 200);
    const overview = (await res.json()) as {
      activeNodes: number;
      totalBlocked: number;
      totalRedacted: number;
      recentIncidentsCount: number;
    };

    assert.strictEqual(overview.activeNodes, 1);
    assert.strictEqual(overview.totalBlocked, 2);
    assert.strictEqual(overview.totalRedacted, 5);
    assert.strictEqual(overview.recentIncidentsCount, 1);
  });

  it("should integrate seamlessly with client fetchRemotePolicy helper", async () => {
    const creds = {
      orgId: "org_test_saas_cluster",
      token: "mock-bearer-token",
      endpoint: `http://localhost:${port}`,
    };

    const result = await fetchRemotePolicy(creds, { timeoutMs: 2000, offlineFallback: false });
    assert.strictEqual(result.policy?.orgId, "org_test_saas_cluster");
    assert.strictEqual(result.policy?.policyVersion, "2026.5.0-hotfix");
    assert.strictEqual(result.isCached, false);
  });
});
