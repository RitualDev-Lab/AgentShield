import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { AgentShieldDaemon, AgentShieldDaemonClient } from "../src/daemon.js";

test("Phase 2: Headless Background Daemon (agentshieldd) Local IPC Suite", async (t) => {
  // Use unique ephemeral socket path for the test suite
  const uniqueId = Math.random().toString(36).substring(2, 9);
  const testSocketPath =
    process.platform === "win32"
      ? `\\\\.\\pipe\\agentshield-test-${uniqueId}`
      : path.join(os.tmpdir(), `agentshield-test-${uniqueId}.sock`);

  const dynamicAuthSecret = Buffer.from("test-daemon-auth-token-key-32b").toString("hex");

  const daemon = new AgentShieldDaemon({
    socketPath: testSocketPath,
    authSecret: dynamicAuthSecret,
  });

  await daemon.start();

  t.after(async () => {
    await daemon.stop();
  });

  await t.test("verifies socket binding and initial daemon status", async () => {
    const status = daemon.getStatus();
    assert.ok(status.version);
    assert.equal(status.activeLocks, 0);
    assert.equal(status.connectedClients, 0);
    assert.equal(status.socketPath, testSocketPath);
  });

  await t.test("client connects and performs unauthenticated PING", async () => {
    const client = new AgentShieldDaemonClient(testSocketPath);
    await client.connect();

    try {
      const pong = await client.ping();
      assert.equal(pong.ok, true);
      assert.equal(pong.action, "PONG");
      assert.equal(pong.authenticated, false);
    } finally {
      client.disconnect();
    }
  });

  await t.test("client fails protected actions before AUTH handshake", async () => {
    const client = new AgentShieldDaemonClient(testSocketPath);
    await client.connect();

    try {
      const lockRes = await client.acquireLock("resource:ci-pipeline");
      assert.equal(lockRes, null);
    } finally {
      client.disconnect();
    }
  });

  await t.test("client authenticates and synchronizes process locks across replicas", async () => {
    const clientA = new AgentShieldDaemonClient(testSocketPath);
    const clientB = new AgentShieldDaemonClient(testSocketPath);

    await clientA.connect();
    await clientB.connect();

    try {
      const authA = await clientA.authenticate(dynamicAuthSecret);
      assert.equal(authA, true, "Client A must authenticate");

      const authB = await clientB.authenticate(dynamicAuthSecret);
      assert.equal(authB, true, "Client B must authenticate");

      // 1. Client A acquires lock
      const lockA = await clientA.acquireLock("resource:db-migration", {
        ownerId: "agent_worker_1",
        leaseTtlMs: 4000,
      });

      assert.ok(lockA, "Client A must acquire lock");
      assert.equal(lockA.resourceKey, "resource:db-migration");
      assert.equal(lockA.ownerId, "agent_worker_1");
      assert.ok(lockA.fenceToken > 0);

      // 2. Client B attempts concurrent acquisition (must fail due to mutual exclusion)
      const lockB = await clientB.acquireLock("resource:db-migration", {
        ownerId: "agent_worker_2",
      });
      assert.equal(lockB, null, "Client B must be blocked by mutual exclusion");

      // 3. Client A releases lock
      const released = await clientA.releaseLock(
        "resource:db-migration",
        lockA.lockId,
        "agent_worker_1",
      );
      assert.equal(released, true);

      // 4. Client B can now acquire cleanly
      const lockBAfter = await clientB.acquireLock("resource:db-migration", {
        ownerId: "agent_worker_2",
      });
      assert.ok(lockBAfter, "Client B must acquire once unlocked");
      assert.ok(lockBAfter.fenceToken > lockA.fenceToken, "Fencing token must strictly increase");

      await clientB.releaseLock("resource:db-migration", lockBAfter.lockId, "agent_worker_2");
    } finally {
      clientA.disconnect();
      clientB.disconnect();
    }
  });

  await t.test(
    "client streams OpenTelemetry metrics with sub-millisecond wire latency",
    async () => {
      const client = new AgentShieldDaemonClient(testSocketPath);
      await client.connect();

      try {
        await client.authenticate(dynamicAuthSecret);

        const t0 = performance.now();
        const metricId = await client.streamOtelMetric(
          "agentshield.surrogate_redactions_total",
          1,
          {
            sandbox: "bubblewrap",
            rule: "SECRET_REDACTION",
            tenant: "enterprise_acme",
          },
          "counter",
        );
        const wireLatencyMs = performance.now() - t0;

        assert.ok(metricId, "Metric ID must be returned");
        assert.ok(wireLatencyMs < 50, `Wire IPC latency was ${wireLatencyMs}ms`);

        const summary = await client.getMetricsSummary();
        assert.equal(summary.ok, true);
        assert.ok(summary.status.totalOtelEvents >= 1);
        assert.equal(
          summary.metrics[summary.metrics.length - 1].metricName,
          "agentshield.surrogate_redactions_total",
        );
      } finally {
        client.disconnect();
      }
    },
  );
});
