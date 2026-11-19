import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { LINUX_CLONE3_FLAGS, ZygoteProcessPool } from "../src/zygote-pool.js";
import { EbpfLsmController, type EbpfLsmEvent } from "../src/ebpf-lsm.js";

describe("Phase 2: AgentShield Runtime Kernel Hardening & Zygote Process Pool", () => {
  it("initializes Zygote pool with pre-warmed workers and valid clone3 container flags", () => {
    const pool = new ZygoteProcessPool({
      minIdle: 4,
      maxCapacity: 8,
      recycleAfterInvocations: 10,
    });

    const workers = pool.getWorkers();
    assert.strictEqual(workers.length, 4, "Must pre-warm minIdle workers");
    for (const w of workers) {
      assert.strictEqual(w.state, "idle");
      assert.ok(w.pid > 0);
      assert.strictEqual(
        w.cloneFlags,
        LINUX_CLONE3_FLAGS.CLONE_NEWPID |
          LINUX_CLONE3_FLAGS.CLONE_NEWNET |
          LINUX_CLONE3_FLAGS.CLONE_NEWNS,
      );
    }

    pool.shutdown();
  });

  it("achieves sub-0.50ms (<500 microseconds) P99 execution overhead via persistent worker reuse", async () => {
    const pool = new ZygoteProcessPool({ minIdle: 4, maxCapacity: 8 });

    // Warm-up run to allow V8 JIT optimization
    for (let i = 0; i < 50; i++) {
      await pool.dispatch({ action: "inspect", command: "ls -la" });
    }
    pool.resetTelemetry();

    // Benchmark 200 consecutive invocations
    for (let i = 0; i < 200; i++) {
      const res = await pool.dispatch({ action: "inspect", command: "ls -la" });
      assert.strictEqual(res.success, true);
    }

    const telemetry = pool.getTelemetry();
    assert.ok(telemetry.totalDispatched >= 200);
    // P99 latency must be under 500 microseconds (< 0.50ms)
    const maxP99 = 500;
    assert.ok(
      telemetry.p99Micros < maxP99,
      `P99 latency must be <${maxP99}μs. Actual P99: ${telemetry.p99Micros}μs`,
    );
    assert.strictEqual(telemetry.p99TargetMet, true);

    pool.shutdown();
  });

  it("recycles contaminated workers after reaching invocation threshold and replenishes idle pool", async () => {
    const pool = new ZygoteProcessPool({
      minIdle: 2,
      maxCapacity: 4,
      recycleAfterInvocations: 5,
    });

    // Run 12 invocations to trigger worker recycling
    for (let i = 0; i < 12; i++) {
      await pool.dispatch({ action: "ping" });
    }

    const telemetry = pool.getTelemetry();
    assert.ok(telemetry.recycledCount >= 2, "Must have recycled aged workers");
    assert.ok(telemetry.idleWorkers >= 2, "Must automatically replenish idle workers to minIdle");

    pool.shutdown();
  });

  it("integrates with Linux eBPF CO-RE controller and registers worker PIDs", async () => {
    const ebpf = new EbpfLsmController();
    await ebpf.loadModule({ forceSimulated: true });

    ebpf.registerMonitoredPid(12345);
    assert.strictEqual(ebpf.isPidMonitored(12345), true);
    assert.strictEqual(ebpf.isPidMonitored(99999), false);

    const status = ebpf.getStatus();
    assert.strictEqual(status.active, true);
    assert.ok(status.tracepoints.includes("sys_enter_openat"));
    assert.strictEqual(status.monitoredPidsCount, 1);
    assert.ok(status.overheadNs < 100, "In-kernel eBPF CO-RE overhead must be <100ns");

    ebpf.unregisterMonitoredPid(12345);
    assert.strictEqual(ebpf.isPidMonitored(12345), false);
  });

  it("intercepts sys_enter_openat for sensitive credential stores via eBPF probe", () => {
    const ebpf = new EbpfLsmController();
    const events: EbpfLsmEvent[] = [];
    ebpf.onEvent((ev) => events.push(ev));

    // Blocked access to .env
    const envRes = ebpf.interceptOpenat("/workspace/app/.env");
    assert.strictEqual(envRes.allowed, false);
    assert.ok(envRes.reason?.includes("unauthorized access to sensitive credential store"));

    // Blocked access to id_rsa
    const rsaRes = ebpf.interceptOpenat("/home/agent/.ssh/id_rsa");
    assert.strictEqual(rsaRes.allowed, false);

    // Allowed access to regular code
    const srcRes = ebpf.interceptOpenat("/workspace/src/index.ts");
    assert.strictEqual(srcRes.allowed, true);

    assert.strictEqual(events.length, 3);
    assert.strictEqual(events[0].actionTaken, "KERNEL_EPERM_BLOCKED");
    assert.strictEqual(events[2].actionTaken, "AUDIT_LOGGED");
  });
});
