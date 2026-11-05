import { strict as assert } from "node:assert";
import { describe, it } from "node:test";
import { DistributedKeyBroker } from "../src/distributed-key-broker.js";
import { EbpfLsmController } from "../src/ebpf-lsm.js";
import { InstitutionalSiemStreamer } from "../src/siem-streamer.js";

describe("Phase 3 (AgentShield): In-Kernel eBPF LSM Monitoring & Enforcement", () => {
  it("initializes eBPF LSM controller and tracks in-kernel tracepoints", async () => {
    const lsm = new EbpfLsmController();
    const status = await lsm.loadModule({ forceSimulated: true });

    assert.equal(status.active, true);
    assert.ok(status.tracepoints.includes("sys_enter_execve"));
    assert.ok(status.tracepoints.includes("sys_enter_ptrace"));
    assert.ok(status.tracepoints.includes("sys_enter_connect"));
    assert.ok(status.blockedBinariesCount >= 5);
  });

  it("blocks dangerous execution vectors (sys_enter_execve) at in-kernel LSM layer", async () => {
    const lsm = new EbpfLsmController();
    await lsm.loadModule();

    let capturedEvent: unknown = null;
    lsm.onEvent((evt) => {
      capturedEvent = evt;
    });

    // Blocked binary
    const blockedRes = lsm.interceptExecve("/bin/nc", 12345);
    assert.equal(blockedRes.allowed, false);
    assert.ok(blockedRes.reason?.includes("eBPF-LSM"));
    assert.ok(capturedEvent);

    // Allowed binary
    const allowedRes = lsm.interceptExecve("/usr/bin/git", 12345);
    assert.equal(allowedRes.allowed, true);
  });

  it("unconditionally blocks ptrace memory inspection across agent boundaries", async () => {
    const lsm = new EbpfLsmController();
    await lsm.loadModule();

    const ptraceRes = lsm.interceptPtrace(9999, 12345);
    assert.equal(ptraceRes.allowed, false);
    assert.ok(ptraceRes.reason?.includes("ptrace"));
  });

  it("blocks outbound Cloud Instance Metadata Service (IMDS) connects", async () => {
    const lsm = new EbpfLsmController();
    await lsm.loadModule();

    const imdsRes = lsm.interceptConnect("169.254.169.254", 80);
    assert.equal(imdsRes.allowed, false);
    assert.ok(imdsRes.reason?.includes("Cloud Instance Metadata Service"));

    const normalRes = lsm.interceptConnect("10.0.1.5", 5432);
    assert.equal(normalRes.allowed, true);
  });
});

describe("Phase 3 (AgentShield): Distributed Cryptographic Key Broker", () => {
  it("synchronizes deterministic surrogates across distributed container builders", async () => {
    const clusterSecret = "test_cluster_secret_xyz123";
    const brokerPodA = new DistributedKeyBroker({ backend: "local_airgapped", clusterSecret });
    const brokerPodB = new DistributedKeyBroker({ backend: "local_airgapped", clusterSecret });

    const key = "mock_aws_key_id_deterministic_123";
    const surrogateA = await brokerPodA.getOrGenerateSurrogate(key, "aws");
    const surrogateB = await brokerPodB.getOrGenerateSurrogate(key, "aws");

    assert.equal(surrogateA.surrogateValue, surrogateB.surrogateValue);
    assert.ok(surrogateA.surrogateValue.startsWith("AKIA_CANARY_"));
    assert.equal(surrogateA.provider, "aws");
  });

  it("handles different credential providers with standard prefixes", async () => {
    const broker = new DistributedKeyBroker();

    const gh = await broker.getOrGenerateSurrogate("ghp_realtoken123456", "github");
    assert.ok(gh.surrogateValue.startsWith("ghp_canary_"));

    const oai = await broker.getOrGenerateSurrogate("sk-proj-realkey123456", "openai");
    assert.ok(oai.surrogateValue.startsWith("sk-canary-"));
  });
});

describe("Phase 3 (AgentShield): Institutional SIEM Integration", () => {
  it("enqueues and flushes events to SIEM destination in Common Event Format (CEF)", async () => {
    const streamer = new InstitutionalSiemStreamer({
      destination: "stdout_mock",
      batchSize: 10,
    });

    streamer.enqueueEvent({
      id: "evt_1",
      timestamp: new Date().toISOString(),
      eventType: "COMMAND_BLOCKED",
      severity: "high",
      source: "AgentShield-LSM",
      actor: "devin-bot",
      details: {
        command: "nc -lvp 4444",
        ruleId: "EBPF_EXECVE_BLOCKED",
      },
    });

    assert.equal(streamer.getQueueLength(), 1);
    const report = await streamer.flush();

    assert.equal(report.eventsSent, 1);
    assert.equal(report.status, "buffered_offline");
    assert.equal(streamer.getQueueLength(), 0);
  });

  it("immediately flushes critical severity events without waiting for interval", async () => {
    const streamer = new InstitutionalSiemStreamer({
      destination: "stdout_mock",
      batchSize: 50,
    });

    streamer.enqueueEvent({
      id: "evt_crit_1",
      timestamp: new Date().toISOString(),
      eventType: "SECRET_LEAK_DETECTED",
      severity: "critical",
      source: "AgentShield-LSM",
      actor: "claude-code",
      details: {
        ruleId: "AWS_SECRET_KEY",
        redactedValue: "AKIA_CANARY_REDACTED",
      },
    });

    // Should have been immediately flushed because severity is critical
    assert.equal(streamer.getQueueLength(), 0);
    assert.equal(streamer.getStats().delivered, 1);
  });
});
