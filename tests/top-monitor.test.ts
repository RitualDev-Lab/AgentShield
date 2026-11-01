import assert from "node:assert";
import { describe, it } from "node:test";
import {
  clearBlockedCallEvents,
  discoverAgentProcesses,
  formatTopMonitorView,
  getRecordedBlockedEvents,
  getTopMonitorSnapshot,
  recordBlockedCallEvent,
} from "../src/top-monitor.js";

describe("AgentShield Top Live Terminal Monitor Suite", () => {
  it("discovers local agent runtime processes with memory and CPU telemetry", () => {
    const procs = discoverAgentProcesses(512);
    assert.ok(procs.length >= 1);
    const selfProc = procs.find((p) => p.pid === process.pid);
    assert.ok(selfProc, "Self runtime process should be included");
    assert.strictEqual(selfProc.status, "CONFINED");
    assert.strictEqual(selfProc.memoryLimitMb, 512);
    assert.ok(selfProc.memoryMb > 0);
  });

  it("records and retrieves blocked system call events in ring buffer", () => {
    clearBlockedCallEvents();
    assert.strictEqual(getRecordedBlockedEvents().length, 0);

    recordBlockedCallEvent({
      category: "metadata_imds",
      command: "curl http://169.254.169.254/latest",
      action: "BLOCKED",
      mechanism: "process_egress_firewall",
    });

    recordBlockedCallEvent({
      category: "protected_file_access",
      command: "read_file path=.env",
      action: "BLOCKED",
      mechanism: "mcp_wrapper_firewall",
    });

    const events = getRecordedBlockedEvents();
    assert.strictEqual(events.length, 2);
    assert.strictEqual(events[0].category, "protected_file_access");
    assert.strictEqual(events[1].category, "metadata_imds");
  });

  it("generates a structured TopMonitorSnapshot with accurate health status", () => {
    const snapshot = getTopMonitorSnapshot(1024);
    assert.strictEqual(typeof snapshot.version, "string");
    assert.strictEqual(typeof snapshot.hostOs, "string");
    assert.strictEqual(snapshot.defaultMemoryCeilingMb, 1024);
    assert.ok(snapshot.systemTotalMemoryMb > 0);
    assert.ok(Array.isArray(snapshot.activeProcesses));
    assert.ok(Array.isArray(snapshot.taintFlows));
    assert.ok(Array.isArray(snapshot.blockedCalls));
  });

  it("formats top monitor view into a clean ANSI dashboard string", () => {
    const snapshot = getTopMonitorSnapshot(512);
    const output = formatTopMonitorView(snapshot);
    assert.ok(output.includes("AgentShield Top Monitor"));
    assert.ok(output.includes("Host OS:"));
    assert.ok(output.includes("Memory Ceiling:"));
    assert.ok(output.includes("512 MB per agent"));
    assert.ok(output.includes("Real-Time Secret Taint Flows"));
    assert.ok(output.includes("[q] Quit"));
  });
});
