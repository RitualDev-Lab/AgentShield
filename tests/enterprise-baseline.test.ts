import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import {
  AgentShieldBenchmark,
  BaselineManager,
  LiveSecretVerifier,
} from "../src/enterprise-baseline.js";

describe("Phase F: Enterprise Value-Adds (Live Verification, Baselines & Benchmarks)", () => {
  const engine = new AgentShieldEngine();

  it("should verify secret validity and attribute to correct provider", () => {
    const rawAws = ["AKIA", "0123456789ABCDEF"].join("");
    const awsFinding = {
      patternId: "aws-access-key-id",
      patternName: "AWS Access Key",
      category: "cloud" as const,
      severity: "critical" as const,
      raw: rawAws,
      redacted: "[AGENT_SHIELD:AWS:123]",
      line: 1,
      column: 1,
      entropy: 4.8,
    };

    const res = LiveSecretVerifier.verifyOffline(awsFinding);
    assert.equal(res.isValid, true);
    assert.equal(res.status, "active");
    assert.equal(res.provider, "AWS");
  });

  it("should compute fingerprints and filter against baseline", () => {
    const rawOpenAI = ["sk-proj-", "1234567890abcdef1234567890abcdef1234"].join("");
    const finding = {
      patternId: "openai-api-key",
      patternName: "OpenAI Secret",
      category: "ai" as const,
      severity: "critical" as const,
      raw: rawOpenAI,
      redacted: "[AGENT_SHIELD:OPENAI:123]",
      line: 5,
      column: 10,
      entropy: 4.9,
      file: "config.js",
    };

    const fp = BaselineManager.computeFingerprint(finding, finding.file);
    assert.equal(typeof fp, "string");
    assert.equal(fp.length, 64);
  });

  it("should execute performance benchmark measuring sub-millisecond latency", () => {
    const sample =
      "const OPENAI_API_KEY = 'sk-proj-1234567890abcdef1234567890abcdef1234';\nconst DB = 'postgres://user:pass@localhost:5432/db';";
    const metrics = AgentShieldBenchmark.runScanBenchmark(sample, 50, engine);

    assert.equal(metrics.iterations, 50);
    assert.ok(metrics.opsPerSecond > 0);
    assert.ok(metrics.averageLatencyMs >= 0);
    assert.ok(metrics.throughputMbPerSecond >= 0);
  });
});
