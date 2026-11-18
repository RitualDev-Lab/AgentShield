import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { formatBenchmarkCsv, runBenchmarkMatrix } from "../benchmarks/run-10k-matrix.js";

test("Phase 9: reproducible latency benchmark matrix emits valid JSON & CSV artifacts and passes p99 gate", async () => {
  const outDir = mkdtempSync(join(tmpdir(), "agentshield-bench-"));
  try {
    const report = await runBenchmarkMatrix({
      iterations: 500,
      warmup: 25,
      outputDir: outDir,
      maxP99Ms: 25,
    });

    assert.equal(report.schemaVersion, "1.0");
    assert.equal(report.iterationsPerScenario, 500);
    assert.equal(report.allGatesPassed, true);
    assert.equal(report.results.length, 4);

    for (const metric of report.results) {
      assert.ok(metric.opsPerSec > 0, `${metric.scenario} opsPerSec must be > 0`);
      assert.ok(metric.p50Micros >= 0);
      assert.ok(metric.p95Micros >= metric.p50Micros);
      assert.ok(metric.p99Micros >= metric.p95Micros);
      assert.equal(metric.passedGate, true);
    }

    const jsonPath = join(outDir, "benchmark-matrix.json");
    const csvPath = join(outDir, "benchmark-matrix.csv");
    assert.ok(existsSync(jsonPath));
    assert.ok(existsSync(csvPath));

    const parsedJson = JSON.parse(readFileSync(jsonPath, "utf8"));
    assert.equal(parsedJson.results.length, 4);

    const csv = readFileSync(csvPath, "utf8");
    assert.equal(csv, formatBenchmarkCsv(report));
    assert.match(csv, /^scenario,iterations,total_ms,ops_per_sec/);
    assert.match(csv, /core_redactor_mixed,500,/);
    assert.match(csv, /engine_scan_and_redact,500,/);
    assert.match(csv, /sandbox_command_inspect,500,/);
    assert.match(csv, /zygote_pool_dispatch,500,/);
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
});
