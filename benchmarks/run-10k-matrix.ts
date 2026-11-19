#!/usr/bin/env tsx
/**
 * Reproducible 10,000-Call Latency & Throughput Benchmark Matrix (Phase 9)
 *
 * Benchmarks core AgentShield hot paths and outputs machine-readable JSON & CSV
 * latency percentiles (min, mean, p50, p95, p99, max) for CI regression gating.
 *
 * Usage:
 *   npx tsx benchmarks/run-10k-matrix.ts [--iterations 10000] [--out benchmarks/out] [--max-p99-ms 15]
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { cpus, platform, release } from "node:os";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { redactText } from "../src/core-redactor.js";
import { AgentShieldEngine } from "../src/engine.js";
import { AgentCommandSandbox } from "../src/sandbox.js";
import { ZygoteProcessPool } from "../src/zygote-pool.js";

export interface BenchmarkMetric {
  scenario: string;
  iterations: number;
  totalMs: number;
  opsPerSec: number;
  minMicros: number;
  meanMicros: number;
  p50Micros: number;
  p95Micros: number;
  p99Micros: number;
  maxMicros: number;
  p99Ms: number;
  passedGate: boolean;
}

export interface BenchmarkMatrixReport {
  schemaVersion: "1.0";
  generatedAt: string;
  environment: {
    nodeVersion: string;
    platform: string;
    osRelease: string;
    cpuModel: string;
    cpuCores: number;
  };
  iterationsPerScenario: number;
  maxP99MsGate: number;
  allGatesPassed: boolean;
  results: BenchmarkMetric[];
}

export interface BenchmarkRunOptions {
  iterations?: number;
  warmup?: number;
  outputDir?: string;
  maxP99Ms?: number;
}

function round(n: number, decimals = 2): number {
  const factor = 10 ** decimals;
  return Math.round(n * factor) / factor;
}

function percentile(sorted: Float64Array, p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function measureScenario(
  scenario: string,
  iterations: number,
  warmup: number,
  maxP99Ms: number,
  fn: (i: number) => void | Promise<void>,
): Promise<BenchmarkMetric> {
  for (let i = 0; i < warmup; i++) {
    await fn(i);
  }

  const samplesMicros = new Float64Array(iterations);
  const suiteStart = performance.now();

  for (let i = 0; i < iterations; i++) {
    const t0 = performance.now();
    await fn(i);
    samplesMicros[i] = (performance.now() - t0) * 1000;
  }

  const totalMs = Math.max(0.001, performance.now() - suiteStart);
  samplesMicros.sort();

  let sum = 0;
  for (let i = 0; i < iterations; i++) {
    sum += samplesMicros[i];
  }

  const p99Micros = percentile(samplesMicros, 99);
  const p99Ms = p99Micros / 1000;

  return {
    scenario,
    iterations,
    totalMs: round(totalMs, 2),
    opsPerSec: Math.round((iterations / totalMs) * 1000),
    minMicros: round(samplesMicros[0], 2),
    meanMicros: round(sum / iterations, 2),
    p50Micros: round(percentile(samplesMicros, 50), 2),
    p95Micros: round(percentile(samplesMicros, 95), 2),
    p99Micros: round(p99Micros, 2),
    maxMicros: round(samplesMicros[iterations - 1], 2),
    p99Ms: round(p99Ms, 4),
    passedGate: p99Ms <= maxP99Ms,
  };
}

export function formatBenchmarkCsv(report: BenchmarkMatrixReport): string {
  const header =
    "scenario,iterations,total_ms,ops_per_sec,min_us,mean_us,p50_us,p95_us,p99_us,max_us,p99_ms,passed_gate";
  const rows = report.results.map(
    (r) =>
      `${r.scenario},${r.iterations},${r.totalMs},${r.opsPerSec},${r.minMicros},${r.meanMicros},${r.p50Micros},${r.p95Micros},${r.p99Micros},${r.maxMicros},${r.p99Ms},${r.passedGate}`,
  );
  return `${header}\n${rows.join("\n")}\n`;
}

export async function runBenchmarkMatrix(
  options: BenchmarkRunOptions = {},
): Promise<BenchmarkMatrixReport> {
  const iterations = options.iterations ?? 10_000;
  const warmup = options.warmup ?? Math.min(200, Math.max(20, Math.floor(iterations / 20)));
  const maxP99Ms = options.maxP99Ms ?? 15;

  // Build synthetic runtime payloads with zero high-entropy static literals in source
  const syntheticPat = ["ghp", "a".repeat(36)].join("_");
  const cleanPayload = "INFO [worker-42] Processed 128 analytics rows in 3.2ms status=200";
  const secretPayload = `DEBUG auth_header=Bearer ${syntheticPat} region=us-east-1`;

  const engine = new AgentShieldEngine();
  const sandbox = new AgentCommandSandbox();
  const zygotePool = new ZygoteProcessPool({ minIdle: 4, maxCapacity: 8 });

  const results: BenchmarkMetric[] = [];
  try {
    results.push(
      await measureScenario("core_redactor_mixed", iterations, warmup, maxP99Ms, (i) => {
        redactText(i % 2 === 0 ? cleanPayload : secretPayload);
      }),
    );

    results.push(
      await measureScenario("engine_scan_and_redact", iterations, warmup, maxP99Ms, (i) => {
        engine.scanAndRedact(i % 2 === 0 ? cleanPayload : secretPayload);
      }),
    );

    results.push(
      await measureScenario("sandbox_command_inspect", iterations, warmup, maxP99Ms, (i) => {
        sandbox.inspectCommand(i % 2 === 0 ? "git status --short" : "cat .env && printenv");
      }),
    );

    results.push(
      await measureScenario("zygote_pool_dispatch", iterations, warmup, maxP99Ms, async () => {
        await zygotePool.dispatch({ action: "inspect", command: "ls -la" });
      }),
    );
  } finally {
    zygotePool.shutdown();
  }

  const cpuInfo = cpus();
  const report: BenchmarkMatrixReport = {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    environment: {
      nodeVersion: process.version,
      platform: platform(),
      osRelease: release(),
      cpuModel: cpuInfo[0]?.model || "unknown",
      cpuCores: cpuInfo.length || 1,
    },
    iterationsPerScenario: iterations,
    maxP99MsGate: maxP99Ms,
    allGatesPassed: results.every((r) => r.passedGate),
    results,
  };

  if (options.outputDir) {
    const outDir = resolve(options.outputDir);
    mkdirSync(outDir, { recursive: true });
    writeFileSync(
      join(outDir, "benchmark-matrix.json"),
      `${JSON.stringify(report, null, 2)}\n`,
      "utf8",
    );
    writeFileSync(join(outDir, "benchmark-matrix.csv"), formatBenchmarkCsv(report), "utf8");
  }

  return report;
}

const isMain =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (isMain) {
  const args = process.argv.slice(2);
  const iterIdx = args.indexOf("--iterations");
  const outIdx = args.indexOf("--out");
  const gateIdx = args.indexOf("--max-p99-ms");

  const iterations = iterIdx !== -1 && args[iterIdx + 1] ? Number(args[iterIdx + 1]) : 10_000;
  const outputDir = outIdx !== -1 && args[outIdx + 1] ? args[outIdx + 1] : "benchmarks/out";
  const maxP99Ms = gateIdx !== -1 && args[gateIdx + 1] ? Number(args[gateIdx + 1]) : 15;

  runBenchmarkMatrix({ iterations, outputDir, maxP99Ms })
    .then((report) => {
      console.log(
        `\n📊 AgentShield 10k-Call Reproducible Benchmark Matrix (${report.iterationsPerScenario} iterations/scenario)`,
      );
      console.table(
        report.results.map((r) => ({
          scenario: r.scenario,
          ops_sec: r.opsPerSec,
          p50_us: r.p50Micros,
          p95_us: r.p95Micros,
          p99_us: r.p99Micros,
          gate_ok: r.passedGate,
        })),
      );
      console.log(`✅ Artifacts written to ${resolve(outputDir)}/benchmark-matrix.{json,csv}`);
      if (!report.allGatesPassed) {
        console.error(
          `❌ Benchmark regression gate failed: one or more scenarios exceeded ${report.maxP99MsGate}ms p99.`,
        );
        process.exit(1);
      }
    })
    .catch((err) => {
      console.error("❌ Benchmark runner failed:", err);
      process.exit(1);
    });
}
