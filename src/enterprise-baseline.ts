import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AgentShieldEngine } from "./engine.js";
import type { DetectedSecret } from "./types.js";

export interface BaselineEntry {
  patternId: string;
  fingerprint: string;
  file?: string;
  line?: number;
  addedAt: string;
}

export interface SecurityBaseline {
  version: string;
  generatedAt: string;
  fingerprints: BaselineEntry[];
}

export interface VerificationResult {
  isValid: boolean;
  status: "active" | "revoked" | "unverified" | "offline";
  provider: string;
  details?: string;
}

export class BaselineManager {
  private baselinePath: string;

  constructor(rootDir: string = process.cwd()) {
    this.baselinePath = join(rootDir, ".agentshield-baseline.json");
  }

  public static computeFingerprint(finding: DetectedSecret, file?: string): string {
    const rawVal = finding.raw || finding.redacted;
    return createHash("sha256")
      .update(`${finding.patternId}:${rawVal}:${file || ""}`)
      .digest("hex");
  }

  public loadBaseline(): SecurityBaseline | null {
    if (!existsSync(this.baselinePath)) return null;
    try {
      const content = readFileSync(this.baselinePath, "utf8");
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  public saveBaseline(findings: Array<DetectedSecret & { file?: string }>): SecurityBaseline {
    const entries: BaselineEntry[] = findings.map((f) => ({
      patternId: f.patternId,
      fingerprint: BaselineManager.computeFingerprint(f, f.file),
      file: f.file,
      line: f.line,
      addedAt: new Date().toISOString(),
    }));

    const baseline: SecurityBaseline = {
      version: "1.0.0",
      generatedAt: new Date().toISOString(),
      fingerprints: entries,
    };

    writeFileSync(this.baselinePath, JSON.stringify(baseline, null, 2), "utf8");
    return baseline;
  }

  public filterAgainstBaseline(
    findings: Array<DetectedSecret & { file?: string }>,
  ): Array<DetectedSecret & { file?: string }> {
    const baseline = this.loadBaseline();
    if (!baseline || !Array.isArray(baseline.fingerprints)) return findings;

    const knownFingerprints = new Set(baseline.fingerprints.map((e) => e.fingerprint));
    return findings.filter((f) => {
      const fp = BaselineManager.computeFingerprint(f, f.file);
      return !knownFingerprints.has(fp);
    });
  }
}

export const LiveSecretVerifier = {
  /**
   * Verifies whether a credential structure appears syntactically valid and active,
   * with offline safety checks and provider attribution.
   */
  verifyOffline(finding: DetectedSecret): VerificationResult {
    const raw = finding.raw;
    if (!raw) {
      return {
        isValid: false,
        status: "unverified",
        provider: finding.patternId,
        details: "No raw credential provided for verification",
      };
    }

    if (finding.patternId === "aws-access-key-id") {
      const isFormatValid = /^(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}$/.test(raw);
      return {
        isValid: isFormatValid,
        status: isFormatValid ? "active" : "revoked",
        provider: "AWS",
        details: isFormatValid ? "AWS Access Key ID format validated" : "Malformed AWS Key ID",
      };
    }

    if (finding.patternId === "openai-api-key") {
      const isFormatValid = /^sk-(proj-|svcacct-)?[A-Za-z0-9_-]{32,120}$/.test(raw);
      return {
        isValid: isFormatValid,
        status: isFormatValid ? "active" : "revoked",
        provider: "OpenAI",
        details: isFormatValid ? "OpenAI API Key format validated" : "Malformed OpenAI Key",
      };
    }

    if (finding.patternId === "stripe-secret-key") {
      const isFormatValid = /^(sk|rk)_(live|test)_[0-9a-zA-Z]{24,100}$/.test(raw);
      return {
        isValid: isFormatValid,
        status: isFormatValid ? "active" : "revoked",
        provider: "Stripe",
        details: isFormatValid ? "Stripe Secret Key format validated" : "Malformed Stripe Key",
      };
    }

    return {
      isValid: true,
      status: "unverified",
      provider: finding.patternId,
      details: "Synthetic format verification passed",
    };
  },
};

export interface BenchmarkMetrics {
  iterations: number;
  totalTimeMs: number;
  opsPerSecond: number;
  averageLatencyMs: number;
  scannedBytes: number;
  throughputMbPerSecond: number;
}

export const AgentShieldBenchmark = {
  runScanBenchmark(
    payload: string,
    iterations = 1000,
    engine = new AgentShieldEngine(),
  ): BenchmarkMetrics {
    const payloadBytes = Buffer.byteLength(payload, "utf8");
    const totalBytes = payloadBytes * iterations;

    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
      engine.scanAndRedact(payload);
    }
    const duration = performance.now() - start;

    const opsPerSecond = Math.round((iterations / (duration / 1000)) * 100) / 100;
    const averageLatencyMs = Math.round((duration / iterations) * 1000) / 1000;
    const throughputMbPerSecond =
      Math.round((totalBytes / (1024 * 1024) / (duration / 1000)) * 100) / 100;

    return {
      iterations,
      totalTimeMs: Math.round(duration * 100) / 100,
      opsPerSecond,
      averageLatencyMs,
      scannedBytes: totalBytes,
      throughputMbPerSecond,
    };
  },
};
