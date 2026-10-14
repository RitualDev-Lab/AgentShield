import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { loadConfig, parseCustomPatterns } from "./config.js";
import { AgentShieldEngine } from "./engine.js";
import { SarifFormatter } from "./sarif.js";
import type { SarifLog } from "./taxonomy.js";
import type { DetectedSecret, ScanOptions } from "./types.js";

export interface CiAuditResult {
  passed: boolean;
  totalSecrets: number;
  criticalCount: number;
  highCount: number;
  filesScanned: number;
  findings: Array<DetectedSecret & { file: string }>;
  markdownReport: string;
  sarifLog?: SarifLog;
}

export class CiGateRunner {
  private engine: AgentShieldEngine;
  private rootDir: string;
  private config: ReturnType<typeof loadConfig>;

  constructor(rootDir: string = process.cwd()) {
    this.rootDir = rootDir;
    this.config = loadConfig(rootDir);
    const customPatterns = parseCustomPatterns(this.config);
    this.engine = new AgentShieldEngine(customPatterns);
  }

  /**
   * Scans git diff for CI workflows (pull requests and pushes)
   */
  public auditPullRequest(baseRef = "origin/main"): CiAuditResult {
    // Validate baseRef to avoid injection or unexpected flags (allow branches, tags, HEAD~N, HEAD^N)
    const sanitizedBase = baseRef.trim();
    if (!/^[a-zA-Z0-9_\-\.\/~^]+$/.test(sanitizedBase)) {
      throw new Error(`Invalid git base ref: '${sanitizedBase}'`);
    }

    const ignoredFiles = new Set(this.config?.ci?.ignoreFiles || []);
    const scanOptions: ScanOptions = {
      allowlist: this.config?.allowlist || [],
      entropyThreshold: this.config?.entropyThreshold ?? 4.5,
      maskStyle: this.config?.maskStyle || "token",
    };

    let diffFiles: string[] = [];
    try {
      // Get list of changed files safely via execFileSync
      const raw = execFileSync("git", ["diff", "--name-only", `${sanitizedBase}...HEAD`], {
        encoding: "utf8",
      }).trim();
      diffFiles = raw
        .split("\n")
        .map((f) => f.trim())
        .filter((f) => Boolean(f) && !ignoredFiles.has(f));
    } catch {
      try {
        // Fallback for single-commit pushes
        const raw = execFileSync("git", ["diff", "--name-only", "HEAD~1", "HEAD"], {
          encoding: "utf8",
        }).trim();
        diffFiles = raw
          .split("\n")
          .map((f) => f.trim())
          .filter((f) => Boolean(f) && !ignoredFiles.has(f));
      } catch {
        diffFiles = [];
      }
    }

    const allFindings: Array<DetectedSecret & { file: string }> = [];
    let criticalCount = 0;
    let highCount = 0;

    for (const file of diffFiles) {
      try {
        const diffContent = execFileSync("git", ["diff", `${sanitizedBase}...HEAD`, "--", file], {
          encoding: "utf8",
        });

        const addedLines = diffContent
          .split("\n")
          .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
          .map((line) => line.substring(1))
          .join("\n");

        if (!addedLines.trim()) continue;

        const scan = this.engine.scanAndRedact(addedLines, scanOptions);
        if (scan.hasSecrets) {
          for (const finding of scan.findings) {
            allFindings.push({ ...finding, file });
            if (finding.severity === "critical") criticalCount++;
            if (finding.severity === "high") highCount++;
          }
        }
      } catch {
        // Skip binary files or unreadable diffs
      }
    }

    const failSeverity = this.config?.ci?.failOnSeverity || "high";
    const failSeverities =
      failSeverity === "medium"
        ? ["critical", "high", "medium"]
        : failSeverity === "high"
          ? ["critical", "high"]
          : ["critical"];

    const blockingFindings = allFindings.filter((f) => failSeverities.includes(f.severity));
    const passed = blockingFindings.length === 0;

    // Generate markdown report
    const reportLines: string[] = ["## 🛡️ AgentShield CI/CD Security Gate Report\n"];

    if (passed) {
      reportLines.push("### ✅ 0 Leaked Secrets Detected");
      reportLines.push(`- **Files Audited**: ${diffFiles.length}`);
      reportLines.push("- **Result**: Clean — Safe to merge!");
    } else {
      reportLines.push(`### 🚨 ${allFindings.length} Exposed Secret(s) Detected in Diff!\n`);
      reportLines.push("| File | Finding | Severity | Redacted Preview |");
      reportLines.push("| :--- | :--- | :---: | :--- |");

      for (const finding of allFindings) {
        reportLines.push(
          `| \`${finding.file}\` | **${finding.patternName}** | \`${finding.severity.toUpperCase()}\` | \`${finding.redacted}\` |`,
        );
      }

      reportLines.push(
        "\n> ⚠️ **Action Required**: Please revoke these credentials and replace them with environment variable references.",
      );
    }

    const markdownReport = reportLines.join("\n");
    const sarifLog = SarifFormatter.generateSarif(allFindings, []);

    return {
      passed,
      totalSecrets: allFindings.length,
      criticalCount,
      highCount,
      filesScanned: diffFiles.length,
      findings: allFindings,
      markdownReport,
      sarifLog,
    };
  }
}
