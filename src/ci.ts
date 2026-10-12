import { execSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { loadConfig, parseCustomPatterns } from "./config.js";
import { AgentShieldEngine } from "./engine.js";
import type { DetectedSecret } from "./types.js";

export interface CiAuditResult {
  passed: boolean;
  totalSecrets: number;
  criticalCount: number;
  highCount: number;
  filesScanned: number;
  findings: Array<DetectedSecret & { file: string }>;
  markdownReport: string;
}

export class CiGateRunner {
  private engine: AgentShieldEngine;
  private rootDir: string;

  constructor(rootDir: string = process.cwd()) {
    this.rootDir = rootDir;
    const config = loadConfig(rootDir);
    const customPatterns = parseCustomPatterns(config);
    this.engine = new AgentShieldEngine(customPatterns);
  }

  /**
   * Scans git diff for CI workflows (pull requests and pushes)
   */
  public auditPullRequest(baseRef = "origin/main"): CiAuditResult {
    let diffFiles: string[] = [];
    try {
      // Get list of changed files
      const raw = execSync(`git diff --name-only ${baseRef}...HEAD`, { encoding: "utf8" }).trim();
      diffFiles = raw
        .split("\n")
        .map((f) => f.trim())
        .filter(Boolean);
    } catch {
      try {
        // Fallback for single-commit pushes
        const raw = execSync("git diff --name-only HEAD~1 HEAD", { encoding: "utf8" }).trim();
        diffFiles = raw
          .split("\n")
          .map((f) => f.trim())
          .filter(Boolean);
      } catch {
        diffFiles = [];
      }
    }

    const allFindings: Array<DetectedSecret & { file: string }> = [];
    let criticalCount = 0;
    let highCount = 0;

    for (const file of diffFiles) {
      try {
        const diffContent = execSync(`git diff ${baseRef}...HEAD -- "${file}"`, {
          encoding: "utf8",
        });

        const addedLines = diffContent
          .split("\n")
          .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
          .map((line) => line.substring(1))
          .join("\n");

        if (!addedLines.trim()) continue;

        const scan = this.engine.scanAndRedact(addedLines);
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

    const passed = allFindings.length === 0;

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

    return {
      passed,
      totalSecrets: allFindings.length,
      criticalCount,
      highCount,
      filesScanned: diffFiles.length,
      findings: allFindings,
      markdownReport,
    };
  }
}
