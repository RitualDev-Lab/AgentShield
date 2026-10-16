import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { loadConfig, parseCustomPatterns } from "./config.js";
import { AgentShieldEngine } from "./engine.js";
import { SarifFormatter } from "./sarif.js";
import type { SarifLog } from "./taxonomy.js";
import type { DetectedSecret, ScanOptions } from "./types.js";

export interface CiAuditOptions {
  allowEmptyDiff?: boolean;
}

export interface CiAuditResult {
  passed: boolean;
  totalSecrets: number;
  criticalCount: number;
  highCount: number;
  filesScanned: number;
  findings: Array<DetectedSecret & { file: string }>;
  markdownReport: string;
  sarifLog?: SarifLog;
  scanError?: string;
  baseRef: string;
  diffMethod?: string;
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
  public auditPullRequest(baseRef = "origin/main", _options?: CiAuditOptions): CiAuditResult {
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
    let diffArgs: string[] = [];
    let diffMethod = "";
    let diffError: string | null = null;
    let diffSuccess = false;

    // 1. Primary diff: range against baseRef
    try {
      const raw = execFileSync("git", ["diff", "--name-only", `${sanitizedBase}...HEAD`], {
        encoding: "utf8",
        cwd: this.rootDir,
      }).trim();
      diffFiles = raw
        ? raw
            .split("\n")
            .map((f) => f.trim())
            .filter((f) => Boolean(f) && !ignoredFiles.has(f))
        : [];
      diffArgs = [`${sanitizedBase}...HEAD`];
      diffMethod = `${sanitizedBase}...HEAD`;
      diffSuccess = true;
    } catch (primaryErr: unknown) {
      diffError = primaryErr instanceof Error ? primaryErr.message : String(primaryErr);
      // 2. Fallback for single-commit pushes
      try {
        const raw = execFileSync("git", ["diff", "--name-only", "HEAD~1", "HEAD"], {
          encoding: "utf8",
          cwd: this.rootDir,
        }).trim();
        diffFiles = raw
          ? raw
              .split("\n")
              .map((f) => f.trim())
              .filter((f) => Boolean(f) && !ignoredFiles.has(f))
          : [];
        diffArgs = ["HEAD~1", "HEAD"];
        diffMethod = "HEAD~1 HEAD";
        diffSuccess = true;
        diffError = null; // Fallback succeeded
      } catch (fallbackErr: unknown) {
        const fallbackMsg =
          fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr);
        diffError = `Git diff discovery failed on both '${sanitizedBase}...HEAD' and 'HEAD~1 HEAD'. Primary: ${diffError} | Fallback: ${fallbackMsg}`;
      }
    }

    // FAIL-CLOSED: In a security gate, if diff discovery fails, NEVER report clean!
    if (!diffSuccess) {
      const errorReportLines: string[] = [
        "## 🛡️ AgentShield CI/CD Security Gate Report\n",
        "### ❌ CI Gate Execution Error: Unable to compute Git diff",
        `- **Base Reference**: \`${sanitizedBase}\``,
        `- **Failure Details**: ${diffError}`,
        "\n> 🚨 **Security Failure (Fail-Closed)**: AgentShield refused to mark this build clean because git diff comparison could not be executed.",
        "> **Remediation**: Verify that `actions/checkout` specifies `fetch-depth: 0` (or sufficient history) and that the base reference exists in the git repository.\n",
      ];
      return {
        passed: false,
        totalSecrets: 0,
        criticalCount: 0,
        highCount: 0,
        filesScanned: 0,
        findings: [],
        markdownReport: errorReportLines.join("\n"),
        scanError: diffError || "Git diff discovery failed",
        baseRef: sanitizedBase,
      };
    }

    const allFindings: Array<DetectedSecret & { file: string }> = [];
    let criticalCount = 0;
    let highCount = 0;

    for (const file of diffFiles) {
      try {
        const diffContent = execFileSync("git", ["diff", ...diffArgs, "--", file], {
          encoding: "utf8",
          cwd: this.rootDir,
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
      if (diffFiles.length === 0) {
        reportLines.push("### ℹ️ 0 Modified Files Audited");
        reportLines.push(`- **Base Ref**: \`${sanitizedBase}\` (method: \`${diffMethod}\`)`);
        reportLines.push("- **Result**: Clean — No changed files to audit.\n");
      } else {
        reportLines.push("### ✅ 0 Leaked Secrets Detected");
        reportLines.push(`- **Files Audited**: ${diffFiles.length} (via \`${diffMethod}\`)`);
        reportLines.push("- **Result**: Clean — Safe to merge!\n");
      }
      reportLines.push(
        "[![AgentShield: OWASP LLM06 Compliant](https://img.shields.io/badge/AgentShield-OWASP%20LLM06%20Compliant-10b981?logo=shield&logoColor=white&style=flat-square)](https://agentshield.ritualdev.in/compliance)\n",
      );
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
      baseRef: sanitizedBase,
      diffMethod,
    };
  }
}
