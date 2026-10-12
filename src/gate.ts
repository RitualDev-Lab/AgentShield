import { execSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { AgentShieldEngine } from "./engine.js";

export interface GitPreCommitResult {
  passed: boolean;
  blockedFiles: string[];
  findingsCount: number;
  report: string;
}

const CRITICAL_FILE_PATTERNS = [
  /^\.env(?:\..*)?$/i,
  /^id_rsa(?:\.pub)?$/i,
  /^id_ed25519(?:\.pub)?$/i,
  /.*\.pem$/i,
  /.*\.key$/i,
  /.*\.pfx$/i,
  /.*\.p12$/i,
  /^\.npmrc$/i,
  /^\.netrc$/i,
];

export class GitPreCommitGate {
  private engine: AgentShieldEngine;

  constructor(engine?: AgentShieldEngine) {
    this.engine = engine || new AgentShieldEngine();
  }

  /**
   * Scans staged files and diffs in the current Git repository.
   */
  public auditStagedFiles(): GitPreCommitResult {
    const blockedFiles: string[] = [];
    const reportLines: string[] = [];
    let findingsCount = 0;

    let stagedFilesStr = "";
    try {
      stagedFilesStr = execSync("git diff --cached --name-only", { encoding: "utf8" }).trim();
    } catch {
      return {
        passed: true,
        blockedFiles: [],
        findingsCount: 0,
        report: "Not a git repository or no staged files.",
      };
    }

    if (!stagedFilesStr) {
      return {
        passed: true,
        blockedFiles: [],
        findingsCount: 0,
        report: "No staged files found.",
      };
    }

    const stagedFiles = stagedFilesStr
      .split("\n")
      .map((f) => f.trim())
      .filter(Boolean);

    for (const file of stagedFiles) {
      // 1. Check filename against critical credentials patterns
      const isCriticalFile = CRITICAL_FILE_PATTERNS.some((p) => p.test(file));
      if (isCriticalFile) {
        blockedFiles.push(file);
        findingsCount++;
        reportLines.push(
          `  🚨 [CRITICAL_FILE] Blocked staging of sensitive credential file: '${file}'`,
        );
        continue;
      }

      // 2. Scan content of staged diff
      try {
        const diffContent = execSync(`git diff --cached -- "${file}"`, { encoding: "utf8" });
        // Only inspect additions (lines starting with +)
        const addedLines = diffContent
          .split("\n")
          .filter((line) => line.startsWith("+") && !line.startsWith("+++"))
          .map((line) => line.substring(1))
          .join("\n");

        const scan = this.engine.scanAndRedact(addedLines);
        if (scan.hasSecrets) {
          blockedFiles.push(file);
          findingsCount += scan.totalFound;
          reportLines.push(
            `  🚨 [SECRET_DETECTED] '${file}' contains ${scan.totalFound} exposed secret(s):`,
          );
          for (const finding of scan.findings) {
            reportLines.push(
              `     • ${finding.patternName} (Line ${finding.line}) -> Redacted: ${finding.redacted}`,
            );
          }
        }
      } catch {
        // Skip unreadable binary files
      }
    }

    const passed = blockedFiles.length === 0;

    return {
      passed,
      blockedFiles,
      findingsCount,
      report: passed
        ? "✅ [PASSED] No exposed secrets or credential files in staged git changes."
        : `❌ [BLOCKED] AgentShield detected ${findingsCount} secret leak(s) across ${blockedFiles.length} file(s):\n${reportLines.join("\n")}`,
    };
  }

  /**
   * Installs the automatic pre-commit hook into the current git repository.
   */
  public installHook(repoRoot: string = process.cwd()): boolean {
    const hooksDir = join(repoRoot, ".git", "hooks");
    if (!existsSync(hooksDir)) {
      return false;
    }

    const preCommitPath = join(hooksDir, "pre-commit");
    const hookScript = `#!/bin/sh
# 🛡️ AgentShield Automatic Zero-Leak Pre-commit Gate
npx agentshield hook check
if [ $? -ne 0 ]; then
  echo "\n🚨 [AgentShield] Commit aborted to prevent secret leakage. Run 'npx agentshield redact' or unstage credentials.\n"
  exit 1
fi
`;

    writeFileSync(preCommitPath, hookScript, { encoding: "utf8", mode: 0o755 });
    return true;
  }
}
