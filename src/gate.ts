import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { AgentShieldEngine } from "./engine.js";
import { AGENTSHIELD_VERSION } from "./version.js";

export interface GitPreCommitResult {
  passed: boolean;
  blockedFiles: string[];
  findingsCount: number;
  report: string;
}

const CRITICAL_FILE_PATTERNS = [
  /^\.env(?:\..*)?$/i,
  /^id_rsa$/i,
  /^id_ed25519$/i,
  /^id_ecdsa$/i,
  /.*\.pem$/i,
  /(?:^|[\/\\])(?:private|id_rsa|server|client|tls|ssl|secret).*\.key$/i,
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
      stagedFilesStr = execFileSync("git", ["diff", "--cached", "--name-only"], {
        encoding: "utf8",
      }).trim();
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
      // 1. Check filename against critical credentials patterns using basename so subdirectories are caught
      const fileNameOnly = basename(file);
      const isCriticalFile = CRITICAL_FILE_PATTERNS.some(
        (p) => p.test(fileNameOnly) || p.test(file),
      );
      if (isCriticalFile) {
        blockedFiles.push(file);
        findingsCount++;
        reportLines.push(
          `  🚨 [CRITICAL_FILE] Blocked staging of sensitive credential file: '${file}'`,
        );
        continue;
      }

      // 2. Scan content of staged diff safely via execFileSync
      try {
        const diffContent = execFileSync("git", ["diff", "--cached", "--", file], {
          encoding: "utf8",
        });
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
   * Resolves common git directory across standard repos and git worktrees.
   */
  public installHook(repoRoot: string = process.cwd()): boolean {
    let hooksDir = join(repoRoot, ".git", "hooks");

    // Support Git worktrees where .git is a file
    try {
      const gitDir = execFileSync("git", ["rev-parse", "--git-path", "hooks"], {
        cwd: repoRoot,
        encoding: "utf8",
      }).trim();
      if (gitDir && existsSync(gitDir)) {
        hooksDir = gitDir;
      }
    } catch {
      // Fallback to .git/hooks
    }

    if (!existsSync(hooksDir)) {
      return false;
    }

    const preCommitPath = join(hooksDir, "pre-commit");
    const marker = "# --- AgentShield Pre-Commit Gate ---";
    const hookSnippet = `
${marker}
if [ -f "./node_modules/.bin/agentshield" ]; then
  ./node_modules/.bin/agentshield hook check
elif command -v npx >/dev/null 2>&1; then
  npx --no-install @ritualdev-lab/agentshield hook check 2>/dev/null || npx @ritualdev-lab/agentshield@${AGENTSHIELD_VERSION} hook check
fi

if [ $? -ne 0 ]; then
  echo "\\n🚨 [AgentShield] Commit aborted to prevent secret leakage. Run 'npx @ritualdev-lab/agentshield@${AGENTSHIELD_VERSION} redact' or unstage credentials.\\n"
  exit 1
fi
# --- End AgentShield Gate ---
`;

    if (existsSync(preCommitPath)) {
      const existing = readFileSync(preCommitPath, "utf8");
      if (!existing.includes(marker)) {
        writeFileSync(preCommitPath, `${existing.trim()}\n${hookSnippet}`, {
          encoding: "utf8",
          mode: 0o755,
        });
      }
    } else {
      writeFileSync(preCommitPath, `#!/bin/sh${hookSnippet}`, {
        encoding: "utf8",
        mode: 0o755,
      });
    }

    return true;
  }
}
