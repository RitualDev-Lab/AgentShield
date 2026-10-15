import type { CiAuditResult } from "./ci.js";
import type { DetectedSecret } from "./types.js";

export interface GitHubActionOptions {
  token?: string;
  repo?: string; // owner/repo
  issueNumber?: number; // PR number
  failOnLeak?: boolean;
  annotateDiff?: boolean;
  postComment?: boolean;
  apiBaseUrl?: string;
}

export interface GitHubAnnotation {
  level: "error" | "warning" | "notice";
  file: string;
  line: number;
  col: number;
  title: string;
  message: string;
}

/**
 * Enterprise GitHub Action & Pull Request Review Bot Suite:
 * - Emits GitHub Actions workflow commands (::error, ::warning) for inline annotations.
 * - Posts or updates sticky PR comments using the GitHub REST API.
 * - Enforces commit pass/fail gates on leaked credentials.
 */
export class GitHubActionBot {
  public static readonly PR_COMMENT_TAG = "<!-- agentshield-security-gate-comment -->";
  private defaultOptions: GitHubActionOptions;

  constructor(defaultOptions: GitHubActionOptions = {}) {
    this.defaultOptions = defaultOptions;
  }

  public annotate(findings: Array<DetectedSecret & { file: string }>): string[] {
    return GitHubActionBot.formatAnnotations(findings);
  }

  public async postComment(
    result: CiAuditResult,
    options?: GitHubActionOptions,
  ): Promise<{
    success: boolean;
    commentId?: number;
    action?: "created" | "updated" | "skipped";
    error?: string;
  }> {
    return GitHubActionBot.postOrUpdatePrComment(result, {
      ...this.defaultOptions,
      ...options,
    });
  }

  /**
   * Formats findings into GitHub Actions Workflow command annotations.
   * Syntax: ::error file={name},line={line},col={col},title={title}::{message}
   */
  public static formatAnnotations(findings: Array<DetectedSecret & { file: string }>): string[] {
    return findings.map((f) => {
      const level = f.severity === "critical" || f.severity === "high" ? "error" : "warning";
      const title = `AgentShield: ${f.patternName} Exposed`;
      const message = `Secret detected (${f.severity.toUpperCase()}) [${f.patternId}]. Redacted: ${f.redacted}`;
      return `::${level} file=${f.file},line=${f.line || 1},col=${f.column || 1},title=${title}::${message}`;
    });
  }

  /**
   * Emits workflow annotations directly to process.stdout
   */
  public static emitAnnotations(findings: Array<DetectedSecret & { file: string }>): void {
    const annotations = GitHubActionBot.formatAnnotations(findings);
    for (const ann of annotations) {
      console.log(ann);
    }
  }

  /**
   * Generates a GitHub PR comment markdown document
   */
  public static generatePrComment(result: CiAuditResult, commitSha?: string): string {
    const lines: string[] = [
      GitHubActionBot.PR_COMMENT_TAG,
      "## 🛡️ AgentShield Pull Request Security Audit",
      "",
    ];

    if (result.passed) {
      lines.push("### ✅ **Security Gate Passed** — No Exposed Secrets Detected");
      lines.push("");
      lines.push(`- **Files Audited**: \`${result.filesScanned}\``);
      if (commitSha) {
        lines.push(`- **Commit Evaluated**: \`${commitSha.substring(0, 7)}\``);
      }
      lines.push(
        "- **Status**: Diff is clean. Zero-leak credential policy verified for autonomous AI & developer tools.",
      );
      lines.push("");
      lines.push(
        "[![AgentShield: OWASP LLM06 Compliant](https://img.shields.io/badge/AgentShield-OWASP%20LLM06%20Compliant-10b981?logo=shield&logoColor=white&style=flat-square)](https://agentshield.ritualdev.in/compliance)",
      );
    } else {
      lines.push(
        `### 🚨 **Security Gate Failed** — ${result.totalSecrets} Exposed Secret(s) Detected!`,
      );
      lines.push("");
      lines.push(
        "AgentShield detected hardcoded credentials in the changes proposed in this pull request:",
      );
      lines.push("");
      lines.push("| File | Finding | Severity | Redacted Preview |");
      lines.push("| :--- | :--- | :---: | :--- |");

      for (const finding of result.findings) {
        lines.push(
          `| \`${finding.file}\` | **${finding.patternName}** | \`${finding.severity.toUpperCase()}\` | \`${finding.redacted}\` |`,
        );
      }

      lines.push("");
      lines.push(
        "> ⚠️ **Recommended Action**: Please revoke the exposed credentials, unstage them from git history, and supply them securely via repository secrets or environment variables.",
      );
    }

    lines.push("");
    lines.push("---");
    lines.push(
      "*Protected by [AgentShield](https://github.com/RitualDev-Lab/AgentShield) — Zero-Leak Security for AI Agents & Engineering Teams.*",
    );

    return lines.join("\n");
  }

  /**
   * Posts or updates sticky PR comment using GitHub REST API
   */
  public static async postOrUpdatePrComment(
    result: CiAuditResult,
    options: GitHubActionOptions,
  ): Promise<{
    success: boolean;
    commentId?: number;
    action?: "created" | "updated" | "skipped";
    error?: string;
  }> {
    const token = options.token || process.env.GITHUB_TOKEN;
    const repo = options.repo || process.env.GITHUB_REPOSITORY;
    let prNumber = options.issueNumber;

    if (!prNumber && process.env.GITHUB_REF) {
      const match = process.env.GITHUB_REF.match(/refs\/pull\/(\d+)\//);
      if (match) {
        prNumber = Number.parseInt(match[1], 10);
      }
    }

    if (!token || !repo || !prNumber) {
      return {
        success: false,
        action: "skipped",
        error:
          "Missing required GitHub credentials (GITHUB_TOKEN, GITHUB_REPOSITORY, or PR number).",
      };
    }

    const apiBase = options.apiBaseUrl || process.env.GITHUB_API_URL || "https://api.github.com";
    const commentBody = GitHubActionBot.generatePrComment(result, process.env.GITHUB_SHA);

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "AgentShield-Security-Gate",
      "Content-Type": "application/json",
    };

    try {
      // 1. Check for existing sticky comment
      const listRes = await fetch(
        `${apiBase}/repos/${repo}/issues/${prNumber}/comments?per_page=50`,
        {
          headers,
        },
      );

      if (!listRes.ok) {
        return {
          success: false,
          error: `Failed to query existing PR comments: HTTP ${listRes.status}`,
        };
      }

      const comments = (await listRes.json()) as Array<{ id: number; body: string }>;
      const existing = comments.find((c) => c.body?.includes(GitHubActionBot.PR_COMMENT_TAG));

      if (existing) {
        // Update existing comment
        const updateRes = await fetch(`${apiBase}/repos/${repo}/issues/comments/${existing.id}`, {
          method: "PATCH",
          headers,
          body: JSON.stringify({ body: commentBody }),
        });

        if (!updateRes.ok) {
          return {
            success: false,
            error: `Failed to update PR comment: HTTP ${updateRes.status}`,
          };
        }

        return { success: true, commentId: existing.id, action: "updated" };
      }

      // Create new comment
      const createRes = await fetch(`${apiBase}/repos/${repo}/issues/${prNumber}/comments`, {
        method: "POST",
        headers,
        body: JSON.stringify({ body: commentBody }),
      });

      if (!createRes.ok) {
        return {
          success: false,
          error: `Failed to create PR comment: HTTP ${createRes.status}`,
        };
      }

      const created = (await createRes.json()) as { id: number };
      return { success: true, commentId: created.id, action: "created" };
    } catch (err: unknown) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
