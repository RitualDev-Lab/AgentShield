import { createHmac, timingSafeEqual } from "node:crypto";
import type { CiAuditResult } from "./ci.js";
import type { DetectedSecret } from "./types.js";

export interface GitHubAppWebhookPayload {
  action?: string;
  installation?: {
    id: number;
  };
  repository?: {
    id: number;
    name: string;
    full_name: string;
    owner: {
      login: string;
    };
  };
  pull_request?: {
    number: number;
    title: string;
    head: {
      sha: string;
      ref: string;
    };
    base: {
      sha: string;
      ref: string;
    };
  };
  check_run?: {
    id: number;
    head_sha: string;
    status: string;
    conclusion?: string;
  };
  security_advisory?: {
    ghsa_id?: string;
    cve_id?: string;
    summary?: string;
    description?: string;
    severity?: string;
    state?: string;
  };
  repository_advisory?: {
    ghsa_id?: string;
    cve_id?: string;
    summary?: string;
    description?: string;
    severity?: string;
    state?: string;
  };
}

export interface GitHubCheckRunPayload {
  name: string;
  head_sha: string;
  status: "queued" | "in_progress" | "completed";
  conclusion?: "success" | "failure" | "neutral" | "action_required";
  output?: {
    title: string;
    summary: string;
    text?: string;
    annotations?: Array<{
      path: string;
      start_line: number;
      end_line: number;
      annotation_level: "notice" | "warning" | "failure";
      message: string;
      title?: string;
    }>;
  };
}

export interface GitHubAppConfig {
  appId?: string;
  webhookSecret?: string;
  privateKey?: string;
  apiBaseUrl?: string;
}

/**
 * Enterprise GitHub App & Multi-Tenant Checks API Service:
 * Handles incoming GitHub App webhook events (X-Hub-Signature-256),
 * creates and updates commit Check Runs (Checks API), and maps secret
 * violations into zero-YAML organization-wide security gates.
 */
export class GitHubAppService {
  private config: GitHubAppConfig;

  constructor(config: GitHubAppConfig = {}) {
    this.config = config;
  }

  /**
   * Verifies the authenticity of incoming GitHub App webhooks via HMAC-SHA256 signature.
   * Format: 'sha256=<hex_digest>'
   */
  public verifyWebhookSignature(
    payload: string,
    signatureHeader?: string,
    secret?: string,
  ): boolean {
    const webhookSecret = secret || this.config.webhookSecret || process.env.GITHUB_WEBHOOK_SECRET;
    if (!webhookSecret || !signatureHeader) {
      return false;
    }

    if (!signatureHeader.startsWith("sha256=")) {
      return false;
    }

    const expectedSig = signatureHeader.substring(7);
    const computedSig = createHmac("sha256", webhookSecret).update(payload, "utf8").digest("hex");

    if (expectedSig.length !== computedSig.length) {
      return false;
    }

    return timingSafeEqual(Buffer.from(expectedSig, "hex"), Buffer.from(computedSig, "hex"));
  }

  /**
   * Formats audit findings into GitHub Checks API annotations
   */
  public static toCheckAnnotations(findings: Array<DetectedSecret & { file: string }>): Array<{
    path: string;
    start_line: number;
    end_line: number;
    annotation_level: "notice" | "warning" | "failure";
    message: string;
    title: string;
  }> {
    return findings.map((f) => ({
      path: f.file,
      start_line: f.line || 1,
      end_line: f.line || 1,
      annotation_level: f.severity === "critical" || f.severity === "high" ? "failure" : "warning",
      title: `AgentShield: ${f.patternName}`,
      message: `Hardcoded credential [${f.patternId}] detected in diff. Redacted: ${f.redacted}`,
    }));
  }

  /**
   * Builds the GitHub Checks API payload based on CI audit results
   */
  public buildCheckRunPayload(
    auditResult: CiAuditResult,
    headSha: string,
    checkName = "AgentShield Security Gate",
  ): GitHubCheckRunPayload {
    const annotations = GitHubAppService.toCheckAnnotations(auditResult.findings);

    if (auditResult.passed) {
      return {
        name: checkName,
        head_sha: headSha,
        status: "completed",
        conclusion: "success",
        output: {
          title: "AgentShield Security Gate Passed",
          summary: `✅ Clean diff — 0 exposed secrets detected across ${auditResult.filesScanned} audited file(s). Safe for autonomous AI and team development.`,
        },
      };
    }

    return {
      name: checkName,
      head_sha: headSha,
      status: "completed",
      conclusion: "failure",
      output: {
        title: `AgentShield Blocked: ${auditResult.totalSecrets} Secret(s) Detected`,
        summary: `🚨 **Security Gate Failed**: Found ${auditResult.totalSecrets} hardcoded credential(s) in this commit. Autonomous AI agent egress or merge is blocked until credentials are removed.`,
        text: auditResult.markdownReport,
        annotations: annotations.slice(0, 50), // GitHub Checks API limits annotations to 50 per request
      },
    };
  }

  /**
   * Dispatches or updates a GitHub Check Run via GitHub REST API
   */
  public async publishCheckRun(
    repoFullName: string,
    checkPayload: GitHubCheckRunPayload,
    installationToken?: string,
  ): Promise<{ success: boolean; checkRunId?: number; error?: string }> {
    const token = installationToken || process.env.GITHUB_TOKEN;
    const apiBase =
      this.config.apiBaseUrl || process.env.GITHUB_API_URL || "https://api.github.com";

    if (!token) {
      return {
        success: false,
        error: "Missing GitHub authentication token for Check Run dispatch.",
      };
    }

    try {
      const res = await fetch(`${apiBase}/repos/${repoFullName}/check-runs`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "AgentShield-GitHub-App",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(checkPayload),
      });

      if (!res.ok) {
        return {
          success: false,
          error: `Failed to create check run: HTTP ${res.status}`,
        };
      }

      const data = (await res.json()) as { id: number };
      return { success: true, checkRunId: data.id };
    } catch (err: unknown) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  /**
   * Generates an automated security advisory acknowledgement message and invites
   * the researcher to the automated AgentShield bug bounty verification test harness.
   */
  public static buildSecurityAdvisoryAcknowledgement(
    advisory: { ghsa_id?: string; summary?: string; severity?: string },
    repoFullName = "RitualDev-Lab/AgentShield",
  ): {
    title: string;
    body: string;
    bountyHarnessCommand: string;
  } {
    const ghsaId = advisory.ghsa_id || "GHSA-PENDING";
    const bountyHarnessCommand = `npx @ritualdev-lab/agentshield bounty-verify "<exploit-payload>"`;

    const body = `### 🛡️ AgentShield Automated Security Advisory Triage Bot

Thank you for reporting this vulnerability to the **AgentShield Security Team** through GitHub Private Vulnerability Reporting.

- **Advisory ID**: \`${ghsaId}\`
- **Report Summary**: ${advisory.summary || "Security Vulnerability Report"}
- **Reported Severity**: \`${(advisory.severity || "high").toUpperCase()}\`
- **Target Repository**: [${repoFullName}](https://github.com/${repoFullName})

---

### ⚡ Instant Proof-of-Concept Verification Harness
We provide an automated, zero-install local verification test harness for security researchers. You can verify whether your proof-of-concept payload bypasses the active defense sandbox or secret redaction engine by running:

\`\`\`bash
${bountyHarnessCommand}
\`\`\`

- **Bounty Verification**: Confirmed reproducible zero-day bypasses and secret leak exploits are eligible for bounties funded via our **Community Security Bounty Fund**.
- **Transparency**: Once verified and patched, disclosures are recorded on the [AgentShield Public Transparency Ledger](https://agentshield.ritualdev.in/transparency) with full credit attributed to the researcher.
- **SLA**: Our security triage team reviews private advisories within 24 hours.

*AgentShield Security Operations — Zero-Leak Defense for AI Coding Agents*`;

    return {
      title: `AgentShield Triage: ${ghsaId} Acknowledged`,
      body,
      bountyHarnessCommand,
    };
  }
}
