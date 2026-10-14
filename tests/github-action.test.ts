import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { after, before, describe, it } from "node:test";
import type { CiAuditResult } from "../src/ci.js";
import { GitHubActionBot } from "../src/github-action.js";

describe("Phase 2: GitHub Action Hardening & PR Review Bot Suite", () => {
  const mockPassingResult: CiAuditResult = {
    passed: true,
    totalSecrets: 0,
    criticalCount: 0,
    highCount: 0,
    filesScanned: 4,
    findings: [],
    markdownReport: "## 🛡️ AgentShield CI/CD Security Gate Report\n### ✅ 0 Leaked Secrets Detected",
  };

  const mockFailingResult: CiAuditResult = {
    passed: false,
    totalSecrets: 2,
    criticalCount: 1,
    highCount: 1,
    filesScanned: 5,
    findings: [
      {
        patternId: "OPENAI_API_KEY",
        patternName: "OpenAI Secret Key",
        category: "ai",
        severity: "critical",
        raw: "sk-proj-test1234567890",
        redacted: "[AGENT_SHIELD:OPENAI_API_KEY:6f8d]",
        line: 14,
        column: 22,
        file: "src/openai.ts",
      },
      {
        patternId: "GITHUB_PAT",
        patternName: "GitHub Personal Access Token",
        category: "vcs",
        severity: "high",
        raw: "ghp_mocktoken1234567890",
        redacted: "[AGENT_SHIELD:GITHUB_PAT:12ab]",
        line: 42,
        column: 5,
        file: "config/auth.ts",
      },
    ],
    markdownReport:
      "## 🛡️ AgentShield CI/CD Security Gate Report\n### 🚨 2 Exposed Secret(s) Detected in Diff!",
  };

  it("should format findings into GitHub Actions inline annotations", () => {
    const annotations = GitHubActionBot.formatAnnotations(mockFailingResult.findings);
    assert.strictEqual(annotations.length, 2);

    assert.strictEqual(
      annotations[0],
      "::error file=src/openai.ts,line=14,col=22,title=AgentShield: OpenAI Secret Key Exposed::Secret detected (CRITICAL) [OPENAI_API_KEY]. Redacted: [AGENT_SHIELD:OPENAI_API_KEY:6f8d]",
    );
    assert.strictEqual(
      annotations[1],
      "::error file=config/auth.ts,line=42,col=5,title=AgentShield: GitHub Personal Access Token Exposed::Secret detected (HIGH) [GITHUB_PAT]. Redacted: [AGENT_SHIELD:GITHUB_PAT:12ab]",
    );
  });

  it("should generate clean, executive PR comment for passing CI audits", () => {
    const comment = GitHubActionBot.generatePrComment(mockPassingResult, "abcdef123456");
    assert.ok(comment.includes(GitHubActionBot.PR_COMMENT_TAG));
    assert.ok(comment.includes("### ✅ **Security Gate Passed**"));
    assert.ok(comment.includes("- **Files Audited**: `4`"));
    assert.ok(comment.includes("- **Commit Evaluated**: `abcdef1`"));
    assert.ok(!comment.includes("Exposed Secret(s)"));
  });

  it("should generate detailed warning table PR comment for failing CI audits", () => {
    const comment = GitHubActionBot.generatePrComment(mockFailingResult, "fedcba987654");
    assert.ok(comment.includes(GitHubActionBot.PR_COMMENT_TAG));
    assert.ok(comment.includes("### 🚨 **Security Gate Failed** — 2 Exposed Secret(s) Detected!"));
    assert.ok(
      comment.includes(
        "| `src/openai.ts` | **OpenAI Secret Key** | `CRITICAL` | `[AGENT_SHIELD:OPENAI_API_KEY:6f8d]` |",
      ),
    );
    assert.ok(
      comment.includes(
        "| `config/auth.ts` | **GitHub Personal Access Token** | `HIGH` | `[AGENT_SHIELD:GITHUB_PAT:12ab]` |",
      ),
    );
    assert.ok(comment.includes("Recommended Action"));
  });

  describe("Mock GitHub REST API interactions", () => {
    let server: Server;
    let mockApiUrl: string;
    let commentsDatabase: Array<{ id: number; body: string }> = [];

    before(async () => {
      server = createServer((req, res) => {
        const url = new URL(req.url || "/", `http://${req.headers.host}`);

        // Route: GET /repos/:owner/:repo/issues/:issue_number/comments
        if (req.method === "GET" && url.pathname.includes("/comments")) {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify(commentsDatabase));
          return;
        }

        // Route: POST /repos/:owner/:repo/issues/:issue_number/comments
        if (req.method === "POST" && url.pathname.includes("/comments")) {
          let body = "";
          req.on("data", (chunk) => {
            body += chunk;
          });
          req.on("end", () => {
            const data = JSON.parse(body);
            const newComment = { id: 101, body: data.body };
            commentsDatabase.push(newComment);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(newComment));
          });
          return;
        }

        // Route: PATCH /repos/:owner/:repo/issues/comments/:comment_id
        if (req.method === "PATCH" && url.pathname.includes("/issues/comments/")) {
          let body = "";
          req.on("data", (chunk) => {
            body += chunk;
          });
          req.on("end", () => {
            const data = JSON.parse(body);
            const comment = commentsDatabase.find((c) => c.id === 101);
            if (comment) {
              comment.body = data.body;
            }
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ id: 101, body: data.body }));
          });
          return;
        }

        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        server.listen(0, () => resolve());
      });
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      mockApiUrl = `http://localhost:${port}`;
    });

    after(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it("should create new PR comment on initial CI run", async () => {
      commentsDatabase = [];
      const res = await GitHubActionBot.postOrUpdatePrComment(mockFailingResult, {
        token: "fake-gh-token",
        repo: "RitualDev-Lab/AgentShield",
        issueNumber: 42,
        apiBaseUrl: mockApiUrl,
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, "created");
      assert.strictEqual(res.commentId, 101);
      assert.strictEqual(commentsDatabase.length, 1);
      assert.ok(commentsDatabase[0].body.includes("Security Gate Failed"));
    });

    it("should update existing sticky PR comment on subsequent commit pushes", async () => {
      assert.strictEqual(commentsDatabase.length, 1);
      const res = await GitHubActionBot.postOrUpdatePrComment(mockPassingResult, {
        token: "fake-gh-token",
        repo: "RitualDev-Lab/AgentShield",
        issueNumber: 42,
        apiBaseUrl: mockApiUrl,
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.action, "updated");
      assert.strictEqual(res.commentId, 101);
      assert.strictEqual(commentsDatabase.length, 1);
      assert.ok(commentsDatabase[0].body.includes("Security Gate Passed"));
    });

    it("should gracefully handle missing credentials and skip comment posting", async () => {
      const res = await GitHubActionBot.postOrUpdatePrComment(mockPassingResult, {
        token: "",
        repo: "",
        apiBaseUrl: mockApiUrl,
      });

      assert.strictEqual(res.success, false);
      assert.strictEqual(res.action, "skipped");
      assert.ok(res.error?.includes("Missing required GitHub credentials"));
    });
  });
});
