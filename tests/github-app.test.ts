import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import { after, before, describe, it } from "node:test";
import type { CiAuditResult } from "../src/ci.js";
import { ControlPlaneServer } from "../src/control-plane-server.js";
import { GitHubAppService } from "../src/github-app.js";

describe("Phase 4: GitHub App Service & Multi-Tenant Checks API Suite", () => {
  const secretKey = "webhook-test-secret-12345";
  const appService = new GitHubAppService({ webhookSecret: secretKey });

  const mockPassingCi: CiAuditResult = {
    passed: true,
    totalSecrets: 0,
    criticalCount: 0,
    highCount: 0,
    filesScanned: 3,
    findings: [],
    markdownReport: "## 🛡️ AgentShield Clean Diff",
  };

  const mockFailingCi: CiAuditResult = {
    passed: false,
    totalSecrets: 1,
    criticalCount: 1,
    highCount: 0,
    filesScanned: 2,
    findings: [
      {
        patternId: "ANTHROPIC_API_KEY",
        patternName: "Anthropic Claude API Key",
        category: "ai",
        severity: "critical",
        raw: "sk-ant-api03-abcdef1234567890",
        redacted: "[AGENT_SHIELD:ANTHROPIC_API_KEY:4b1e]",
        line: 18,
        column: 10,
        file: "src/llm/client.ts",
      },
    ],
    markdownReport: "## 🚨 Secrets Detected",
  };

  describe("1. Webhook Signature Verification (X-Hub-Signature-256)", () => {
    it("should accept authentic GitHub App webhook payloads with valid HMAC-SHA256 signature", () => {
      const payload = JSON.stringify({ action: "opened", repository: { name: "AgentShield" } });
      const signature = `sha256=${createHmac("sha256", secretKey).update(payload).digest("hex")}`;

      const isValid = appService.verifyWebhookSignature(payload, signature, secretKey);
      assert.strictEqual(isValid, true);
    });

    it("should reject tampered webhook payloads", () => {
      const payload = JSON.stringify({ action: "opened" });
      const tamperedPayload = JSON.stringify({ action: "deleted" });
      const signature = `sha256=${createHmac("sha256", secretKey).update(payload).digest("hex")}`;

      const isValid = appService.verifyWebhookSignature(tamperedPayload, signature, secretKey);
      assert.strictEqual(isValid, false);
    });

    it("should reject payloads with invalid signature format or missing header", () => {
      const payload = JSON.stringify({ test: true });
      assert.strictEqual(appService.verifyWebhookSignature(payload, undefined, secretKey), false);
      assert.strictEqual(
        appService.verifyWebhookSignature(payload, "invalid-format", secretKey),
        false,
      );
    });
  });

  describe("2. Checks API Payload Builder", () => {
    it("should construct successful Check Run payload when diff is clean", () => {
      const checkPayload = appService.buildCheckRunPayload(mockPassingCi, "commit-sha-12345");
      assert.strictEqual(checkPayload.name, "AgentShield Security Gate");
      assert.strictEqual(checkPayload.head_sha, "commit-sha-12345");
      assert.strictEqual(checkPayload.status, "completed");
      assert.strictEqual(checkPayload.conclusion, "success");
      assert.ok(checkPayload.output?.title.includes("Passed"));
      assert.strictEqual(checkPayload.output?.annotations, undefined);
    });

    it("should construct failure Check Run payload with structured annotations when secrets leaked", () => {
      const checkPayload = appService.buildCheckRunPayload(mockFailingCi, "commit-sha-67890");
      assert.strictEqual(checkPayload.name, "AgentShield Security Gate");
      assert.strictEqual(checkPayload.head_sha, "commit-sha-67890");
      assert.strictEqual(checkPayload.status, "completed");
      assert.strictEqual(checkPayload.conclusion, "failure");
      assert.ok(checkPayload.output?.title.includes("Blocked"));
      assert.strictEqual(checkPayload.output?.annotations?.length, 1);

      const annotation = checkPayload.output?.annotations?.[0];
      assert.strictEqual(annotation?.path, "src/llm/client.ts");
      assert.strictEqual(annotation?.start_line, 18);
      assert.strictEqual(annotation?.annotation_level, "failure");
      assert.ok(annotation?.title.includes("Anthropic Claude API Key"));
      assert.ok(annotation?.message.includes("Redacted"));
    });
  });

  describe("3. REST API Check Run Publisher", () => {
    let mockServer: Server;
    let mockApiUrl: string;
    let postedCheckRuns: unknown[] = [];

    before(async () => {
      mockServer = createServer((req, res) => {
        const url = new URL(req.url || "/", `http://${req.headers.host}`);
        if (req.method === "POST" && url.pathname.includes("/check-runs")) {
          let body = "";
          req.on("data", (chunk) => {
            body += chunk;
          });
          req.on("end", () => {
            const data = JSON.parse(body);
            postedCheckRuns.push(data);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ id: 501, ...data }));
          });
          return;
        }
        res.writeHead(404);
        res.end();
      });

      await new Promise<void>((resolve) => {
        mockServer.listen(0, () => resolve());
      });
      const addr = mockServer.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      mockApiUrl = `http://localhost:${port}`;
    });

    after(async () => {
      await new Promise<void>((resolve) => mockServer.close(() => resolve()));
    });

    it("should dispatch check run payload to GitHub REST API endpoint", async () => {
      postedCheckRuns = [];
      const service = new GitHubAppService({ apiBaseUrl: mockApiUrl });
      const checkPayload = service.buildCheckRunPayload(mockFailingCi, "sha-abc");

      const result = await service.publishCheckRun(
        "RitualDev-Lab/AgentShield",
        checkPayload,
        "mock-installation-token",
      );

      assert.strictEqual(result.success, true);
      assert.strictEqual(result.checkRunId, 501);
      assert.strictEqual(postedCheckRuns.length, 1);
    });
  });

  describe("4. ControlPlaneServer GitHub Webhook Integration", () => {
    it("should accept authenticated GitHub App webhooks on POST /api/v1/github/webhook", async () => {
      const server = new ControlPlaneServer({ port: 0 });
      const port = await server.start();
      const webhookSecret = "test-webhook-secret-999";
      process.env.GITHUB_WEBHOOK_SECRET = webhookSecret;

      try {
        const payload = JSON.stringify({
          action: "opened",
          repository: { full_name: "RitualDev-Lab/AgentShield" },
        });
        const signature = `sha256=${createHmac("sha256", webhookSecret).update(payload).digest("hex")}`;

        const res = await fetch(`http://localhost:${port}/api/v1/github/webhook`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": signature,
          },
          body: payload,
        });

        assert.strictEqual(res.status, 200);
        const data = (await res.json()) as { received: boolean; event: string };
        assert.strictEqual(data.received, true);
        assert.strictEqual(data.event, "pull_request");
      } finally {
        process.env.GITHUB_WEBHOOK_SECRET = undefined;
        await server.stop();
      }
    });
  });
});
