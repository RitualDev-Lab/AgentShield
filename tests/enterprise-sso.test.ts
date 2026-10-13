import assert from "node:assert";
import { createServer, type Server } from "node:http";
import { describe, it, before, after } from "node:test";
import {
  EnterpriseWebhookStreamer,
  EnterpriseSsoValidator,
  type WebhookSubscription,
  type SsoUserClaims,
} from "../src/enterprise-sso.js";
import { ControlPlaneServer } from "../src/control-plane-server.js";
import { SiemExporter } from "../src/siem.js";

describe("Phase 3: SIEM Streaming, Webhooks & Enterprise SSO Suite", () => {
  let webhookReceiver: Server;
  let webhookReceiverPort: number;
  let receivedWebhooks: Array<{
    body: string;
    headers: Record<string, string | string[] | undefined>;
  }> = [];

  const secretKey = "webhook-test-shared-secret-999";
  const ssoSecret = "enterprise-sso-master-key-xyz";

  before(async () => {
    // Start a mock external SIEM receiver endpoint (representing Datadog/Splunk/Slack)
    receivedWebhooks = [];
    webhookReceiver = createServer(async (req, res) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        receivedWebhooks.push({ body, headers: req.headers });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ acknowledged: true }));
      });
    });

    await new Promise<void>((resolve) => {
      webhookReceiver.listen(0, () => {
        const address = webhookReceiver.address();
        webhookReceiverPort = typeof address === "object" && address ? address.port : 0;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => webhookReceiver.close(() => resolve()));
  });

  describe("1. Enterprise Webhook Streaming & SIEM Exporters", () => {
    it("should compute valid HMAC-SHA256 signatures for webhook payloads", () => {
      const payload = JSON.stringify({ event: "SECRET_LEAK_DETECTED", severity: "critical" });
      const sig = EnterpriseWebhookStreamer.signPayload(payload, secretKey);
      assert.strictEqual(typeof sig, "string");
      assert.strictEqual(sig.length, 64); // 256 bits = 64 hex characters
    });

    it("should stream signed incident payloads to registered SIEM webhooks", async () => {
      const streamer = new EnterpriseWebhookStreamer();
      const sub: WebhookSubscription = {
        id: "sub_datadog_siem",
        url: `http://localhost:${webhookReceiverPort}/webhook/datadog`,
        secret: secretKey,
        events: ["COMMAND_BLOCKED"],
        format: "json",
        active: true,
      };
      streamer.addSubscription(sub);

      const siemEvent = SiemExporter.createCommandBlockedEvent(
        "cat .env",
        "Blocked credential file read",
        {
          source: "agent-node-macbook",
          actor: "claude-code",
        },
      );

      const results = await streamer.dispatchEvent(siemEvent);
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].delivered, true);
      assert.strictEqual(results[0].statusCode, 200);

      assert.strictEqual(receivedWebhooks.length > 0, true);
      const lastPayload = receivedWebhooks[receivedWebhooks.length - 1];
      assert.strictEqual(lastPayload.headers["x-agentshield-event"], "COMMAND_BLOCKED");
      assert.strictEqual(typeof lastPayload.headers["x-agentshield-signature"], "string");
    });
  });

  describe("2. Enterprise SSO & RBAC Role Validation", () => {
    const ssoValidator = new EnterpriseSsoValidator(ssoSecret, ["org_acme_corp"]);

    it("should issue and verify valid compact JWT SSO tokens", () => {
      const claims: SsoUserClaims = {
        sub: "usr_alice_secops",
        email: "alice@acmecorp.com",
        name: "Alice Security",
        orgId: "org_acme_corp",
        roles: ["admin", "security_auditor"],
        provider: "okta",
      };

      const token = ssoValidator.issueMockToken(claims);
      assert.strictEqual(typeof token, "string");

      const result = ssoValidator.verifyToken(token);
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.claims?.email, "alice@acmecorp.com");
      assert.strictEqual(result.claims?.roles.includes("security_auditor"), true);
      assert.strictEqual(result.claims?.provider, "okta");
    });

    it("should reject tampered SSO tokens with invalid signatures", () => {
      const claims: SsoUserClaims = {
        sub: "usr_attacker",
        email: "attacker@external.io",
        name: "Attacker",
        orgId: "org_acme_corp",
        roles: ["admin"],
        provider: "oidc",
      };

      const token = ssoValidator.issueMockToken(claims);
      const [header, payload] = token.split(".");
      const forgedToken = `${header}.${payload}.forged_invalid_signature_xyz`;

      const result = ssoValidator.verifyToken(forgedToken);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.error?.includes("signature"), true);
    });

    it("should reject valid tokens from unauthorized foreign organizations", () => {
      const claims: SsoUserClaims = {
        sub: "usr_foreign",
        email: "bob@othercorp.com",
        name: "Bob Other",
        orgId: "org_unauthorized_corp",
        roles: ["developer"],
        provider: "azure_ad",
      };

      const token = ssoValidator.issueMockToken(claims);
      const result = ssoValidator.verifyToken(token);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.error?.includes("not authorized"), true);
    });
  });

  describe("3. Control Plane End-to-End SSO & Webhook Subscription", () => {
    let server: ControlPlaneServer;
    let serverPort: number;

    before(async () => {
      server = new ControlPlaneServer({
        port: 0,
        ssoSigningSecret: ssoSecret,
        allowedOrgIds: ["org_acme_corp"],
      });
      serverPort = await server.start();
    });

    after(async () => {
      await server.stop();
    });

    it("should allow subscribing SIEM webhooks via POST /api/v1/webhooks/subscribe", async () => {
      const res = await fetch(`http://localhost:${serverPort}/api/v1/webhooks/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: "sub_splunk_cloud",
          url: `http://localhost:${webhookReceiverPort}/webhook/splunk`,
          secret: secretKey,
          events: ["*"],
          format: "json",
        }),
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as { success: boolean; subscriptionId: string };
      assert.strictEqual(data.success, true);
      assert.strictEqual(data.subscriptionId, "sub_splunk_cloud");
    });

    it("should authenticate tokens through POST /api/v1/auth/sso/verify", async () => {
      const claims: SsoUserClaims = {
        sub: "usr_carol",
        email: "carol@acmecorp.com",
        name: "Carol Admin",
        orgId: "org_acme_corp",
        roles: ["admin"],
        provider: "google",
      };
      const token = server.ssoValidator.issueMockToken(claims);

      const res = await fetch(`http://localhost:${serverPort}/api/v1/auth/sso/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      assert.strictEqual(res.status, 200);
      const data = (await res.json()) as { valid: boolean; claims: SsoUserClaims };
      assert.strictEqual(data.valid, true);
      assert.strictEqual(data.claims.email, "carol@acmecorp.com");
    });
  });
});
