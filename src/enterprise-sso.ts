import { createHmac } from "node:crypto";
import { type SiemEvent, SiemExporter } from "./siem.js";

export interface WebhookSubscription {
  id: string;
  url: string;
  secret: string; // HMAC signing secret
  events: Array<"SECRET_LEAK_DETECTED" | "COMMAND_BLOCKED" | "VAULT_INJECTION" | "*">;
  format: "json" | "cef" | "syslog";
  headers?: Record<string, string>;
  active: boolean;
}

export interface WebhookDispatchResult {
  subscriptionId: string;
  url: string;
  delivered: boolean;
  statusCode?: number;
  durationMs: number;
  error?: string;
}

export interface SsoUserClaims {
  sub: string;
  email: string;
  name: string;
  orgId: string;
  roles: Array<"admin" | "security_auditor" | "developer">;
  provider: "saml" | "oidc" | "google" | "okta" | "azure_ad";
}

export interface SsoTokenVerificationResult {
  valid: boolean;
  claims?: SsoUserClaims;
  error?: string;
}

/**
 * Enterprise Webhook Streamer & SIEM Dispatcher:
 * Delivers cryptographic HMAC-SHA256 signed incident streams to enterprise SIEM platforms:
 * - Datadog, Splunk (HEC), AWS EventBridge, Slack/Teams webhooks.
 */
export class EnterpriseWebhookStreamer {
  private subscriptions: Map<string, WebhookSubscription> = new Map();

  constructor(initialSubscriptions: WebhookSubscription[] = []) {
    for (const sub of initialSubscriptions) {
      this.subscriptions.set(sub.id, sub);
    }
  }

  public addSubscription(sub: WebhookSubscription): void {
    this.subscriptions.set(sub.id, sub);
  }

  public removeSubscription(id: string): boolean {
    return this.subscriptions.delete(id);
  }

  public getSubscriptions(): WebhookSubscription[] {
    return Array.from(this.subscriptions.values());
  }

  /**
   * Generates HMAC-SHA256 signature header for webhook payloads
   */
  public static signPayload(payload: string, secret: string): string {
    return createHmac("sha256", secret).update(payload).digest("hex");
  }

  /**
   * Dispatches an event to all matched active webhook subscriptions
   */
  public async dispatchEvent(event: SiemEvent): Promise<WebhookDispatchResult[]> {
    const results: WebhookDispatchResult[] = [];
    const activeSubs = Array.from(this.subscriptions.values()).filter((s) => s.active);

    for (const sub of activeSubs) {
      if (!sub.events.includes("*") && !sub.events.includes(event.eventType)) {
        continue;
      }

      const exporter = new SiemExporter({ format: sub.format });
      const serialized = exporter.exportEvent(event, sub.format);
      const signature = EnterpriseWebhookStreamer.signPayload(serialized, sub.secret);

      const startTime = Date.now();
      try {
        const response = await fetch(sub.url, {
          method: "POST",
          headers: {
            "Content-Type": sub.format === "json" ? "application/json" : "text/plain",
            "X-AgentShield-Signature": `sha256=${signature}`,
            "X-AgentShield-Event": event.eventType,
            "User-Agent": "AgentShield-SIEM-Streamer",
            ...(sub.headers || {}),
          },
          body: serialized,
        });

        results.push({
          subscriptionId: sub.id,
          url: sub.url,
          delivered: response.ok,
          statusCode: response.status,
          durationMs: Date.now() - startTime,
        });
      } catch (err: unknown) {
        results.push({
          subscriptionId: sub.id,
          url: sub.url,
          delivered: false,
          durationMs: Date.now() - startTime,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return results;
  }
}

/**
 * Enterprise Single Sign-On (SSO) & RBAC Validator:
 * Validates corporate bearer tokens and maps permissions for Okta, Azure AD, and Google Workspace.
 */
export class EnterpriseSsoValidator {
  private signingSecret: string;
  private allowedOrgIds: Set<string>;

  constructor(signingSecret: string, allowedOrgIds: string[] = []) {
    this.signingSecret = signingSecret;
    this.allowedOrgIds = new Set(allowedOrgIds);
  }

  /**
   * Validates corporate SSO authentication token and extracts RBAC roles
   */
  public verifyToken(token: string): SsoTokenVerificationResult {
    if (!token || typeof token !== "string") {
      return { valid: false, error: "Missing or invalid token string" };
    }

    const parts = token.split(".");
    // Support standard 3-part JWT or enterprise bearer token
    if (parts.length === 3) {
      try {
        const [headerB64, payloadB64, sigB64] = parts;
        const expectedSig = createHmac("sha256", this.signingSecret)
          .update(`${headerB64}.${payloadB64}`)
          .digest("base64url");

        if (sigB64 !== expectedSig) {
          return { valid: false, error: "Invalid cryptographic token signature" };
        }

        const payloadJson = Buffer.from(payloadB64, "base64url").toString("utf8");
        const claims = JSON.parse(payloadJson) as SsoUserClaims;

        if (this.allowedOrgIds.size > 0 && !this.allowedOrgIds.has(claims.orgId)) {
          return { valid: false, error: `Organization '${claims.orgId}' is not authorized` };
        }

        return { valid: true, claims };
      } catch {
        return { valid: false, error: "Malformed JWT payload structure" };
      }
    }

    return { valid: false, error: "Unsupported token format: Expected standard compact JWT" };
  }

  /**
   * Helper to sign an SSO token for testing, staging, and local cluster development
   */
  public issueMockToken(claims: SsoUserClaims): string {
    const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const signature = createHmac("sha256", this.signingSecret)
      .update(`${header}.${payload}`)
      .digest("base64url");

    return `${header}.${payload}.${signature}`;
  }
}
