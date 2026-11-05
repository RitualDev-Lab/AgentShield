import { createHmac } from "node:crypto";
import { type SiemEvent, SiemExporter } from "./siem.js";

function trimTrailingSlash(url: string): string {
  let u = url.trim();
  while (u.endsWith("/")) {
    u = u.slice(0, -1);
  }
  return u;
}

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

export interface DeviceAuthorizationResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

export interface DeviceTokenPollResult {
  status: "pending" | "slow_down" | "approved" | "expired" | "access_denied";
  token?: string;
  claims?: SsoUserClaims;
  error?: string;
}

/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628) Manager:
 * Enables terminal CLI users to authenticate via browser SSO with Okta, Google Workspace, Azure AD.
 */
export class DeviceAuthorizationFlow {
  private static readonly CHARSET = "BCDFGHJKLMNPQRSTVWXZ23456789";

  /**
   * Generates a standard RFC 8628 user code in format XXXX-XXXX
   * Uses cryptographically secure randomInt to eliminate modulo reduction bias.
   */
  public static generateUserCode(): string {
    const { randomInt } = require("node:crypto");
    let part1 = "";
    let part2 = "";
    for (let i = 0; i < 4; i++) {
      part1 += this.CHARSET[randomInt(0, this.CHARSET.length)];
      part2 += this.CHARSET[randomInt(0, this.CHARSET.length)];
    }
    return `${part1}-${part2}`;
  }

  /**
   * Initiates the device authorization flow.
   * If remote endpoint is specified, issues POST to oauth endpoint.
   * Otherwise provisions standard RitualDev SSO verification session.
   */
  public static async initiate(
    options: {
      endpoint?: string;
      orgId?: string;
      provider?: string;
    } = {},
  ): Promise<DeviceAuthorizationResponse> {
    const { randomBytes } = await import("node:crypto");
    const deviceCode = `ashield_dev_${randomBytes(24).toString("hex")}`;
    const userCode = this.generateUserCode();
    const verificationUri = "https://ritualdev.in/device";
    const verificationUriComplete = `${verificationUri}?user_code=${userCode}`;

    if (options.endpoint) {
      try {
        const res = await fetch(
          `${trimTrailingSlash(options.endpoint)}/oauth/v2/device/authorize`,
          {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
              client_id: "agentshield-cli",
              scope: "openid profile email rbac:rules",
              ...(options.orgId ? { org_id: options.orgId } : {}),
            }),
          },
        );
        if (res.ok) {
          return (await res.json()) as DeviceAuthorizationResponse;
        }
      } catch {
        // Fall back to default portal flow
      }
    }

    return {
      device_code: deviceCode,
      user_code: userCode,
      verification_uri: verificationUri,
      verification_uri_complete: verificationUriComplete,
      expires_in: 900, // 15 minutes
      interval: 3, // 3 seconds
    };
  }

  /**
   * Polls token endpoint until user approves in browser or token expires
   */
  public static async pollToken(
    deviceCode: string,
    options: {
      endpoint?: string;
      interval?: number;
      timeoutMs?: number;
      onPoll?: () => void;
    } = {},
  ): Promise<DeviceTokenPollResult> {
    const intervalSec = options.interval || 3;
    const timeoutMs = options.timeoutMs || 300_000; // 5 min default
    const startTime = Date.now();

    const targetUrl = options.endpoint
      ? `${trimTrailingSlash(options.endpoint)}/oauth/v2/token`
      : "https://ritualdev.in/api/device";

    while (Date.now() - startTime < timeoutMs) {
      if (options.onPoll) options.onPoll();
      await new Promise((resolve) => setTimeout(resolve, intervalSec * 1000));

      try {
        const res = await fetch(targetUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: deviceCode,
            client_id: "agentshield-cli",
          }),
        });

        if (res.ok) {
          const data = (await res.json()) as { access_token?: string; claims?: SsoUserClaims };
          if (data.access_token) {
            return {
              status: "approved",
              token: data.access_token,
              claims: data.claims,
            };
          }
        }

        const errData = (await res.json().catch(() => ({}))) as { error?: string };
        if (errData.error === "authorization_pending") {
          continue;
        } else if (errData.error === "slow_down") {
          await new Promise((resolve) => setTimeout(resolve, 2000));
          continue;
        } else if (errData.error === "expired_token") {
          return { status: "expired", error: "Device code expired. Please initiate login again." };
        } else if (errData.error === "access_denied") {
          return { status: "access_denied", error: "Authentication was rejected in the browser." };
        }
      } catch {
        // network retry
        continue;
      }
    }

    return { status: "expired", error: "Polling timed out waiting for browser authorization." };
  }
}
