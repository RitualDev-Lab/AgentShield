import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { RemotePolicyPayload } from "./remote-policy.js";
import type { FleetAgentTelemetryReport } from "./control-plane.js";
import {
  EnterpriseWebhookStreamer,
  EnterpriseSsoValidator,
  type WebhookSubscription,
  type SsoUserClaims,
} from "./enterprise-sso.js";
import { SiemExporter } from "./siem.js";

export interface ControlPlaneIncidentEvent {
  id: string;
  orgId: string;
  agentId: string;
  agentRuntime: string;
  hostname: string;
  command?: string;
  ruleCategory?: string;
  reason?: string;
  severity: "critical" | "high" | "medium" | "info";
  timestamp: string;
}

export interface ControlPlaneServerOptions {
  port?: number;
  apiKey?: string;
  initialPolicy?: RemotePolicyPayload;
  ssoSigningSecret?: string;
  allowedOrgIds?: string[];
}

/**
 * Lightweight, zero-external-dependency Enterprise Control Plane Server MVP.
 * Provides REST endpoints for:
 * - GET  /api/v1/health
 * - GET  /api/v1/policies/:orgId
 * - PUT  /api/v1/policies/:orgId
 * - POST /api/v1/telemetry/heartbeat
 * - POST /api/v1/telemetry/incident
 * - GET  /api/v1/incidents
 * - GET  /api/v1/overview
 */
export class ControlPlaneServer {
  private server: Server | null = null;
  private policies: Map<string, RemotePolicyPayload> = new Map();
  private heartbeats: Map<string, FleetAgentTelemetryReport> = new Map();
  private incidents: ControlPlaneIncidentEvent[] = [];
  private apiKey: string;
  private port: number;
  public webhookStreamer: EnterpriseWebhookStreamer;
  public ssoValidator: EnterpriseSsoValidator;

  constructor(options: ControlPlaneServerOptions = {}) {
    this.port = options.port !== undefined ? options.port : 3000;
    this.apiKey = options.apiKey || "mock-enterprise-api-key";
    this.webhookStreamer = new EnterpriseWebhookStreamer();
    this.ssoValidator = new EnterpriseSsoValidator(
      options.ssoSigningSecret || "agentshield-enterprise-secret-key-2026",
      options.allowedOrgIds || [],
    );

    // Initialize default org policy if provided
    if (options.initialPolicy) {
      this.policies.set(options.initialPolicy.orgId, options.initialPolicy);
    }
  }

  public setPolicy(orgId: string, policy: RemotePolicyPayload): void {
    this.policies.set(orgId, policy);
  }

  public getPolicy(orgId: string): RemotePolicyPayload | undefined {
    return this.policies.get(orgId);
  }

  public getIncidents(): ControlPlaneIncidentEvent[] {
    return [...this.incidents];
  }

  public getHeartbeats(): FleetAgentTelemetryReport[] {
    return Array.from(this.heartbeats.values());
  }

  public async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.listen(this.port, () => {
        const address = this.server?.address();
        const actualPort = typeof address === "object" && address ? address.port : this.port;
        this.port = actualPort;
        resolve(actualPort);
      });

      this.server.on("error", (err) => reject(err));
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const parsedUrl = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = parsedUrl.pathname;
    const method = req.method || "GET";

    // Set CORS headers for browser dashboard access
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-AgentShield-Org");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Read request body helper
    const readBody = async (): Promise<string> => {
      return new Promise((resolve) => {
        let body = "";
        req.on("data", (chunk) => {
          body += chunk;
        });
        req.on("end", () => resolve(body));
      });
    };

    // Routing
    if (pathname === "/api/v1/health" && method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "healthy",
          service: "agentshield-control-plane",
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // GET /api/v1/policies/:orgId
    const policyGetMatch = pathname.match(/^\/api\/v1\/policies\/([^/]+)$/);
    if (policyGetMatch && method === "GET") {
      const orgId = decodeURIComponent(policyGetMatch[1]);
      const policy = this.policies.get(orgId);
      if (policy) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(policy));
      } else {
        // Fallback default policy if none explicitly provisioned
        const defaultPolicy: RemotePolicyPayload = {
          policyVersion: "2026.1.0",
          orgId,
          name: "Default Organization Policy",
          allowlist: [],
          entropyThreshold: 4.5,
          maskStyle: "token",
          customPatterns: [],
          enforceKernelSandbox: true,
          quarantineOnCanaryTrip: true,
          updatedAt: new Date().toISOString(),
        };
        this.policies.set(orgId, defaultPolicy);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(defaultPolicy));
      }
      return;
    }

    // PUT /api/v1/policies/:orgId
    if (policyGetMatch && method === "PUT") {
      const orgId = decodeURIComponent(policyGetMatch[1]);
      readBody().then((body) => {
        try {
          const payload = JSON.parse(body) as RemotePolicyPayload;
          payload.orgId = orgId;
          payload.updatedAt = new Date().toISOString();
          this.policies.set(orgId, payload);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, policy: payload }));
        } catch (e) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid JSON payload" }));
        }
      });
      return;
    }

    // POST /api/v1/telemetry/heartbeat
    if (pathname === "/api/v1/telemetry/heartbeat" && method === "POST") {
      readBody().then((body) => {
        try {
          const report = JSON.parse(body) as FleetAgentTelemetryReport;
          const key = `${report.agentId}@${report.hostname}`;
          this.heartbeats.set(key, report);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, registeredNodes: this.heartbeats.size }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid heartbeat payload" }));
        }
      });
      return;
    }

    // POST /api/v1/telemetry/incident
    if (pathname === "/api/v1/telemetry/incident" && method === "POST") {
      readBody().then((body) => {
        try {
          const event = JSON.parse(body) as Partial<ControlPlaneIncidentEvent>;
          const incident: ControlPlaneIncidentEvent = {
            id: `inc_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            orgId: event.orgId || "default",
            agentId: event.agentId || "unknown-agent",
            agentRuntime: event.agentRuntime || "generic",
            hostname: event.hostname || "localhost",
            command: event.command,
            ruleCategory: event.ruleCategory,
            reason: event.reason,
            severity: event.severity || "high",
            timestamp: new Date().toISOString(),
          };
          this.incidents.unshift(incident);
          // Retain last 500 incidents in memory
          if (this.incidents.length > 500) this.incidents.pop();

          // Stream incident out to all subscribed enterprise SIEM webhooks (Datadog, Splunk, Slack)
          const siemEvent = {
            id: incident.id,
            timestamp: incident.timestamp,
            eventType: "COMMAND_BLOCKED" as const,
            severity: incident.severity as "critical" | "high" | "medium" | "low",
            source: incident.hostname,
            actor: incident.agentId,
            details: {
              command: incident.command,
              ruleName: incident.reason,
            },
          };
          this.webhookStreamer.dispatchEvent(siemEvent).catch(() => {});

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, incidentId: incident.id }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid incident payload" }));
        }
      });
      return;
    }

    // POST /api/v1/webhooks/subscribe
    if (pathname === "/api/v1/webhooks/subscribe" && method === "POST") {
      readBody().then((body) => {
        try {
          const sub = JSON.parse(body) as WebhookSubscription;
          if (!sub.id || !sub.url || !sub.secret) {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Missing required webhook fields: id, url, secret" }));
            return;
          }
          this.webhookStreamer.addSubscription({
            ...sub,
            events: sub.events || ["*"],
            format: sub.format || "json",
            active: sub.active !== false,
          });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, subscriptionId: sub.id }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid webhook subscription payload" }));
        }
      });
      return;
    }

    // POST /api/v1/auth/sso/verify
    if (pathname === "/api/v1/auth/sso/verify" && method === "POST") {
      readBody().then((body) => {
        try {
          const { token } = JSON.parse(body) as { token: string };
          const result = this.ssoValidator.verifyToken(token);
          if (result.valid) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ valid: true, claims: result.claims }));
          } else {
            res.writeHead(401, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ valid: false, error: result.error }));
          }
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid verification payload" }));
        }
      });
      return;
    }

    // GET /api/v1/incidents
    if (pathname === "/api/v1/incidents" && method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ incidents: this.incidents }));
      return;
    }

    // GET /api/v1/overview
    if (pathname === "/api/v1/overview" && method === "GET") {
      const activeNodes = this.heartbeats.size;
      const totalBlocked = Array.from(this.heartbeats.values()).reduce(
        (sum, h) => sum + (h.totalCommandsBlocked || 0),
        0,
      );
      const totalRedacted = Array.from(this.heartbeats.values()).reduce(
        (sum, h) => sum + (h.totalSecretsRedacted || 0),
        0,
      );

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          activeNodes,
          totalBlocked,
          totalRedacted,
          recentIncidentsCount: this.incidents.length,
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // GET /api/v1/compliance/attestation
    if (pathname === "/api/v1/compliance/attestation" && method === "GET") {
      const { EnterpriseComplianceBundleGenerator } = await import("./enterprise-bundle.js");
      const orgName = parsedUrl.searchParams.get("org") || "Enterprise Fleet";
      const pkg = EnterpriseComplianceBundleGenerator.generateBundle(
        Array.from(this.heartbeats.values()),
        [],
        undefined,
        { organizationName: orgName },
      );

      const format = parsedUrl.searchParams.get("format");
      if (format === "markdown" || format === "md") {
        const md = EnterpriseComplianceBundleGenerator.toExecutiveMarkdown(pkg);
        res.writeHead(200, { "Content-Type": "text/markdown; charset=utf-8" });
        res.end(md);
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(pkg, null, 2));
      }
      return;
    }

    // POST /api/v1/github/webhook
    if (pathname === "/api/v1/github/webhook" && method === "POST") {
      const rawBody = await readBody();
      const signature = req.headers["x-hub-signature-256"] as string | undefined;
      const eventType = req.headers["x-github-event"] as string | undefined;

      const { GitHubAppService } = await import("./github-app.js");
      const appService = new GitHubAppService();

      // Check webhook signature if secret configured
      const secret = process.env.GITHUB_WEBHOOK_SECRET;
      if (secret && !appService.verifyWebhookSignature(rawBody, signature, secret)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid webhook HMAC signature" }));
        return;
      }

      let payload: unknown = {};
      try {
        payload = JSON.parse(rawBody || "{}");
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Malformed JSON payload" }));
        return;
      }

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          received: true,
          event: eventType || "unknown",
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // GET /api/v1/badges/:slug.svg (Dynamic SVG badge generator)
    if (pathname.startsWith("/api/v1/badges/") && pathname.endsWith(".svg") && method === "GET") {
      const { VerifiedBadgeGenerator } = await import("./badge-generator.js");
      const filename = pathname.replace("/api/v1/badges/", "").replace(".svg", "");
      const toolName = decodeURIComponent(filename).replace(/[-_]/g, " ");
      const tier = (parsedUrl.searchParams.get("tier") || "verified") as any;
      const svg = VerifiedBadgeGenerator.generateSvgBadge(toolName, { tier });

      res.writeHead(200, {
        "Content-Type": "image/svg+xml; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
      });
      res.end(svg);
      return;
    }

    // GET /api/v1/badges/verify (Cryptographic verification check)
    if (pathname === "/api/v1/badges/verify" && method === "GET") {
      const { VerifiedBadgeGenerator } = await import("./badge-generator.js");
      const tool = parsedUrl.searchParams.get("tool") || "";
      const repo = parsedUrl.searchParams.get("repo") || "";
      const tier = (parsedUrl.searchParams.get("tier") || "verified") as any;
      const hash = parsedUrl.searchParams.get("hash") || "";

      if (!tool || !repo || !hash) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Missing required query parameters: tool, repo, hash" }));
        return;
      }

      const isValid = VerifiedBadgeGenerator.verifyAuditRecord(tool, repo, tier, hash);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          valid: isValid,
          tool,
          tier,
          status: isValid ? "VERIFIED_ZERO_LEAK" : "SIGNATURE_MISMATCH",
          auditedBy: "AgentShield Security Engine",
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    // GET /api/v1/sponsorship/products (List available sponsor & audit tiers)
    if (pathname === "/api/v1/sponsorship/products" && method === "GET") {
      const { DodoPaymentsService } = await import("./dodo-payments.js");
      const dodo = new DodoPaymentsService();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ products: dodo.getAvailableProducts() }));
      return;
    }

    // POST /api/v1/sponsorship/checkout (Create Dodo Payments checkout session)
    if (pathname === "/api/v1/sponsorship/checkout" && method === "POST") {
      const { DodoPaymentsService } = await import("./dodo-payments.js");
      const dodo = new DodoPaymentsService();
      const rawBody = await readBody();
      try {
        const body = JSON.parse(rawBody || "{}");
        const session = await dodo.createCheckoutSession({
          tierId: body.tierId || "sponsor-verified-badge",
          toolName: body.toolName,
          repoUrl: body.repoUrl,
          customerEmail: body.customerEmail,
          customerName: body.customerName,
          returnUrl: body.returnUrl,
        });

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(session));
      } catch (e: any) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: e?.message || "Failed to create checkout session" }));
      }
      return;
    }

    // GET /api/v1/transparency/ledger (Public financial transparency audit ledger)
    if (pathname === "/api/v1/transparency/ledger" && method === "GET") {
      const { PublicTransparencyLedger } = await import("./transparency-ledger.js");
      const ledger = new PublicTransparencyLedger();
      const summary = ledger.getSummary();
      const entries = ledger.getEntries();

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ summary, entries }, null, 2));
      return;
    }

    // GET /api/v1/badges/patron/:username.svg (Dynamic patron backer badge generator)
    if (pathname.startsWith("/api/v1/badges/patron/") && pathname.endsWith(".svg") && method === "GET") {
      const { PublicTransparencyLedger } = await import("./transparency-ledger.js");
      const rawUser = pathname.replace("/api/v1/badges/patron/", "").replace(".svg", "");
      const username = decodeURIComponent(rawUser);
      const tier = parsedUrl.searchParams.get("tier") || "Supporter";
      const svg = PublicTransparencyLedger.generatePatronSvgBadge(username, tier);

      res.writeHead(200, {
        "Content-Type": "image/svg+xml; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
      });
      res.end(svg);
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Endpoint not found" }));
  }
}
