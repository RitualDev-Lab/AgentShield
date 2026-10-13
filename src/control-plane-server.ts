import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import type { RemotePolicyPayload } from "./remote-policy.js";
import type { FleetAgentTelemetryReport } from "./control-plane.js";

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

  constructor(options: ControlPlaneServerOptions = {}) {
    this.port = options.port || 3000;
    this.apiKey = options.apiKey || "mock-enterprise-api-key";

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

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
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
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: true, incidentId: incident.id }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid incident payload" }));
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

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Endpoint not found" }));
  }
}
