import type { DetectedSecret } from "./types.js";

export interface SiemEvent {
  id: string;
  timestamp: string;
  eventType: "SECRET_LEAK_DETECTED" | "COMMAND_BLOCKED" | "VAULT_INJECTION";
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  actor: string;
  details: {
    ruleId?: string;
    ruleName?: string;
    redactedValue?: string;
    command?: string;
    file?: string;
    frameworks?: string[];
  };
}

export interface SiemExportOptions {
  format?: "json" | "cef" | "syslog";
  actor?: string;
  source?: string;
  frameworks?: string[];
}

export class SiemExporter {
  private defaultOptions: SiemExportOptions;

  constructor(defaultOptions: SiemExportOptions = {}) {
    this.defaultOptions = defaultOptions;
  }

  public exportEvent(event: SiemEvent, format?: "json" | "cef" | "syslog"): string {
    const fmt = format || this.defaultOptions.format || "cef";
    if (fmt === "json") return JSON.stringify(event, null, 2);
    if (fmt === "syslog") return SiemExporter.toSyslog(event);
    return SiemExporter.toCef(event);
  }

  /**
   * Formats a finding into Common Event Format (CEF) standard used by Splunk, Datadog, Sentinel.
   * Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
   */
  public static toCef(event: SiemEvent): string {
    const cefSeverity =
      event.severity === "critical"
        ? "10"
        : event.severity === "high"
          ? "7"
          : event.severity === "medium"
            ? "5"
            : "3";

    const extensions = [
      `msg=${JSON.stringify(event.details.ruleName || event.eventType)}`,
      `src=${event.source}`,
      `suser=${event.actor}`,
      `fname=${event.details.file || "unknown"}`,
      `cs1=${event.details.ruleId || "NONE"}`,
      "cs1Label=RuleId",
      `cs2=${event.details.redactedValue || "NONE"}`,
      "cs2Label=RedactedPayload",
    ].join(" ");

    return `CEF:0|RitualDev|AgentShield|1.0.0|${event.eventType}|${event.details.ruleName || event.eventType}|${cefSeverity}|${extensions}`;
  }

  /**
   * Formats event for syslog RFC 5424
   */
  public static toSyslog(event: SiemEvent): string {
    return `<134>1 ${event.timestamp} agentshield-daemon ${event.actor} - - - ${JSON.stringify(event)}`;
  }

  /**
   * Forwards incident event directly to Datadog Logs API via HTTPS
   */
  public static async forwardToDatadog(
    event: SiemEvent,
    config: { apiKey: string; site?: string; service?: string },
  ): Promise<{ delivered: boolean; statusCode?: number; error?: string }> {
    const site = config.site || "datadoghq.com";
    const url = `https://http-intake.logs.${site}/api/v2/logs`;
    try {
      const payload = [
        {
          ddsource: "agentshield",
          ddtags: `env:production,audit:zero-leak,severity:${event.severity}`,
          service: config.service || "agentshield-defense",
          message: SiemExporter.toCef(event),
          ...event,
        },
      ];
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "DD-API-KEY": config.apiKey,
          "User-Agent": "AgentShield-SIEM/1.0",
        },
        body: JSON.stringify(payload),
      });
      return { delivered: res.ok, statusCode: res.status };
    } catch (err: unknown) {
      return { delivered: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Forwards incident event directly to Splunk HTTP Event Collector (HEC)
   */
  public static async forwardToSplunk(
    event: SiemEvent,
    config: { hecUrl: string; token: string; index?: string },
  ): Promise<{ delivered: boolean; statusCode?: number; error?: string }> {
    let base = config.hecUrl.trim();
    while (base.endsWith("/")) {
      base = base.slice(0, -1);
    }
    const url = base.endsWith("/services/collector/event")
      ? base
      : `${base}/services/collector/event`;
    try {
      const payload = {
        time: Math.floor(Date.now() / 1000),
        source: "agentshield",
        sourcetype: "agentshield:incident",
        index: config.index || "security",
        event,
      };
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Splunk ${config.token}`,
          "User-Agent": "AgentShield-SIEM/1.0",
        },
        body: JSON.stringify(payload),
      });
      return { delivered: res.ok, statusCode: res.status };
    } catch (err: unknown) {
      return { delivered: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Forwards incident event to CloudWatch HTTPS endpoint or generic SIEM Webhook
   */
  public static async forwardToWebhook(
    event: SiemEvent,
    config: {
      url: string;
      secret?: string;
      format?: "json" | "cef" | "syslog";
      headers?: Record<string, string>;
    },
  ): Promise<{ delivered: boolean; statusCode?: number; error?: string }> {
    const format = config.format || "json";
    let body: string;
    let contentType = "application/json";

    if (format === "cef") {
      body = SiemExporter.toCef(event);
      contentType = "text/plain";
    } else if (format === "syslog") {
      body = SiemExporter.toSyslog(event);
      contentType = "text/plain";
    } else {
      body = JSON.stringify(event);
    }

    const headers: Record<string, string> = {
      "Content-Type": contentType,
      "User-Agent": "AgentShield-SIEM/1.0",
      ...(config.headers || {}),
    };

    if (config.secret) {
      const { createHmac } = await import("node:crypto");
      headers["X-AgentShield-Signature"] =
        `sha256=${createHmac("sha256", config.secret).update(body).digest("hex")}`;
    }

    try {
      const res = await fetch(config.url, {
        method: "POST",
        headers,
        body,
      });
      return { delivered: res.ok, statusCode: res.status };
    } catch (err: unknown) {
      return { delivered: false, error: err instanceof Error ? err.message : String(err) };
    }
  }

  /**
   * Builds a SIEM event object from a secret finding
   */
  public static createSecretLeakEvent(
    finding: DetectedSecret,
    options: SiemExportOptions = {},
  ): SiemEvent {
    return {
      id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      eventType: "SECRET_LEAK_DETECTED",
      severity: finding.severity,
      source: options.source || "AgentShield-CLI",
      actor: options.actor || process.env.USER || process.env.USERNAME || "autonomous-agent",
      details: {
        ruleId: finding.patternId,
        ruleName: finding.patternName,
        redactedValue: finding.redacted,
        file: finding.file,
        frameworks: options.frameworks || ["soc2", "pci_dss"],
      },
    };
  }

  /**
   * Builds a SIEM event object from a blocked agent command
   */
  public static createCommandBlockedEvent(
    command: string,
    reason: string,
    options: SiemExportOptions = {},
  ): SiemEvent {
    return {
      id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      eventType: "COMMAND_BLOCKED",
      severity: "critical",
      source: options.source || "AgentShield-Sandbox",
      actor: options.actor || process.env.USER || process.env.USERNAME || "autonomous-agent",
      details: {
        command,
        ruleName: reason,
        frameworks: options.frameworks || ["soc2", "iso27001"],
      },
    };
  }
}
