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
