import type { AgentConfigAuditIssue, SarifLog, SarifResult } from "./taxonomy.js";
import type { DetectedSecret } from "./types.js";
import { AGENTSHIELD_VERSION } from "./version.js";

/**
 * Generates OASIS SARIF 2.1.0 formatted vulnerability reports
 * for native ingestion by GitHub Code Scanning, SonarQube, and CI dashboards.
 */
export class SarifFormatter {
  private defaultToolName: string;

  constructor(defaultToolName = "AgentShield") {
    this.defaultToolName = defaultToolName;
  }

  public format(
    secrets: Array<DetectedSecret & { file?: string }> = [],
    configIssues: AgentConfigAuditIssue[] = [],
  ): SarifLog {
    return SarifFormatter.generateSarif(secrets, configIssues);
  }

  public static generateSarif(
    secrets: Array<DetectedSecret & { file?: string }> = [],
    configIssues: AgentConfigAuditIssue[] = [],
  ): SarifLog {
    const results: SarifResult[] = [];
    const rulesMap = new Map<
      string,
      {
        id: string;
        name: string;
        shortDescription: { text: string };
        properties?: { tags?: string[] };
      }
    >();

    // 1. Process Secret Findings
    for (const secret of secrets) {
      const ruleId = secret.patternId || "AS-SECRET-GENERIC";
      if (!rulesMap.has(ruleId)) {
        rulesMap.set(ruleId, {
          id: ruleId,
          name: secret.patternName || "Exposed Secret",
          shortDescription: {
            text: `Detected exposed secret token: ${secret.patternName}`,
          },
          properties: {
            tags: ["security", "secrets", "OWASP-LLM06", "MITRE-AML.T0024"],
          },
        });
      }

      const sarifLevel =
        secret.severity === "critical" || secret.severity === "high" ? "error" : "warning";

      results.push({
        ruleId,
        level: sarifLevel,
        message: {
          text: `Exposed ${secret.patternName} detected. Sanitized preview: ${secret.redacted}`,
        },
        locations: secret.file
          ? [
              {
                physicalLocation: {
                  artifactLocation: { uri: secret.file },
                  region: {
                    startLine: secret.line || 1,
                    startColumn: secret.column || 1,
                  },
                },
              },
            ]
          : undefined,
        properties: {
          severity: secret.severity,
          owaspLlm: ["LLM06"],
          mitreAtlas: ["AML.T0024"],
        },
      });
    }

    // 2. Process Configuration Issues
    for (const issue of configIssues) {
      if (!rulesMap.has(issue.id)) {
        rulesMap.set(issue.id, {
          id: issue.id,
          name: issue.title,
          shortDescription: { text: issue.description },
          properties: {
            tags: [
              "security",
              "configuration",
              issue.owaspLlm ? `OWASP-${issue.owaspLlm}` : "OWASP-LLM06",
              issue.mitreAtlas ? `MITRE-${issue.mitreAtlas}` : "MITRE-AML.T0054",
            ],
          },
        });
      }

      const sarifLevel = issue.severity === "critical" ? "error" : "warning";

      results.push({
        ruleId: issue.id,
        level: sarifLevel,
        message: {
          text: `${issue.title}: ${issue.description} Recommendation: ${issue.recommendation}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: issue.file },
            },
          },
        ],
        properties: {
          severity: issue.severity,
          owaspLlm: issue.owaspLlm ? [issue.owaspLlm] : undefined,
          mitreAtlas: issue.mitreAtlas ? [issue.mitreAtlas] : undefined,
        },
      });
    }

    return {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "AgentShield",
              version: AGENTSHIELD_VERSION,
              informationUri: "https://github.com/RitualDev-Lab/AgentShield",
              rules: Array.from(rulesMap.values()),
            },
          },
          results,
        },
      ],
    };
  }
}
