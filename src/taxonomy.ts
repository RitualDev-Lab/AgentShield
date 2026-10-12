export interface SigmaRuleMetadata {
  id: string;
  title: string;
  status?: "stable" | "experimental" | "deprecated";
  description: string;
  author?: string;
  references?: string[];
  tags: {
    mitreAttack?: string[]; // e.g. ["T1552", "T1059"]
    mitreAtlas?: string[]; // e.g. ["AML.T0054", "AML.T0024"]
    owaspLlm?: string[]; // e.g. ["LLM06", "LLM02"]
  };
  severity: "critical" | "high" | "medium" | "low";
}

export interface SigmaPatternDetection {
  regex: string;
  category: "ai" | "cloud" | "saas" | "vcs" | "crypto" | "config" | "generic";
  prefix?: string;
  entropyCheck?: boolean;
}

export interface SigmaRule {
  meta: SigmaRuleMetadata;
  detection: SigmaPatternDetection;
}

export interface SarifPhysicalLocation {
  artifactLocation: {
    uri: string;
  };
  region?: {
    startLine: number;
    startColumn: number;
    endLine?: number;
    endColumn?: number;
  };
}

export interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: {
    text: string;
  };
  locations?: Array<{
    physicalLocation: SarifPhysicalLocation;
  }>;
  properties?: {
    mitreAtlas?: string[];
    owaspLlm?: string[];
    severity?: string;
  };
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          fullDescription?: { text: string };
          defaultConfiguration?: { level: "error" | "warning" | "note" };
          helpUri?: string;
          properties?: {
            tags?: string[];
          };
        }>;
      };
    };
    results: SarifResult[];
  }>;
}

export interface AgentConfigAuditIssue {
  id: string;
  file: string;
  severity: "critical" | "high" | "medium";
  category:
    | "excessive_permissions"
    | "insecure_transport"
    | "unrestricted_mcp"
    | "credential_exposure";
  title: string;
  description: string;
  recommendation: string;
  owaspLlm?: string;
  mitreAtlas?: string;
}

export interface AgentConfigAuditReport {
  timestamp: string;
  totalFilesAudited: number;
  issues: AgentConfigAuditIssue[];
  passed: boolean;
}
