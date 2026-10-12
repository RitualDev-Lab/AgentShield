import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { SecretPattern } from "./types.js";

export interface AgentShieldConfig {
  version?: string;
  allowlist?: string[];
  entropyThreshold?: number;
  maskStyle?: "token" | "hash" | "asterisk";
  customPatterns?: Array<{
    id: string;
    name: string;
    category?: "cloud" | "ai" | "saas" | "vcs" | "crypto" | "generic";
    severity?: "critical" | "high" | "medium";
    regex: string;
    description?: string;
  }>;
  ci?: {
    failOnSeverity?: "critical" | "high" | "medium";
    ignoreFiles?: string[];
  };
}

export function loadConfig(rootDir: string = process.cwd()): AgentShieldConfig | null {
  const configFiles = [
    join(rootDir, ".agentshield.json"),
    join(rootDir, "agentshield.config.json"),
  ];

  for (const file of configFiles) {
    if (existsSync(file)) {
      try {
        const raw = readFileSync(file, "utf8");
        return JSON.parse(raw);
      } catch (err) {
        console.warn(`⚠️ Warning: Failed to parse configuration file at '${file}':`, err);
      }
    }
  }

  return null;
}

export function parseCustomPatterns(config: AgentShieldConfig | null): SecretPattern[] {
  if (!config?.customPatterns || !Array.isArray(config.customPatterns)) {
    return [];
  }

  const patterns: SecretPattern[] = [];
  for (const item of config.customPatterns) {
    try {
      patterns.push({
        id: item.id,
        name: item.name,
        category: item.category || "generic",
        severity: item.severity || "high",
        regex: new RegExp(item.regex, "g"),
        description: item.description || item.name,
      });
    } catch (err) {
      console.warn(`⚠️ Invalid regex pattern in custom rule '${item.id}':`, err);
    }
  }

  return patterns;
}
