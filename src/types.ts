export interface SecretPattern {
  id: string;
  name: string;
  category: "cloud" | "ai" | "saas" | "vcs" | "crypto" | "generic";
  severity: "critical" | "high" | "medium";
  regex: RegExp;
  description: string;
  prefix?: string;
}

export interface DetectedSecret {
  patternId: string;
  patternName: string;
  category: string;
  severity: "critical" | "high" | "medium";
  raw: string;
  redacted: string;
  line: number;
  column: number;
  entropy?: number;
  file?: string;
}

export interface ScanOptions {
  entropyThreshold?: number;
  maskStyle?: "token" | "hash" | "asterisk";
  allowlist?: string[];
  customPatterns?: SecretPattern[];
  includeRaw?: boolean; // Defaults to false to prevent accidental secret leakage in logs
}

export interface ScanResult {
  hasSecrets: boolean;
  totalFound: number;
  findings: DetectedSecret[];
  sanitizedText: string;
  vaultMap: Map<string, string>; // Maps redacted placeholder -> original secret
}
