/**
 * Unified `ritual.policy.yaml` Manifest Parser, Validator & `agentshield up` Orchestrator (Phase 8)
 *
 * Zero-dependency declarative policy parser that unifies the 3-layer RitualDev-Lab defense stack:
 *   1. AgentShield — OS kernel sandbox, secret redaction & Ed25519 audit ledger
 *   2. DBShield    — PostgreSQL/MySQL wire-protocol SQL firewall & ChatOps approval proxy
 *   3. SkillPrism  — Ephemeral JIT MCP schema compactor & prompt-injection guard
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export type AgentShieldMode = "strict" | "balanced" | "audit";
export type SandboxProfile = "strict" | "standard" | "permissive";
export type DbShieldTier = "STRICT" | "BALANCED" | "PERMISSIVE";

export interface AgentShieldLayerConfig {
  enabled: boolean;
  mode: AgentShieldMode;
  sandboxProfile: SandboxProfile;
  redactPii: boolean;
  ledgerPath: string;
}

export interface DbShieldLayerConfig {
  enabled: boolean;
  listenPort: number;
  targetUrl: string;
  safetyTier: DbShieldTier;
  requireChatOpsApproval: boolean;
  maxEstimatedCost: number;
}

export interface SkillPrismLayerConfig {
  enabled: boolean;
  listenPort: number;
  maxActiveSkills: number;
  promptGuard: boolean;
  redisSentinelFallback: boolean;
}

export interface RitualPolicyManifest {
  version: string;
  name: string;
  airGapped: boolean;
  agentshield: AgentShieldLayerConfig;
  dbshield: DbShieldLayerConfig;
  skillprism: SkillPrismLayerConfig;
}

export interface PolicyValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  manifest: RitualPolicyManifest;
}

export interface OrchestrationStep {
  layer: "agentshield" | "dbshield" | "skillprism";
  packageName: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  listenPort?: number;
  summary: string;
}

export interface OrchestrationPlan {
  configPath: string;
  policyName: string;
  version: string;
  airGapped: boolean;
  layersEnabled: string[];
  steps: OrchestrationStep[];
}

function parseScalar(raw: string): unknown {
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed === "null" || trimmed === "~") return null;
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);

  // Strip surrounding single or double quotes
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    return trimmed.slice(1, -1);
  }

  // Inline array: [a, b, c]
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const inner = trimmed.slice(1, -1).trim();
    if (!inner) return [];
    return inner.split(",").map((item) => parseScalar(item));
  }

  return trimmed;
}

function stripInlineComment(line: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
    } else if (ch === "#" && !inSingle && !inDouble) {
      if (i === 0 || line[i - 1] === " " || line[i - 1] === "\t") {
        return line.slice(0, i);
      }
    }
  }
  return line;
}

/**
 * Lightweight zero-dependency YAML/JSON object parser supporting nested maps,
 * scalars, comments, and inline/block arrays for `ritual.policy.yaml`.
 */
export function parseSimpleYaml(source: string): Record<string, unknown> {
  const trimmed = source.trim();
  if (!trimmed) {
    return {};
  }
  if (trimmed.startsWith("{")) {
    const parsed = JSON.parse(trimmed);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    throw new Error("ritual.policy.yaml root must be a mapping/object");
  }

  const root: Record<string, unknown> = {};
  const stack: Array<{ indent: number; obj: Record<string, unknown> }> = [
    { indent: -1, obj: root },
  ];

  const lines = source.split(/\r?\n/);
  for (let idx = 0; idx < lines.length; idx++) {
    const cleaned = stripInlineComment(lines[idx]);
    if (!cleaned.trim()) continue;

    const indent = cleaned.length - cleaned.trimStart().length;
    const content = cleaned.trim();

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) {
      stack.pop();
    }
    const current = stack[stack.length - 1].obj;

    const colonIdx = content.indexOf(":");
    if (colonIdx === -1) {
      throw new Error(`Invalid YAML syntax on line ${idx + 1}: "${content}"`);
    }

    const key = content.slice(0, colonIdx).trim();
    const rest = content.slice(colonIdx + 1).trim();

    if (!key) {
      throw new Error(`Missing key on line ${idx + 1}`);
    }

    if (rest === "") {
      const child: Record<string, unknown> = {};
      current[key] = child;
      stack.push({ indent, obj: child });
    } else {
      current[key] = parseScalar(rest);
    }
  }

  return root;
}

function asRecord(val: unknown): Record<string, unknown> {
  return val && typeof val === "object" && !Array.isArray(val)
    ? (val as Record<string, unknown>)
    : {};
}

function asBool(val: unknown, fallback: boolean): boolean {
  return typeof val === "boolean" ? val : fallback;
}

function asString(val: unknown, fallback: string): string {
  return typeof val === "string" && val.length > 0 ? val : fallback;
}

function asNumber(val: unknown, fallback: number): number {
  return typeof val === "number" && Number.isFinite(val) ? val : fallback;
}

export function parseRitualPolicyYaml(source: string): PolicyValidationResult {
  const raw = parseSimpleYaml(source);
  const errors: string[] = [];
  const warnings: string[] = [];

  const version = raw.version !== undefined && raw.version !== null ? String(raw.version) : "";
  if (!version) {
    errors.push("Missing required top-level field: 'version' (expected '1' or '1.0').");
  } else if (version !== "1" && version !== "1.0") {
    errors.push(`Unsupported policy schema version '${version}'. Supported: '1', '1.0'.`);
  }

  const name = asString(raw.name, "ritual-defense-stack");
  const airGapped = asBool(raw.airGapped ?? raw.air_gapped, true);

  const asRaw = asRecord(raw.agentshield);
  const dbRaw = asRecord(raw.dbshield);
  const spRaw = asRecord(raw.skillprism);

  const modeRaw = asString(asRaw.mode, "strict").toLowerCase();
  const validModes: AgentShieldMode[] = ["strict", "balanced", "audit"];
  if (!validModes.includes(modeRaw as AgentShieldMode)) {
    errors.push(
      `Invalid agentshield.mode '${modeRaw}'. Expected one of: ${validModes.join(", ")}.`,
    );
  }

  const profileRaw = asString(
    asRaw.sandboxProfile ?? asRaw.sandbox_profile,
    "strict",
  ).toLowerCase();
  const validProfiles: SandboxProfile[] = ["strict", "standard", "permissive"];
  if (!validProfiles.includes(profileRaw as SandboxProfile)) {
    errors.push(
      `Invalid agentshield.sandboxProfile '${profileRaw}'. Expected one of: ${validProfiles.join(", ")}.`,
    );
  }

  const tierRaw = asString(dbRaw.safetyTier ?? dbRaw.safety_tier, "STRICT").toUpperCase();
  const validTiers: DbShieldTier[] = ["STRICT", "BALANCED", "PERMISSIVE"];
  if (!validTiers.includes(tierRaw as DbShieldTier)) {
    errors.push(
      `Invalid dbshield.safetyTier '${tierRaw}'. Expected one of: ${validTiers.join(", ")}.`,
    );
  }

  const dbPort = asNumber(dbRaw.listenPort ?? dbRaw.listen_port, 5433);
  const spPort = asNumber(spRaw.listenPort ?? spRaw.listen_port, 4310);

  if (dbPort < 1 || dbPort > 65535) {
    errors.push(`Invalid dbshield.listenPort '${dbPort}'. Must be between 1 and 65535.`);
  }
  if (spPort < 1 || spPort > 65535) {
    errors.push(`Invalid skillprism.listenPort '${spPort}'. Must be between 1 and 65535.`);
  }

  const manifest: RitualPolicyManifest = {
    version: version || "1.0",
    name,
    airGapped,
    agentshield: {
      enabled: asBool(asRaw.enabled, true),
      mode: (validModes.includes(modeRaw as AgentShieldMode)
        ? modeRaw
        : "strict") as AgentShieldMode,
      sandboxProfile: (validProfiles.includes(profileRaw as SandboxProfile)
        ? profileRaw
        : "strict") as SandboxProfile,
      redactPii: asBool(asRaw.redactPii ?? asRaw.redact_pii, true),
      ledgerPath: asString(
        asRaw.ledgerPath ?? asRaw.ledger_path,
        ".agentshield/audit-ledger.jsonl",
      ),
    },
    dbshield: {
      enabled: asBool(dbRaw.enabled, true),
      listenPort: dbPort,
      targetUrl: asString(
        dbRaw.targetUrl ?? dbRaw.target_url,
        "postgres://127.0.0.1:5432/postgres",
      ),
      safetyTier: (validTiers.includes(tierRaw as DbShieldTier)
        ? tierRaw
        : "STRICT") as DbShieldTier,
      requireChatOpsApproval: asBool(
        dbRaw.requireChatOpsApproval ?? dbRaw.require_chatops_approval,
        true,
      ),
      maxEstimatedCost: asNumber(dbRaw.maxEstimatedCost ?? dbRaw.max_estimated_cost, 50000),
    },
    skillprism: {
      enabled: asBool(spRaw.enabled, true),
      listenPort: spPort,
      maxActiveSkills: asNumber(spRaw.maxActiveSkills ?? spRaw.max_active_skills, 8),
      promptGuard: asBool(spRaw.promptGuard ?? spRaw.prompt_guard, true),
      redisSentinelFallback: asBool(
        spRaw.redisSentinelFallback ?? spRaw.redis_sentinel_fallback,
        true,
      ),
    },
  };

  if (
    manifest.dbshield.enabled &&
    manifest.skillprism.enabled &&
    manifest.dbshield.listenPort === manifest.skillprism.listenPort
  ) {
    errors.push(
      `Port conflict: dbshield.listenPort and skillprism.listenPort are both set to ${manifest.dbshield.listenPort}.`,
    );
  }

  if (!manifest.agentshield.enabled && !manifest.dbshield.enabled && !manifest.skillprism.enabled) {
    warnings.push("All 3 defense layers are disabled in ritual.policy.yaml.");
  }

  if (!manifest.airGapped) {
    warnings.push("airGapped is false; outbound telemetry or cloud integrations may be permitted.");
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    manifest,
  };
}

export function loadRitualPolicyFile(configPath = "ritual.policy.yaml"): {
  resolvedPath: string;
  validation: PolicyValidationResult;
} {
  const resolvedPath = resolve(configPath);
  if (!existsSync(resolvedPath)) {
    throw new Error(
      `Unified policy manifest not found at '${resolvedPath}'. Run 'agentshield up --init' to generate a default ritual.policy.yaml.`,
    );
  }
  const source = readFileSync(resolvedPath, "utf8");
  return {
    resolvedPath,
    validation: parseRitualPolicyYaml(source),
  };
}

export function resolveOrchestrationPlan(
  manifest: RitualPolicyManifest,
  configPath: string,
): OrchestrationPlan {
  const sharedEnv: Record<string, string> = {
    RITUAL_POLICY_NAME: manifest.name,
    RITUAL_POLICY_VERSION: manifest.version,
    RITUAL_AIR_GAPPED: manifest.airGapped ? "1" : "0",
    AGENTSHIELD_AIR_GAPPED: manifest.airGapped ? "1" : "0",
  };

  const steps: OrchestrationStep[] = [];
  const layersEnabled: string[] = [];

  if (manifest.agentshield.enabled) {
    layersEnabled.push("agentshield");
    steps.push({
      layer: "agentshield",
      packageName: "@ritualdev-lab/agentshield",
      command: "agentshield",
      args: ["doctor", "--json"],
      env: {
        ...sharedEnv,
        AGENTSHIELD_MODE: manifest.agentshield.mode,
        AGENTSHIELD_SANDBOX_PROFILE: manifest.agentshield.sandboxProfile,
        AGENTSHIELD_REDACT_PII: manifest.agentshield.redactPii ? "1" : "0",
        AGENTSHIELD_LEDGER_PATH: manifest.agentshield.ledgerPath,
      },
      summary: `AgentShield sandbox (${manifest.agentshield.sandboxProfile}/${manifest.agentshield.mode}) + Ed25519 ledger (${manifest.agentshield.ledgerPath})`,
    });
  }

  if (manifest.dbshield.enabled) {
    layersEnabled.push("dbshield");
    steps.push({
      layer: "dbshield",
      packageName: "@ritualdev-lab/dbshield",
      command: "npx",
      args: [
        "-y",
        "@ritualdev-lab/dbshield",
        "proxy",
        "--port",
        String(manifest.dbshield.listenPort),
        "--tier",
        manifest.dbshield.safetyTier,
      ],
      env: {
        ...sharedEnv,
        DBSHIELD_TARGET_URL: manifest.dbshield.targetUrl,
        DBSHIELD_SAFETY_TIER: manifest.dbshield.safetyTier,
        DBSHIELD_CHATOPS_APPROVAL: manifest.dbshield.requireChatOpsApproval ? "1" : "0",
        DBSHIELD_MAX_ESTIMATED_COST: String(manifest.dbshield.maxEstimatedCost),
      },
      listenPort: manifest.dbshield.listenPort,
      summary: `DBShield SQL firewall proxy on :${manifest.dbshield.listenPort} (tier=${manifest.dbshield.safetyTier}, ChatOps=${manifest.dbshield.requireChatOpsApproval})`,
    });
  }

  if (manifest.skillprism.enabled) {
    layersEnabled.push("skillprism");
    steps.push({
      layer: "skillprism",
      packageName: "@ritualdev-lab/skillprism",
      command: "npx",
      args: [
        "-y",
        "@ritualdev-lab/skillprism",
        "proxy",
        "--port",
        String(manifest.skillprism.listenPort),
      ],
      env: {
        ...sharedEnv,
        SKILLPRISM_MAX_ACTIVE_SKILLS: String(manifest.skillprism.maxActiveSkills),
        SKILLPRISM_PROMPT_GUARD: manifest.skillprism.promptGuard ? "1" : "0",
        SKILLPRISM_REDIS_FALLBACK: manifest.skillprism.redisSentinelFallback ? "1" : "0",
      },
      listenPort: manifest.skillprism.listenPort,
      summary: `SkillPrism MCP context compactor on :${manifest.skillprism.listenPort} (promptGuard=${manifest.skillprism.promptGuard}, maxSkills=${manifest.skillprism.maxActiveSkills})`,
    });
  }

  return {
    configPath,
    policyName: manifest.name,
    version: manifest.version,
    airGapped: manifest.airGapped,
    layersEnabled,
    steps,
  };
}

export function generateDefaultRitualPolicyYaml(): string {
  return `# RitualDev-Lab Unified 3-Layer AI Agent Defense Policy
# Boot with: npx @ritualdev-lab/agentshield up --config ritual.policy.yaml
version: "1.0"
name: "ritual-defense-stack"
airGapped: true

agentshield:
  enabled: true
  mode: strict
  sandboxProfile: strict
  redactPii: true
  ledgerPath: ".agentshield/audit-ledger.jsonl"

dbshield:
  enabled: true
  listenPort: 5433
  targetUrl: "postgres://127.0.0.1:5432/postgres"
  safetyTier: STRICT
  requireChatOpsApproval: true
  maxEstimatedCost: 50000

skillprism:
  enabled: true
  listenPort: 4310
  maxActiveSkills: 8
  promptGuard: true
  redisSentinelFallback: true
`;
}
