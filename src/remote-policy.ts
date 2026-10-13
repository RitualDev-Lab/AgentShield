import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { AgentShieldConfig } from "./config.js";

export interface RemotePolicyCredentials {
  orgId: string;
  token: string;
  endpoint?: string;
  lastLogin?: string;
}

export interface RemotePolicyPayload {
  policyVersion: string;
  orgId: string;
  name?: string;
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
  enforceKernelSandbox?: boolean;
  quarantineOnCanaryTrip?: boolean;
  updatedAt: string;
}

export interface FetchPolicyOptions {
  timeoutMs?: number;
  offlineFallback?: boolean;
}

export const AGENTSHIELD_GLOBAL_DIR = join(homedir(), ".agentshield");
export const CREDENTIALS_FILE = join(AGENTSHIELD_GLOBAL_DIR, "credentials.json");
export const CACHED_POLICY_FILE = join(AGENTSHIELD_GLOBAL_DIR, "policies.cache.json");

/**
 * Saves remote enterprise organization credentials locally in ~/.agentshield/credentials.json
 */
export function saveCredentials(creds: RemotePolicyCredentials): void {
  if (!existsSync(AGENTSHIELD_GLOBAL_DIR)) {
    mkdirSync(AGENTSHIELD_GLOBAL_DIR, { recursive: true, mode: 0o700 });
  }
  const payload: RemotePolicyCredentials = {
    orgId: creds.orgId,
    token: creds.token,
    endpoint: creds.endpoint || "https://api.agentshield.ritualdev.in",
    lastLogin: new Date().toISOString(),
  };
  writeFileSync(CREDENTIALS_FILE, JSON.stringify(payload, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
}

/**
 * Loads remote enterprise organization credentials from ~/.agentshield/credentials.json or env vars
 */
export function loadCredentials(): RemotePolicyCredentials | null {
  // 1. Environment variables take highest precedence (CI/CD and containers)
  const envOrg = process.env.AGENTSHIELD_ORG_ID;
  const envToken = process.env.AGENTSHIELD_TOKEN || process.env.AGENTSHIELD_API_KEY;
  const envEndpoint = process.env.AGENTSHIELD_ENDPOINT;

  if (envOrg && envToken) {
    return {
      orgId: envOrg,
      token: envToken,
      endpoint: envEndpoint || "https://api.agentshield.ritualdev.in",
    };
  }

  // 2. Global file storage (~/.agentshield/credentials.json)
  if (existsSync(CREDENTIALS_FILE)) {
    try {
      const raw = readFileSync(CREDENTIALS_FILE, "utf8");
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Clears saved organization credentials on logout
 */
export function clearCredentials(): boolean {
  if (existsSync(CREDENTIALS_FILE)) {
    try {
      writeFileSync(CREDENTIALS_FILE, "{}", "utf8");
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Saves fetched remote policy to local cache for resilient air-gapped / offline fallback
 */
export function cacheRemotePolicy(policy: RemotePolicyPayload): void {
  if (!existsSync(AGENTSHIELD_GLOBAL_DIR)) {
    mkdirSync(AGENTSHIELD_GLOBAL_DIR, { recursive: true, mode: 0o700 });
  }
  writeFileSync(CACHED_POLICY_FILE, JSON.stringify(policy, null, 2), {
    encoding: "utf8",
    mode: 0o600,
  });
}

/**
 * Reads cached remote policy from local disk if remote fetch is unreachable
 */
export function getCachedRemotePolicy(): RemotePolicyPayload | null {
  if (existsSync(CACHED_POLICY_FILE)) {
    try {
      const raw = readFileSync(CACHED_POLICY_FILE, "utf8");
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Fetches organization policy from remote control plane with timeout and resilient offline fallback
 */
export async function fetchRemotePolicy(
  creds?: RemotePolicyCredentials | null,
  options: FetchPolicyOptions = {},
): Promise<{ policy: RemotePolicyPayload | null; isCached: boolean; error?: string }> {
  const activeCreds = creds || loadCredentials();
  if (!activeCreds?.orgId || !activeCreds?.token) {
    return { policy: null, isCached: false };
  }

  const endpoint = (activeCreds.endpoint || "https://api.agentshield.ritualdev.in").replace(
    /\/$/,
    "",
  );
  const url = `${endpoint}/api/v1/policies/${encodeURIComponent(activeCreds.orgId)}`;
  const timeoutMs = options.timeoutMs ?? 3500;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(url, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${activeCreds.token}`,
        "X-AgentShield-Org": activeCreds.orgId,
        "User-Agent": "AgentShield-CLI",
        Accept: "application/json",
      },
      signal: controller.signal,
    });
    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(
        `Remote policy endpoint returned HTTP ${response.status}: ${response.statusText}`,
      );
    }

    const data = (await response.json()) as RemotePolicyPayload;
    // Cache successfully fetched policy for resilient offline use
    cacheRemotePolicy(data);
    return { policy: data, isCached: false };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    if (options.offlineFallback !== false) {
      const cached = getCachedRemotePolicy();
      if (cached) {
        return { policy: cached, isCached: true, error: errorMsg };
      }
    }
    return { policy: null, isCached: false, error: errorMsg };
  }
}

/**
 * Merges local workspace config with remote enterprise policy.
 * Enterprise policy rules take mandatory security precedence.
 */
export function mergeRemotePolicyIntoConfig(
  localConfig: AgentShieldConfig | null,
  remotePolicy: RemotePolicyPayload | null,
): AgentShieldConfig {
  if (!remotePolicy) {
    return localConfig || {};
  }

  const mergedAllowlist = Array.from(
    new Set([...(localConfig?.allowlist || []), ...(remotePolicy.allowlist || [])]),
  );

  const mergedCustomPatterns = [
    ...(remotePolicy.customPatterns || []),
    ...(localConfig?.customPatterns || []),
  ];

  return {
    ...localConfig,
    allowlist: mergedAllowlist,
    entropyThreshold: remotePolicy.entropyThreshold ?? localConfig?.entropyThreshold,
    maskStyle: remotePolicy.maskStyle ?? localConfig?.maskStyle ?? "token",
    customPatterns: mergedCustomPatterns,
  };
}
