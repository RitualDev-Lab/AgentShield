import assert from "node:assert";
import { existsSync, rmSync } from "node:fs";
import { describe, it, before, after } from "node:test";
import {
  saveCredentials,
  loadCredentials,
  clearCredentials,
  cacheRemotePolicy,
  getCachedRemotePolicy,
  mergeRemotePolicyIntoConfig,
  fetchRemotePolicy,
  type RemotePolicyPayload,
  CREDENTIALS_FILE,
  CACHED_POLICY_FILE,
} from "../src/remote-policy.js";
import { AgentShieldEngine } from "../src/engine.js";
import { parseCustomPatterns } from "../src/config.js";

describe("Phase 1: Remote Team Config & Organization Tokens", () => {
  const originalOrg = process.env.AGENTSHIELD_ORG_ID;
  const originalToken = process.env.AGENTSHIELD_TOKEN;

  before(() => {
    process.env.AGENTSHIELD_ORG_ID = "";
    process.env.AGENTSHIELD_TOKEN = "";
  });

  after(() => {
    if (originalOrg) process.env.AGENTSHIELD_ORG_ID = originalOrg;
    if (originalToken) process.env.AGENTSHIELD_TOKEN = originalToken;
  });

  it("should save and load organization credentials correctly", () => {
    const creds = {
      orgId: "org_enterprise_acme_2026",
      token: "ashield_tok_secops_live_987654321",
      endpoint: "https://api.agentshield.ritualdev.in",
    };

    saveCredentials(creds);
    assert.strictEqual(existsSync(CREDENTIALS_FILE), true);

    const loaded = loadCredentials();
    assert.strictEqual(loaded?.orgId, creds.orgId);
    assert.strictEqual(loaded?.token, creds.token);
    assert.strictEqual(loaded?.endpoint, creds.endpoint);
  });

  it("should prioritize environment variables over stored credentials", () => {
    process.env.AGENTSHIELD_ORG_ID = "env_org_ci_runner";
    process.env.AGENTSHIELD_TOKEN = "env_token_ci_999";

    const loaded = loadCredentials();
    assert.strictEqual(loaded?.orgId, "env_org_ci_runner");
    assert.strictEqual(loaded?.token, "env_token_ci_999");

    process.env.AGENTSHIELD_ORG_ID = "";
    process.env.AGENTSHIELD_TOKEN = "";
  });

  it("should cache remote policies locally for offline fallback", () => {
    const mockPolicy: RemotePolicyPayload = {
      policyVersion: "2026.3.0",
      orgId: "org_enterprise_acme_2026",
      allowlist: ["mock-internal-token-clean"],
      entropyThreshold: 4.8,
      maskStyle: "hash",
      customPatterns: [
        {
          id: "corp-internal-key",
          name: "Acme Corp Internal Key",
          regex: "\\bACME_[A-Z0-9]{24}\\b",
          category: "generic",
          severity: "critical",
        },
      ],
      updatedAt: new Date().toISOString(),
    };

    cacheRemotePolicy(mockPolicy);
    assert.strictEqual(existsSync(CACHED_POLICY_FILE), true);

    const cached = getCachedRemotePolicy();
    assert.strictEqual(cached?.policyVersion, "2026.3.0");
    assert.strictEqual(cached?.customPatterns?.[0].id, "corp-internal-key");
  });

  it("should merge remote enterprise policy with local workspace config", () => {
    const localConfig = {
      allowlist: ["local-test-token"],
      customPatterns: [
        {
          id: "local-pattern",
          name: "Local Pattern",
          regex: "\\bLOCAL_[0-9]{6}\\b",
        },
      ],
    };

    const remotePolicy: RemotePolicyPayload = {
      policyVersion: "2026.3.0",
      orgId: "org_enterprise_acme_2026",
      allowlist: ["remote-corporate-allowlist"],
      maskStyle: "asterisk",
      entropyThreshold: 4.2,
      customPatterns: [
        {
          id: "corp-internal-key",
          name: "Acme Corp Key",
          regex: "\\bCORP_[A-Z0-9]{16}\\b",
        },
      ],
      updatedAt: new Date().toISOString(),
    };

    const merged = mergeRemotePolicyIntoConfig(localConfig, remotePolicy);

    assert.strictEqual(merged.maskStyle, "asterisk");
    assert.strictEqual(merged.entropyThreshold, 4.2);
    assert.strictEqual(merged.allowlist?.includes("local-test-token"), true);
    assert.strictEqual(merged.allowlist?.includes("remote-corporate-allowlist"), true);
    assert.strictEqual(
      merged.customPatterns?.some((p) => p.id === "corp-internal-key"),
      true,
    );
    assert.strictEqual(
      merged.customPatterns?.some((p) => p.id === "local-pattern"),
      true,
    );

    // Verify engine detects enterprise remote pattern
    const patterns = parseCustomPatterns(merged);
    const engine = new AgentShieldEngine(patterns);
    const scanResult = engine.scanAndRedact("leaked token CORP_ABC1234567890XYZ");
    assert.strictEqual(scanResult.hasSecrets, true);
    assert.strictEqual(
      scanResult.findings.some((f) => f.patternId === "corp-internal-key"),
      true,
    );
  });

  it("should gracefully clear credentials on logout", () => {
    clearCredentials();
    const loaded = loadCredentials();
    assert.strictEqual(!loaded || Object.keys(loaded).length === 0, true);
  });
});
