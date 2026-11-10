import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { runAgentShieldDemo } from "../src/demo.js";

describe("AgentShield Interactive 10-Second Demo", () => {
  it("blocks direct and obfuscated exfiltration attempts and redacts all simulated secrets", () => {
    const result = runAgentShieldDemo({ silent: true });
    assert.equal(result.directBlocked, true);
    assert.equal(result.evasionBlocked, true);
    assert.ok(result.redactedCount >= 4, `Expected >= 4 findings, got ${result.redactedCount}`);
    assert.ok(!result.sanitizedEnv.includes("VaultPass99!Prod2026"));
    assert.ok(!result.sanitizedEnv.includes("7K9X2M4R8Q6W1N3B"));
  });
});
