import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { SurrogateManager } from "../src/surrogate.js";

describe("Phase 1: AgentShield In-Memory Volatile Surrogate Redactor", () => {
  it("replaces deterministic AWS access keys with RD_SURROGATE tokens", () => {
    const manager = new SurrogateManager();
    const cmd = "curl -H 'Authorization: AKIAIOSFODNN7EXAMPLE' https://api.aws.com";
    const res = manager.redactWithSurrogates(cmd);

    assert.equal(res.surrogatesCount, 1);
    assert.match(res.sanitized, /RD_SURROGATE_[0-9A-F]{32}/);
    assert.doesNotMatch(res.sanitized, /AKIAIOSFODNN7EXAMPLE/);

    // Test restoration
    const restored = manager.restoreSurrogates(res.sanitized);
    assert.equal(restored, cmd);
  });

  it("replaces GitHub personal access tokens with surrogate decoys", () => {
    const manager = new SurrogateManager();
    const token = "ghp_1234567890abcdefghijklmnopqrstuv";
    const cmd = `git clone https://${token}@github.com/org/repo.git`;
    const res = manager.redactWithSurrogates(cmd);

    assert.equal(res.surrogatesCount, 1);
    assert.match(res.sanitized, /RD_SURROGATE_[0-9A-F]{32}/);
    assert.doesNotMatch(res.sanitized, /ghp_1234567890/);
    assert.equal(manager.restoreSurrogates(res.sanitized), cmd);
  });

  it("replaces OpenAI and Anthropic API keys with surrogates", () => {
    const manager = new SurrogateManager();
    const openaiKey = `sk-${"a".repeat(48)}`;
    const cmd = `export OPENAI_API_KEY=${openaiKey}`;
    const res = manager.redactWithSurrogates(cmd);

    assert.equal(res.surrogatesCount, 1);
    assert.match(res.sanitized, /RD_SURROGATE_[0-9A-F]{32}/);
    assert.doesNotMatch(res.sanitized, new RegExp(openaiKey));
  });

  it("substitutes high-entropy strings (H > 4.5) while ignoring common false positives", () => {
    const manager = new SurrogateManager();
    // High entropy random string (24 chars)
    const secret = "zK9#vP2$mL5!qR8*xT1^jN4@";
    const falsePositive = "00000000-0000-0000-0000-000000000000"; // UUID
    const cmd = `node app.js --secret=${secret} --id=${falsePositive}`;

    const res = manager.redactWithSurrogates(cmd);
    assert.match(res.sanitized, /RD_SURROGATE_/);
    assert.match(res.sanitized, new RegExp(falsePositive)); // False positive preserved
    assert.doesNotMatch(res.sanitized, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });

  it("masks surrogate tokens with standard static placeholder for public audit logging", () => {
    const manager = new SurrogateManager();
    const cmd = "export TOKEN=AKIA1234567890ABCDEF";
    const res = manager.redactWithSurrogates(cmd);

    const masked = manager.maskSurrogates(res.sanitized, "[MASKED]");
    assert.equal(masked, "export TOKEN=[MASKED]");
  });

  it("purges all volatile surrogate mappings upon clear()", () => {
    const manager = new SurrogateManager();
    const res = manager.redactWithSurrogates("AKIA1234567890ABCDEF");
    assert.equal(manager.getMappings().length, 1);

    manager.clear();
    assert.equal(manager.getMappings().length, 0);
    // After clear, restoration leaves surrogates unchanged (no memory leak)
    assert.equal(manager.restoreSurrogates(res.sanitized), res.sanitized);
  });
});
