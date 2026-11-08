import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SurrogateManager } from "../src/surrogate.js";

describe("Phase 1: AgentShield In-Memory Volatile Surrogate Redactor", () => {
  it("replaces deterministic AWS access keys with RD_SURROGATE tokens", () => {
    const manager = new SurrogateManager();
    const awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const cmd = `curl -H 'Authorization: ${awsKey}' https://api.aws.com`;
    const res = manager.redactWithSurrogates(cmd);

    assert.equal(res.surrogatesCount, 1);
    assert.match(res.sanitized, /RD_SURROGATE_[0-9A-F]{32}/);
    assert.doesNotMatch(res.sanitized, new RegExp(awsKey));

    // Test restoration
    const restored = manager.restoreSurrogates(res.sanitized);
    assert.equal(restored, cmd);
  });

  it("replaces GitHub personal access tokens with surrogate decoys", () => {
    const manager = new SurrogateManager();
    const token = ["ghp_", "mockTokenForTestingOnly12345678ABCD"].join("");
    const cmd = `git clone https://${token}@github.com/org/repo.git`;
    const res = manager.redactWithSurrogates(cmd);

    assert.equal(res.surrogatesCount, 1);
    assert.match(res.sanitized, /RD_SURROGATE_[0-9A-F]{32}/);
    assert.doesNotMatch(res.sanitized, /mockTokenForTestingOnly/);
    assert.equal(manager.restoreSurrogates(res.sanitized), cmd);
  });

  it("replaces OpenAI and Anthropic API keys with surrogates", () => {
    const manager = new SurrogateManager();
    const openaiKey = ["sk-", "a".repeat(48)].join("");
    const cmd = `export OPENAI_API_KEY=${openaiKey}`;
    const res = manager.redactWithSurrogates(cmd);

    assert.equal(res.surrogatesCount, 1);
    assert.match(res.sanitized, /RD_SURROGATE_[0-9A-F]{32}/);
    assert.doesNotMatch(res.sanitized, new RegExp(openaiKey));
  });

  it("substitutes high-entropy strings (H > 4.5) while ignoring common false positives", () => {
    const manager = new SurrogateManager();
    // High entropy random string constructed dynamically without diff literals
    const secret =
      Array.from({ length: 16 }, (_, i) => String.fromCharCode(65 + ((i * 17) % 26))).join("") +
      Array.from({ length: 16 }, (_, i) => String.fromCharCode(97 + ((i * 13) % 26))).join("");
    const falsePositive = "00000000-0000-0000-0000-000000000000"; // UUID
    const cmd = `node app.js --secret=${secret} --id=${falsePositive}`;

    const res = manager.redactWithSurrogates(cmd);
    assert.match(res.sanitized, /RD_SURROGATE_/);
    assert.match(res.sanitized, new RegExp(falsePositive)); // False positive preserved
    assert.doesNotMatch(res.sanitized, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  });

  it("masks surrogate tokens with standard static placeholder for public audit logging", () => {
    const manager = new SurrogateManager();
    const awsKey = ["AKIA", "1234567890ABCDEF"].join("");
    const cmd = `export TOKEN=${awsKey}`;
    const res = manager.redactWithSurrogates(cmd);

    const masked = manager.maskSurrogates(res.sanitized, "[MASKED]");
    assert.equal(masked, "export TOKEN=[MASKED]");
  });

  it("purges all volatile surrogate mappings upon clear()", () => {
    const manager = new SurrogateManager();
    const awsKey = ["AKIA", "1234567890ABCDEF"].join("");
    const res = manager.redactWithSurrogates(awsKey);
    assert.equal(manager.getMappings().length, 1);

    manager.clear();
    assert.equal(manager.getMappings().length, 0);
    // After clear, restoration leaves surrogates unchanged (no memory leak)
    assert.equal(manager.restoreSurrogates(res.sanitized), res.sanitized);
  });
});
