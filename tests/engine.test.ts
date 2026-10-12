import assert from "node:assert/strict";
import test, { describe } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { calculateShannonEntropy } from "../src/entropy.js";

describe("AgentShield Detection & Redaction Engine", () => {
  const engine = new AgentShieldEngine();

  test("calculates Shannon entropy correctly", () => {
    // Low entropy
    const low = calculateShannonEntropy("aaaaaaaaaa");
    assert.strictEqual(low, 0);

    // High entropy random string
    const high = calculateShannonEntropy("d7F!9kP#mZ2$xL1@qW8*");
    assert.ok(high > 3.8);
  });

  test("detects and redacts OpenAI secret keys", () => {
    // Construct sample token dynamically to avoid triggering GitHub push protection
    const sampleToken = ["sk-proj-", "mockTestKey1234567890123456789012345678901234"].join("");
    const text = `Const key = '${sampleToken}';`;
    const result = engine.scanAndRedact(text);

    assert.strictEqual(result.hasSecrets, true);
    assert.strictEqual(result.totalFound, 1);
    assert.strictEqual(result.findings[0].patternId, "openai-api-key");
    assert.ok(result.sanitizedText.includes("[AGENT_SHIELD:OPENAI_API_KEY:"));
    assert.ok(!result.sanitizedText.includes("mockTestKey"));
  });

  test("detects and redacts Anthropic Claude keys", () => {
    const sampleToken = ["sk-ant-api03-", "mockClaudeTestKey123456789012345678901234567890"].join(
      "",
    );
    const text = `export ANTHROPIC_API_KEY='${sampleToken}'`;
    const result = engine.scanAndRedact(text);

    assert.strictEqual(result.hasSecrets, true);
    assert.strictEqual(result.findings[0].patternId, "anthropic-api-key");
    assert.ok(result.sanitizedText.includes("[AGENT_SHIELD:ANTHROPIC_API_KEY:"));
  });

  test("detects and redacts AWS access keys", () => {
    const sampleToken = ["AKIA", "9AF7XK2MP4VL8WQ1"].join("");
    const text = `AWS_ACCESS_KEY_ID=${sampleToken}`;
    const result = engine.scanAndRedact(text);

    assert.strictEqual(result.hasSecrets, true);
    assert.strictEqual(result.findings[0].patternId, "aws-access-key-id");
    assert.ok(!result.sanitizedText.includes("9AF7XK2MP4VL8WQ1"));
  });

  test("detects and redacts Stripe live keys", () => {
    const sampleToken = ["sk_live_", "MockStripeKey1234567890123456789012345"].join("");
    const text = `stripe.init('${sampleToken}');`;
    const result = engine.scanAndRedact(text);

    assert.strictEqual(result.hasSecrets, true);
    assert.strictEqual(result.findings[0].patternId, "stripe-secret-key");
    assert.ok(!result.sanitizedText.includes("MockStripeKey"));
  });

  test("rehydrates redacted text back to original credentials", () => {
    const sampleToken = ["sk-proj-", "RehydrateSampleKey1234567890123456789012345"].join("");
    const original = `apiKey: ${sampleToken}`;
    const result = engine.scanAndRedact(original);

    assert.notStrictEqual(result.sanitizedText, original);
    const restored = engine.rehydrate(result.sanitizedText);
    assert.strictEqual(restored, original);
  });

  test("actively discovers unknown high-entropy passwords and tokens", () => {
    // Generate a standalone high-entropy token without any pattern keyword
    const highEntropyToken = ["X9qK", "vL2z", "W8mP", "jR5y", "T1bN", "cE4x", "Z7hF"].join("");
    const input = `const userSessionData = "${highEntropyToken}";`;
    const result = engine.scanAndRedact(input);

    assert.strictEqual(result.hasSecrets, true);
    assert.strictEqual(result.findings[0].patternId, "high-entropy-secret");
    assert.ok(result.sanitizedText.includes("[AGENT_SHIELD:HIGH_ENTROPY_SECRET:"));
    assert.ok(!result.sanitizedText.includes(highEntropyToken));
  });

  test("prevents collision when secrets share identical prefixes", () => {
    const sampleToken = ["sk-proj-", "1111111111111111111111111111111111111111"].join("");
    const secretA = `${sampleToken}AAAA`;
    const secretB = `${sampleToken}BBBB`;

    const resA = engine.scanAndRedact(`const keyA = "${secretA}";`);
    const resB = engine.scanAndRedact(`const keyB = "${secretB}";`);

    assert.strictEqual(resA.hasSecrets, true);
    assert.strictEqual(resB.hasSecrets, true);
    // Redaction tokens must be completely distinct because hashes are 16 hex characters
    assert.notStrictEqual(resA.findings[0].redacted, resB.findings[0].redacted);
  });
});
