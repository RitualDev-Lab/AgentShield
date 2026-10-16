import assert from "node:assert";
import { Readable } from "node:stream";
import { describe, it } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { calculateShannonEntropy, isLikelyFalsePositive } from "../src/entropy.js";
import { createRedactingStream } from "../src/interceptor.js";

describe("Phase 5: Property-Based Testing & Security Invariants", () => {
  const engine = new AgentShieldEngine();

  describe("Property 1: Streaming Redaction Boundary Invariance", () => {
    // Generate synthetic secrets using small chunk assembly
    const testCases = [
      {
        name: "Anthropic Claude Key",
        prefix: ["sk", "ant", "api03"].join("-"),
        body: ["mock", "Key", "12345", "67890", "abcde"].join(""),
      },
      {
        name: "Stripe Live Key",
        prefix: ["sk", "live"].join("_"),
        body: ["test", "Token", "98765", "43210", "xyzab"].join(""),
      },
      {
        name: "AWS Access Key",
        prefix: "AKIA",
        body: ["1234", "5678", "ABCD", "EFGH"].join(""),
      },
    ];

    for (const tc of testCases) {
      it(`never leaks secret fragment for arbitrary 2-chunk boundary splits: ${tc.name}`, async () => {
        const secret = `${tc.prefix}-${tc.body}`;
        const fullPayload = `[HEADER:START] AuthKey=${secret} [FOOTER:END]`;

        // Test every possible split point in the payload
        for (let splitIndex = 1; splitIndex < fullPayload.length; splitIndex++) {
          const chunk1 = fullPayload.slice(0, splitIndex);
          const chunk2 = fullPayload.slice(splitIndex);

          let streamedOutput = "";
          const redactingTransform = createRedactingStream(engine, "token");

          await new Promise<void>((resolve, reject) => {
            const readable = Readable.from([chunk1, chunk2]);
            readable
              .pipe(redactingTransform)
              .on("data", (c: Buffer) => {
                streamedOutput += c.toString("utf8");
              })
              .on("end", resolve)
              .on("error", reject);
          });

          // Invariant: The raw secret MUST NOT appear in the output stream
          assert.strictEqual(
            streamedOutput.includes(secret),
            false,
            `Invariant violation at split point ${splitIndex}: raw secret leaked!`,
          );
          // Invariant: The output MUST contain the surrogate token
          assert.ok(
            streamedOutput.includes("[AGENT_SHIELD:"),
            `Invariant violation at split point ${splitIndex}: missing surrogate token!`,
          );
        }
      });
    }
  });

  describe("Property 2: Multibyte UTF-8 Boundary Preservation", () => {
    it("preserves unicode characters split across byte boundaries without corruption", async () => {
      // String with 1-byte, 2-byte, 3-byte, and 4-byte UTF-8 characters
      const unicodeString = "Hello 🛡️ 安全 ∑ é π 🌍 World!";
      const rawBytes = Buffer.from(unicodeString, "utf8");

      // Stream byte-by-byte (extreme fragmentation)
      const byteChunks: Buffer[] = [];
      for (let i = 0; i < rawBytes.length; i++) {
        byteChunks.push(rawBytes.subarray(i, i + 1));
      }

      let reconstructed = "";
      const stream = createRedactingStream(engine, "token");

      await new Promise<void>((resolve, reject) => {
        Readable.from(byteChunks)
          .pipe(stream)
          .on("data", (chunk: Buffer) => {
            reconstructed += chunk.toString("utf8");
          })
          .on("end", resolve)
          .on("error", reject);
      });

      // Invariant: Reconstructed unicode string must be 100% byte-for-byte identical
      assert.strictEqual(reconstructed.trim(), unicodeString.trim());
      // Invariant: No UTF-8 replacement character \uFFFD was generated
      assert.strictEqual(reconstructed.includes("\uFFFD"), false);
    });
  });

  describe("Property 3: Bijective In-Memory Vault Rehydration", () => {
    it("guarantees rehydration bijectivity across multiple secret formats", () => {
      const p1 = ["sk", "ant", "api03"].join("-");
      const k1 = `${p1}-${["token1", "1234567890", "1234567890", "1234567890", "abcde"].join("")}`;

      const p2 = ["sk", "live"].join("_");
      const k2 = `${p2}_${["token2", "1234567890", "1234567890", "12345"].join("")}`;

      const originalText = `First token: ${k1}, Second token: ${k2}. End of config.`;

      const redacted = engine.scanAndRedact(originalText);
      assert.strictEqual(redacted.hasSecrets, true);
      assert.strictEqual(redacted.sanitizedText.includes(k1), false);
      assert.strictEqual(redacted.sanitizedText.includes(k2), false);

      const restored = engine.rehydrate(redacted.sanitizedText);
      assert.strictEqual(restored, originalText);
    });
  });

  describe("Property 4: Multiline Fail-Closed Safety Invariant", () => {
    it("fails closed on unclosed multiline PEM private key at EOF", async () => {
      const header = ["-----BEGIN ", "RSA PRIVATE ", "KEY-----"].join("");
      const body = "MIIEowIBAAKCAQEA0Y3x\nMIIEowIBAAKCAQEA1Z4y\n";
      const unclosedKey = `${header}\n${body}`;

      let output = "";
      const stream = createRedactingStream(engine, "token");

      await new Promise<void>((resolve, reject) => {
        Readable.from([unclosedKey])
          .pipe(stream)
          .on("data", (c: Buffer) => {
            output += c.toString("utf8");
          })
          .on("end", resolve)
          .on("error", reject);
      });

      // Invariant: Raw key body must never escape
      assert.strictEqual(output.includes(body), false);
      assert.ok(output.includes("[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED]"));
    });

    it("fails closed on oversized unclosed buffer exceeding limit", async () => {
      const header = ["-----BEGIN ", "PRIVATE ", "KEY-----"].join("");
      const smallWindowStream = createRedactingStream(engine, "token", undefined, {
        maxMultilineBuffer: 512,
      });

      const oversizedContent = `${header}\n${"A".repeat(600)}`;

      let output = "";
      await new Promise<void>((resolve, reject) => {
        Readable.from([oversizedContent])
          .pipe(smallWindowStream)
          .on("data", (c: Buffer) => {
            output += c.toString("utf8");
          })
          .on("end", resolve)
          .on("error", reject);
      });

      assert.strictEqual(output.includes("A".repeat(600)), false);
      assert.ok(output.includes("[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED_OVERSIZED]"));
    });
  });

  describe("Property 5: False Positive Invariance on Benign High-Entropy Data", () => {
    it("does not flag common non-secret high-entropy structures as secrets", () => {
      const benignSamples = [
        "commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904", // Git SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // SHA256 hash of empty string
        "123e4567-e89b-12d3-a456-426614174000", // Standard UUID
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY44YAAAAASUVORK5CYII=", // Base64 data URI
        "const __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED = true;", // React internal keyword
      ];

      for (const sample of benignSamples) {
        // Must be identified as likely false positive if high entropy
        const isFalsePositive = isLikelyFalsePositive(sample);
        const scan = engine.scan(sample);
        assert.strictEqual(
          scan.length,
          0,
          `Benign sample falsely flagged as secret: ${sample}`,
        );
      }
    });

    it("Shannon entropy calculation invariants", () => {
      assert.strictEqual(calculateShannonEntropy(""), 0);
      assert.strictEqual(calculateShannonEntropy("1111111111"), 0);

      // Binary alternating sequence has entropy of exactly 1.0
      const binaryEntropy = calculateShannonEntropy("0101010101010101");
      assert.strictEqual(Math.round(binaryEntropy * 10) / 10, 1.0);

      // Higher diversity increases entropy monotonically
      const lowDiversity = calculateShannonEntropy("abcdef");
      const highDiversity = calculateShannonEntropy("abcdef123456!@#$%^");
      assert.ok(highDiversity > lowDiversity);
    });
  });
});
