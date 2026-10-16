import assert from "node:assert";
import { Readable } from "node:stream";
import { describe, it } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { createRedactingStream, RedactingStream } from "../src/interceptor.js";

async function streamToString(stream: Readable): Promise<string> {
  let result = "";
  for await (const chunk of stream) {
    result += chunk.toString("utf8");
  }
  return result;
}

describe("A1 Regression: Boundary-Safe Streaming Redaction & Multiline Windowing", () => {
  const engine = new AgentShieldEngine();

  describe("1. Exhaustive Boundary-Cut Fuzzing (Every Possible Split Point)", () => {
    it("never leaks a secret when split at any arbitrary 2-chunk boundary", async () => {
      const secret = ["ghp", "123456789012345678901234567890123456"].join("_");
      const fullText = `export GITHUB_TOKEN=${secret}\necho "Done"\n`;

      for (let split = 1; split < fullText.length; split++) {
        const chunk1 = fullText.slice(0, split);
        const chunk2 = fullText.slice(split);

        let scrubbedCount = 0;
        const transform = createRedactingStream(engine, "token", (c) => {
          scrubbedCount += c;
        });

        const output = await streamToString(Readable.from([chunk1, chunk2]).pipe(transform));

        assert.strictEqual(
          output.includes(secret),
          false,
          `Secret leaked when split at index ${split}! Output was: ${output}`,
        );
        assert.ok(
          output.includes("[AGENT_SHIELD:GITHUB_PAT:"),
          `Missing redaction token when split at index ${split}`,
        );
        assert.ok(scrubbedCount >= 1);
      }
    });

    it("scrubs secrets when streamed 1 byte at a time (extreme fragmentation)", async () => {
      const secrets = [
        ["sk", "ant", "api03-12345678901234567890123456789012345678901234"].join("-"),
        ["sk", "proj", "1234567890123456789012345678901234567890"].join("-"),
        ["AKIA", "IOSFODNN7EXAMPLE"].join(""),
        ["sk", "live", "1234567890123456789012345678"].join("_"),
      ];

      for (const secret of secrets) {
        const payload = `Line start: ${secret} Line end\n`;
        const oneByteChunks = Array.from(payload).map((char) => Buffer.from(char, "utf8"));

        const transform = createRedactingStream(engine, "token");
        const output = await streamToString(Readable.from(oneByteChunks).pipe(transform));

        assert.strictEqual(
          output.includes(secret),
          false,
          `Secret ${secret} escaped in 1-byte chunk stream!`,
        );
        assert.ok(
          output.includes("[AGENT_SHIELD:"),
          `Missing redaction token for secret ${secret} in 1-byte chunk stream`,
        );
      }
    });
  });

  describe("2. Multibyte UTF-8 Character Boundary Preservation", () => {
    it("preserves multibyte UTF-8 characters split across chunk boundaries", async () => {
      // 🔒 is 4 bytes: 0xF0 0x9F 0x94 0x92
      const emojiBytes = Buffer.from("🔒", "utf8");
      const part1 = emojiBytes.subarray(0, 2);
      const part2 = emojiBytes.subarray(2);

      const secret = ["ghp", "123456789012345678901234567890123456"].join("_");
      const chunk1 = Buffer.concat([Buffer.from("Key icon: "), part1]);
      const chunk2 = Buffer.concat([part2, Buffer.from(` Token=${secret}\n`)]);

      const transform = createRedactingStream(engine, "token");
      const output = await streamToString(Readable.from([chunk1, chunk2]).pipe(transform));

      assert.ok(output.includes("🔒"), "Multibyte UTF-8 emoji was corrupted across boundary!");
      assert.strictEqual(output.includes(secret), false, "Secret leaked in UTF-8 test!");
      assert.ok(output.includes("[AGENT_SHIELD:GITHUB_PAT:"));
    });
  });

  describe("3. Multiline PEM Private Key Streaming & Fail-Closed Windowing", () => {
    const rawRsaKey = [
      ["-----", "BEGIN RSA ", "PRIVATE KEY", "-----"].join(""),
      ["MIIEowIBA", "AKCAQEA0Y1", "+5K9r12345", "67890abcde", "fghijklmno", "pqrstuvwxyz"].join(""),
      ["1234567890", "abcdefghij", "klmnopqrst", "uvwxyz1234", "567890abcd", "efghijklmn"].join(""),
      ["-----", "END RSA ", "PRIVATE KEY", "-----"].join(""),
    ].join("\n");

    const rawOpenSshKey = [
      ["-----", "BEGIN OPENSSH ", "PRIVATE KEY", "-----"].join(""),
      [
        "b3BlbnNzaC",
        "1rZXktdjEA",
        "AAAABG5vbm",
        "UAAAAEbm9u",
        "ZQAAAAAAAA",
        "ABAAABlwAA",
        "AAdzc2gtcn",
      ].join(""),
      [
        "NhAAAAAwEA",
        "AQAAAYEAw7",
        "q9abcdefgh",
        "ijklmnopqr",
        "stuvwxyz12",
        "3456789012",
        "34",
      ].join(""),
      ["-----", "END OPENSSH ", "PRIVATE KEY", "-----"].join(""),
    ].join("\n");

    it("redacts multiline RSA and OpenSSH private keys streamed in 17-byte chunks", async () => {
      for (const pemKey of [rawRsaKey, rawOpenSshKey]) {
        const payload = `Certificate dump:\n${pemKey}\nDone\n`;
        const chunks: Buffer[] = [];
        for (let i = 0; i < payload.length; i += 17) {
          chunks.push(Buffer.from(payload.slice(i, i + 17), "utf8"));
        }

        let scrubbedCount = 0;
        const transform = createRedactingStream(engine, "token", (c) => {
          scrubbedCount += c;
        });

        const output = await streamToString(Readable.from(chunks).pipe(transform));

        assert.strictEqual(
          output.includes(["1234567890", "abcdefghij"].join("")),
          false,
          "RSA private key body leaked in chunks!",
        );
        assert.strictEqual(
          output.includes(["b3BlbnNzaC", "1rZXktdjEA"].join("")),
          false,
          "OpenSSH private key body leaked in chunks!",
        );
        assert.ok(
          output.includes("[AGENT_SHIELD:PRIVATE_KEY_BLOCK:"),
          "Missing private key block token",
        );
        assert.ok(scrubbedCount >= 1);
      }
    });

    it("fails closed on incomplete / truncated PEM private keys at EOF", async () => {
      // Incomplete private key with missing closing tag
      const truncatedPem = [
        ["-----", "BEGIN OPENSSH ", "PRIVATE KEY", "-----"].join(""),
        ["b3BlbnNzaC", "1rZXktdjEA", "AAAABG5vbm", "UAAAAEbm9u", "ZQ"].join(""),
      ].join("\n");

      let scrubbedCount = 0;
      const transform = createRedactingStream(engine, "token", (c) => {
        scrubbedCount += c;
      });

      const output = await streamToString(
        Readable.from([Buffer.from(truncatedPem, "utf8")]).pipe(transform),
      );

      assert.strictEqual(
        output.includes(["b3BlbnNzaC", "1rZXktdjEA"].join("")),
        false,
        "Truncated private key escaped unredacted at EOF!",
      );
      assert.ok(
        output.includes("[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED]"),
        "Expected fail-closed TRUNCATED tag for unclosed PEM key",
      );
      assert.ok(scrubbedCount >= 1);
    });

    it("fails closed on oversized unclosed PEM streams exceeding maxMultilineBuffer", async () => {
      let scrubbedCount = 0;
      // Configure low 2KB limit for testing
      const stream = new RedactingStream(engine, {
        maxMultilineBuffer: 2048,
        onSecretFound: (c) => {
          scrubbedCount += c;
        },
      });

      const startHeader = `${["-----", "BEGIN RSA ", "PRIVATE KEY", "-----"].join("")}\n`;
      const giantChunk = `${"A".repeat(3000)}\n`;

      const output = await streamToString(
        Readable.from([Buffer.from(startHeader, "utf8"), Buffer.from(giantChunk, "utf8")]).pipe(
          stream,
        ),
      );

      assert.strictEqual(
        output.includes("AAAA"),
        false,
        "Oversized open private key block leaked raw bytes!",
      );
      assert.ok(
        output.includes("[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED_OVERSIZED]"),
        "Expected fail-closed TRUNCATED_OVERSIZED tag",
      );
      assert.ok(scrubbedCount >= 1);
    });
  });

  describe("4. Long Single-Line Streams (Safe Delimiter Windowing)", () => {
    it("redacts secrets inside minified single-line JSON without newlines", async () => {
      const secret1 = ["sk", "proj", "1234567890123456789012345678901234567890"].join("-");
      const secret2 = ["ghp", "123456789012345678901234567890123456"].join("_");
      const padding = "x".repeat(600);

      const jsonLine = JSON.stringify({
        status: "ok",
        data: padding,
        openai_key: secret1,
        more_data: padding,
        github_token: secret2,
      });

      // Stream in 120-byte chunks without any newlines
      const chunks: Buffer[] = [];
      for (let i = 0; i < jsonLine.length; i += 120) {
        chunks.push(Buffer.from(jsonLine.slice(i, i + 120), "utf8"));
      }

      const transform = createRedactingStream(engine, "token");
      const output = await streamToString(Readable.from(chunks).pipe(transform));

      assert.strictEqual(output.includes(secret1), false, "OpenAI key leaked in minified JSON!");
      assert.strictEqual(output.includes(secret2), false, "GitHub token leaked in minified JSON!");
      assert.ok(output.includes("[AGENT_SHIELD:OPENAI_API_KEY:"));
      assert.ok(output.includes("[AGENT_SHIELD:GITHUB_PAT:"));
    });

    it("never cuts secrets across delimiter splits in long single-line streams", async () => {
      const secret = ["sk", "live", "1234567890123456789012345678"].join("_");
      // Build single line payload exceeding 2 * maxWindowSize (e.g. 1200 chars) with delimiter near the secret
      const prefix = "a".repeat(600);
      const payload = `${prefix} Bearer ${secret} ${prefix}`;

      const chunks: Buffer[] = [];
      for (let i = 0; i < payload.length; i += 150) {
        chunks.push(Buffer.from(payload.slice(i, i + 150), "utf8"));
      }

      const transform = createRedactingStream(engine, "token");
      const output = await streamToString(Readable.from(chunks).pipe(transform));

      assert.strictEqual(
        output.includes(secret),
        false,
        "Stripe secret leaked across delimiter window cut!",
      );
      assert.ok(output.includes("[AGENT_SHIELD:STRIPE_SECRET_KEY:"));
    });

    it("split-canary boundary regression test: 'x'.repeat(300) + 'CANARY_SECRET' + 'y'.repeat(120) with arbitrary chunk boundaries", async () => {
      const canarySecret = "CANARY_SECRET";
      const payload = "x".repeat(300) + canarySecret + "y".repeat(120);

      const canaryEngine = new AgentShieldEngine([
        {
          id: "CANARY_DETECTOR",
          name: "Canary Secret Detector",
          category: "generic",
          severity: "critical",
          regex: /CANARY_SECRET/g,
        },
      ]);

      // 1. Exhaustive 2-chunk boundary splits: test across every split point around and through the canary
      const canaryStart = 300;
      const canaryEnd = canaryStart + canarySecret.length;
      for (let split = canaryStart - 25; split <= canaryEnd + 25; split++) {
        const chunk1 = Buffer.from(payload.slice(0, split), "utf8");
        const chunk2 = Buffer.from(payload.slice(split), "utf8");

        const transform = createRedactingStream(canaryEngine, "token");
        const output = await streamToString(Readable.from([chunk1, chunk2]).pipe(transform));

        assert.strictEqual(
          output.includes(canarySecret),
          false,
          `Canary secret leaked when split at character index ${split}! Output: ${output}`,
        );
        assert.ok(
          output.includes("[AGENT_SHIELD:CANARY_DETECTOR:"),
          `Missing canary redaction token when split at index ${split}`,
        );
      }

      // 2. Arbitrary chunk sizes (from 1 byte up to 128 bytes)
      for (const chunkSize of [1, 13, 27, 42, 64, 128]) {
        const chunks: Buffer[] = [];
        for (let i = 0; i < payload.length; i += chunkSize) {
          chunks.push(Buffer.from(payload.slice(i, i + chunkSize), "utf8"));
        }

        const transform = createRedactingStream(canaryEngine, "token");
        const output = await streamToString(Readable.from(chunks).pipe(transform));

        assert.strictEqual(
          output.includes(canarySecret),
          false,
          `Canary secret leaked with chunk size ${chunkSize}!`,
        );
        assert.ok(
          output.includes("[AGENT_SHIELD:CANARY_DETECTOR:"),
          `Missing canary redaction token with chunk size ${chunkSize}`,
        );
      }
    });
  });
});
