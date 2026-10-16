import assert from "node:assert";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { AgentShieldSidecar } from "../src/sidecar.js";

describe("Phase 4: Multi-Language JSON-RPC Stdio Sidecar Daemon", () => {
  const sidecar = new AgentShieldSidecar();

  describe("1. Core JSON-RPC 2.0 Protocol Methods", () => {
    it("handles shield.ping", async () => {
      const req = JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "shield.ping",
      });

      const resStr = await sidecar.handleMessage(req);
      const res = JSON.parse(resStr);

      assert.strictEqual(res.id, 1);
      assert.strictEqual(res.result, "pong");
    });

    it("handles shield.health", async () => {
      const req = JSON.stringify({
        jsonrpc: "2.0",
        id: "health-check",
        method: "shield.health",
      });

      const resStr = await sidecar.handleMessage(req);
      const res = JSON.parse(resStr);

      assert.strictEqual(res.id, "health-check");
      assert.strictEqual(res.result.status, "ok");
      assert.ok(typeof res.result.version === "string");
      assert.ok(res.result.activePatternsCount > 0);
    });

    it("handles shield.scan for finding secrets", async () => {
      const prefix = ["sk", "ant", "api03"].join("-");
      const secret = `${prefix}-sampleSecretToken12345678901234567890`;
      const req = JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "shield.scan",
        params: {
          text: `Here is the key: ${secret}`,
        },
      });

      const resStr = await sidecar.handleMessage(req);
      const res = JSON.parse(resStr);

      assert.strictEqual(res.id, 2);
      assert.strictEqual(res.result.hasSecrets, true);
      assert.ok(res.result.findings.length > 0);
    });

    it("handles shield.scanAndRedact and shield.rehydrate lifecycle", async () => {
      const prefix = ["sk", "live"].join("_");
      const secret = `${prefix}_sampleStripeSecret12345678901234567890`;
      const input = `Stripe token=${secret} in config`;

      // 1. Redact
      const redactReq = JSON.stringify({
        jsonrpc: "2.0",
        id: "redact-1",
        method: "shield.scanAndRedact",
        params: {
          text: input,
          maskStyle: "token",
        },
      });

      const redactResStr = await sidecar.handleMessage(redactReq);
      const redactRes = JSON.parse(redactResStr);

      assert.strictEqual(redactRes.id, "redact-1");
      assert.strictEqual(redactRes.result.hasSecrets, true);
      assert.strictEqual(redactRes.result.sanitizedText.includes(secret), false);
      assert.ok(redactRes.result.sanitizedText.includes("[AGENT_SHIELD:"));

      // 2. Rehydrate
      const rehydrateReq = JSON.stringify({
        jsonrpc: "2.0",
        id: "rehydrate-1",
        method: "shield.rehydrate",
        params: {
          text: redactRes.result.sanitizedText,
        },
      });

      const rehydrateResStr = await sidecar.handleMessage(rehydrateReq);
      const rehydrateRes = JSON.parse(rehydrateResStr);

      assert.strictEqual(rehydrateRes.id, "rehydrate-1");
      assert.strictEqual(rehydrateRes.result.rehydratedText, input);
    });

    it("handles shield.inspectCommand for sandbox pre-flight checks", async () => {
      // Prohibited command
      const blockedReq = JSON.stringify({
        jsonrpc: "2.0",
        id: "cmd-1",
        method: "shield.inspectCommand",
        params: {
          command: "cat .env",
        },
      });

      const blockedResStr = await sidecar.handleMessage(blockedReq);
      const blockedRes = JSON.parse(blockedResStr);

      assert.strictEqual(blockedRes.result.isBlocked, true);
      assert.ok(blockedRes.result.reason.length > 0);

      // Permitted command
      const allowedReq = JSON.stringify({
        jsonrpc: "2.0",
        id: "cmd-2",
        method: "shield.inspectCommand",
        params: {
          command: "python -m pytest",
        },
      });

      const allowedResStr = await sidecar.handleMessage(allowedReq);
      const allowedRes = JSON.parse(allowedResStr);

      assert.strictEqual(allowedRes.result.isBlocked, false);
    });

    it("handles shield.evaluateCompliance", async () => {
      const compReq = JSON.stringify({
        jsonrpc: "2.0",
        id: "comp-1",
        method: "shield.evaluateCompliance",
        params: {
          findings: [],
          blockedCount: 2,
          frameworks: ["soc2", "pci_dss"],
        },
      });

      const compResStr = await sidecar.handleMessage(compReq);
      const compRes = JSON.parse(compResStr);

      assert.strictEqual(compRes.result.status, "NO_FINDINGS_IN_ASSESSED_CONTROLS");
      assert.strictEqual(compRes.result.score, 100);
      assert.ok(compRes.result.unassessedControls.length > 0);
    });
  });

  describe("2. Error Handling & Protocol Conformance", () => {
    it("returns -32700 Parse error on malformed JSON", async () => {
      const resStr = await sidecar.handleMessage("{ broken json: ");
      const res = JSON.parse(resStr);

      assert.strictEqual(res.id, null);
      assert.strictEqual(res.error.code, -32700);
      assert.ok(res.error.message.includes("Parse error"));
    });

    it("returns -32600 on missing or invalid method", async () => {
      const resStr = await sidecar.handleMessage(JSON.stringify({ id: 9 }));
      const res = JSON.parse(resStr);

      assert.strictEqual(res.id, 9);
      assert.strictEqual(res.error.code, -32600);
    });

    it("returns -32603 on unknown method", async () => {
      const resStr = await sidecar.handleMessage(
        JSON.stringify({ id: 10, method: "shield.unknownFunction" }),
      );
      const res = JSON.parse(resStr);

      assert.strictEqual(res.id, 10);
      assert.strictEqual(res.error.code, -32603);
      assert.ok(res.error.message.includes("not found"));
    });
  });

  describe("3. Stdio Server Streaming Pipeline", () => {
    it("processes line-delimited stream messages seamlessly", async () => {
      const inputStream = new PassThrough();
      const outputStream = new PassThrough();

      const server = sidecar.startStdioServer(inputStream, outputStream);

      const receivedLines: string[] = [];
      outputStream.on("data", (chunk: Buffer) => {
        const text = chunk.toString("utf8");
        for (const line of text.split("\n")) {
          if (line.trim()) receivedLines.push(line.trim());
        }
      });

      // Write two JSON-RPC commands
      inputStream.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 101, method: "shield.ping" })}\n`,
      );
      inputStream.write(
        `${JSON.stringify({ jsonrpc: "2.0", id: 102, method: "shield.health" })}\n`,
      );

      // Wait a moment for microtasks to flush
      await new Promise((r) => setTimeout(r, 50));

      assert.strictEqual(receivedLines.length, 2);

      const res1 = JSON.parse(receivedLines[0]);
      assert.strictEqual(res1.id, 101);
      assert.strictEqual(res1.result, "pong");

      const res2 = JSON.parse(receivedLines[1]);
      assert.strictEqual(res2.id, 102);
      assert.strictEqual(res2.result.status, "ok");

      server.close();
    });
  });
});
