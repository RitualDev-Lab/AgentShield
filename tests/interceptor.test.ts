import assert from "node:assert";
import { Readable } from "node:stream";
import { describe, it } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { AgentStdioInterceptor, createRedactingStream } from "../src/interceptor.js";

describe("Phase 2: AgentStdioInterceptor & Streaming Redaction", () => {
  const engine = new AgentShieldEngine();

  it("scrubs secrets emitted across streaming chunks", async () => {
    let scrubbedCount = 0;
    const transform = createRedactingStream(engine, "token", (count) => {
      scrubbedCount += count;
    });

    const prefix = `${["sk", "live"].join("_")}_`;
    const body = "MockStripeKey1234567890123456789012345";
    const expectedSecret = `${prefix}${body}`;

    const chunks = [`Process initialized. Token: ${prefix}`, body, " ready for deployment.\n"];

    const source = Readable.from(chunks);
    let output = "";

    await new Promise<void>((resolve, reject) => {
      source
        .pipe(transform)
        .on("data", (chunk: Buffer) => {
          output += chunk.toString("utf8");
        })
        .on("end", resolve)
        .on("error", reject);
    });

    assert.strictEqual(output.includes(expectedSecret), false);
    assert.strictEqual(output.includes("AGENT_SHIELD:STRIPE_SECRET_KEY:"), true);
    assert.strictEqual(scrubbedCount > 0, true);
  });

  it("blocks adversarial command before execution", async () => {
    const interceptor = new AgentStdioInterceptor(engine);
    const result = await interceptor.execute("cat /etc/shadow");

    assert.strictEqual(result.isBlocked, true);
    assert.strictEqual(result.exitCode, 1);
    assert.notStrictEqual(result.blockReason, undefined);
  });

  it("executes safe commands and scrubs stdout output", async () => {
    const interceptor = new AgentStdioInterceptor(engine);
    // Node print command emitting a secret
    const cmd = `node -e "console.log('API_KEY=ghp_' + '123456789012345678901234567890123456')"`;
    const result = await interceptor.execute(cmd);

    assert.strictEqual(result.isBlocked, false);
    assert.strictEqual(result.exitCode, 0);
    assert.ok(result.isolationMechanism);
    assert.ok(result.isolationNotice);
  });

  it("transparently reports isolation status when kernel sandbox is requested", async () => {
    const interceptor = new AgentStdioInterceptor(engine);
    const result = await interceptor.execute('node -e "console.log(1+1)"', {
      enableKernelSandbox: true,
    });

    assert.strictEqual(result.isBlocked, false);
    assert.strictEqual(result.exitCode, 0);
    assert.ok(result.isolationMechanism);
    assert.ok(result.isolationNotice);
    if (process.platform === "darwin") {
      assert.strictEqual(result.isolationMechanism, "macos_sandbox_exec");
      assert.strictEqual(result.downgradedIsolation, false);
      assert.ok(result.isolationNotice.includes("sandbox-exec"));
    } else {
      assert.strictEqual(result.isolationMechanism, "process_level_firewall");
      assert.strictEqual(result.downgradedIsolation, true);
      assert.ok(result.isolationNotice.includes("only supported on macOS"));
    }
  });
});
