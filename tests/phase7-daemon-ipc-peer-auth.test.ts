import assert from "node:assert/strict";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";
import { AgentShieldDaemon } from "../src/daemon.js";

function makeTempSocketPath(tag: string): string {
  const id = `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
  return process.platform === "win32"
    ? `\\\\.\\pipe\\agentshield-p7-${tag}-${id}`
    : path.join(os.tmpdir(), `agentshield-p7-${tag}-${id}.sock`);
}

function sendRawLine(socketPath: string, payload?: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath);
    let data = "";
    const timer = setTimeout(() => {
      client.destroy();
      resolve(data);
    }, 1500);

    client.on("connect", () => {
      if (payload && !client.destroyed && client.writable) {
        client.write(`${payload}\n`, () => {});
      }
    });
    client.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.includes("\n")) {
        clearTimeout(timer);
        client.destroy();
        resolve(data.trim());
      }
    });
    client.on("end", () => {
      clearTimeout(timer);
      resolve(data.trim());
    });
    client.on("error", (err) => {
      clearTimeout(timer);
      if (data.trim()) resolve(data.trim());
      else reject(err);
    });
  });
}

test("Phase 7 (SEC-07): agentshieldd rejects untrusted peer UID via SO_PEERCRED guard with EACCES", async () => {
  const socketPath = makeTempSocketPath("reject");
  const daemon = new AgentShieldDaemon({
    socketPath,
    authSecret: "super-secret-daemon-token-32bytes",
    allowedUids: [1000],
    requirePeerCredentials: true,
    peerCredentialResolver: () => ({ uid: 65534, gid: 65534, pid: 9999 }), // untrusted nobody UID
  });

  await daemon.start();
  try {
    const rawResp = await sendRawLine(
      socketPath,
      JSON.stringify({ id: "1", action: "POLICY_SET", policy: { blockEnvReads: false } }),
    );
    const parsed = JSON.parse(rawResp);
    assert.equal(parsed.ok, false);
    assert.equal(parsed.code, "EACCES");
    assert.match(parsed.error, /Unauthorized IPC peer UID 65534/i);
  } finally {
    await daemon.stop();
  }
});

test("Phase 7 (SEC-07): agentshieldd rejects unauthenticated POLICY_SET and allows verified same-UID + token", async () => {
  const socketPath = makeTempSocketPath("allow");
  const secret = "verified-peer-token-0123456789abcdef";
  const daemon = new AgentShieldDaemon({
    socketPath,
    authSecret: secret,
    allowedUids: [1000],
    requirePeerCredentials: true,
    peerCredentialResolver: () => ({ uid: 1000, gid: 1000, pid: process.pid }),
  });

  await daemon.start();
  try {
    // 1. Unauthenticated POLICY_SET must fail with EACCES
    const unauthRaw = await sendRawLine(
      socketPath,
      JSON.stringify({ id: "unauth-1", action: "POLICY_SET", policy: { strict: false } }),
    );
    const unauth = JSON.parse(unauthRaw);
    assert.equal(unauth.ok, false);
    assert.equal(unauth.code, "EACCES");

    // 2. Authenticated same-UID peer succeeds
    const authResp = await new Promise<string>((resolve, reject) => {
      const client = net.createConnection(socketPath);
      let buf = "";
      let step = 0;
      client.on("connect", () => {
        client.write(`${JSON.stringify({ id: "a1", action: "AUTH", token: secret })}\n`);
      });
      client.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        const lines = buf.split("\n");
        buf = lines.pop() || "";
        for (const line of lines) {
          if (!line.trim()) continue;
          if (step === 0) {
            step = 1;
            const authJson = JSON.parse(line);
            assert.equal(authJson.ok, true);
            assert.equal(authJson.peerUid, 1000);
            client.write(
              `${JSON.stringify({ id: "p1", action: "POLICY_SET", policy: { strict: true } })}\n`,
            );
          } else {
            client.end();
            resolve(line);
          }
        }
      });
      client.on("error", reject);
    });

    const policyJson = JSON.parse(authResp);
    assert.equal(policyJson.ok, true);
    assert.equal(policyJson.policy.strict, true);
  } finally {
    await daemon.stop();
  }
});
