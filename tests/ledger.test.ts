import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { KernelSandboxConfinement } from "../src/kernel.js";
import { TamperEvidentLedger } from "../src/ledger.js";

describe("Phase 3: OS Kernel Sandboxing & Tamper-Evident Ledger", () => {
  describe("Tamper-Evident Write-Ahead Audit Ledger", () => {
    it("should record chained audit events and verify HMAC signature integrity", () => {
      const tempPath = join(tmpdir(), `test-ledger-${Date.now()}.ledger`);
      const ledger = new TamperEvidentLedger(tempPath, "test-secret-salt-123");

      // Record three sequential verdicts
      const e1 = ledger.record("cat .env", "BLOCKED", "Protected env config");
      const e2 = ledger.record("git status", "ALLOWED", "Safe command");
      const e3 = ledger.record("curl https://remote.io", "REDACTED", "Filtered outbound token");

      assert.equal(e1.sequence, 1);
      assert.equal(e2.sequence, 2);
      assert.equal(e3.sequence, 3);
      assert.equal(e2.previousHash, e1.hash);
      assert.equal(e3.previousHash, e2.hash);

      const verification = ledger.verifyChain();
      assert.equal(verification.isValid, true);
      assert.equal(verification.totalEntries, 3);
    });

    it("should detect corrupted or tampered entries in the ledger", () => {
      const tempPath = join(tmpdir(), `test-ledger-tamper-${Date.now()}.ledger`);
      const ledger = new TamperEvidentLedger(tempPath, "salt-key");

      ledger.record("test1", "ALLOWED");
      ledger.record("test2", "BLOCKED");

      // Simulate malicious attacker tampering with an in-memory block
      ledger.corruptEntryForTesting(0, "tampered-command-injection");

      const verification = ledger.verifyChain();
      assert.equal(verification.isValid, false);
      assert.equal(verification.corruptedSequence, 1);
    });
  });

  describe("OS Kernel Micro-Sandboxing Confinement", () => {
    const sandbox = new KernelSandboxConfinement(process.cwd());

    it("should generate valid OS-specific confinement profiles", () => {
      const profile = sandbox.buildProfile();
      assert.ok(profile.os);
      assert.ok(profile.allowedWorkspace);
      assert.ok(profile.blockedPaths.length >= 3);
      assert.ok(profile.runnerScript.length > 0);
    });

    it("should intercept commands targeting protected system credential paths", () => {
      const dangerousCmd = "cat ~/.ssh/id_rsa";
      const check = sandbox.verifyTargetPaths(dangerousCmd);
      assert.equal(check.isSafe, false);
      assert.ok(check.reason?.includes("Kernel confinement violation"));

      const safeCmd = "npm test";
      const safeCheck = sandbox.verifyTargetPaths(safeCmd);
      assert.equal(safeCheck.isSafe, true);
    });
  });
});
