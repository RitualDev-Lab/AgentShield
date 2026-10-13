import assert from "node:assert";
import { describe, it } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { GitPreCommitGate } from "../src/gate.js";
import { AgentCommandSandbox } from "../src/sandbox.js";

describe("Phase 1: Adversarial Red-Team & Bypass Test Suite", () => {
  const sandbox = new AgentCommandSandbox();
  const engine = new AgentShieldEngine();

  describe("1. Runtime Environment Dump Evasions", () => {
    it("should intercept node -p 'process.env.OPENAI_API_KEY'", () => {
      const res = sandbox.inspectCommand("node -p 'process.env.OPENAI_API_KEY'");
      assert.strictEqual(res.isBlocked, true);
    });

    it("should intercept node -e 'console.log(process.env)'", () => {
      const res = sandbox.inspectCommand("node -e 'console.log(process.env)'");
      assert.strictEqual(res.isBlocked, true);
    });

    it("should intercept python -c 'import os; print(os.environ)'", () => {
      const res = sandbox.inspectCommand("python -c 'import os; print(os.environ)'");
      assert.strictEqual(res.isBlocked, true);
    });

    it("should intercept deno and bun runtime env inspections", () => {
      assert.strictEqual(sandbox.inspectCommand("deno eval 'console.log(Deno.env.toObject())'").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("bun -e 'console.log(process.env)'").isBlocked, true);
    });
  });

  describe("2. Copy, Link, Archive & Binary Reader Evasions", () => {
    it("should intercept cp .env target and copy operations", () => {
      assert.strictEqual(sandbox.inspectCommand("cp .env /tmp/leak").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("copy .env.production leak.txt").isBlocked, true);
    });

    it("should intercept symlink creation targeting .env", () => {
      assert.strictEqual(sandbox.inspectCommand("ln -s .env safe_name.txt").isBlocked, true);
    });

    it("should intercept tar, zip, gzip archiving of .env", () => {
      assert.strictEqual(sandbox.inspectCommand("tar -czf archive.tar.gz .env").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("zip backup.zip .env").isBlocked, true);
    });

    it("should intercept base64, xxd, and hex readers targeting .env", () => {
      assert.strictEqual(sandbox.inspectCommand("base64 .env").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("xxd .env").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("git show HEAD:.env").isBlocked, true);
    });

    it("should intercept move, rename, rsync, install and openssl encryption targeting .env", () => {
      assert.strictEqual(sandbox.inspectCommand("mv .env /tmp/renamed").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("move .env safe.txt").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("rsync -av .env /tmp/").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("install .env /tmp/").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("openssl enc -in .env -out .env.enc").isBlocked, true);
    });
  });

  describe("3. Shell Obfuscation & Quote Splitting", () => {
    it("should neutralize quote-splitting: cat .e\"\"nv", () => {
      assert.strictEqual(sandbox.inspectCommand('cat .e""nv').isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("cat .e''nv").isBlocked, true);
    });

    it("should intercept wildcard and single-char glob evasion: cat .e?v", () => {
      assert.strictEqual(sandbox.inspectCommand("cat .e?v").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("cat .e*v").isBlocked, true);
    });

    it("should intercept compgen -v and declare -p environment dumps", () => {
      assert.strictEqual(sandbox.inspectCommand("compgen -v").isBlocked, true);
      assert.strictEqual(sandbox.inspectCommand("declare -p").isBlocked, true);
    });

    it("should decode and intercept inline base64 eval payloads", () => {
      // Y2F0IC5lbnY= is base64 for 'cat .env'
      assert.strictEqual(
        sandbox.inspectCommand("eval $(echo Y2F0IC5lbnY= | base64 -d)").isBlocked,
        true,
      );
    });
  });

  describe("4. Engine Hardening & Substring Collision Defense", () => {
    it("should mask raw findings by default unless includeRaw is explicitly requested", () => {
      const secret = "sk-proj-1234567890123456789012345678901234567890";
      const defaultResult = engine.scanAndRedact(`api_key = "${secret}"`);
      assert.strictEqual(defaultResult.hasSecrets, true);
      assert.notStrictEqual(defaultResult.findings[0].raw, secret);
      assert.strictEqual(defaultResult.findings[0].raw.includes("AGENT_SHIELD"), true);

      const optedInResult = engine.scanAndRedact(`api_key = "${secret}"`, { includeRaw: true });
      assert.strictEqual(optedInResult.findings[0].raw, secret);
    });

    it("should prevent substring collision when a shorter secret is contained within a longer secret", () => {
      const longSecret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890LONG";
      const shortSecret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
      const text = `key1 = "${longSecret}"\nkey2 = "${shortSecret}"`;

      const result = engine.scanAndRedact(text);
      assert.strictEqual(result.sanitizedText.includes(longSecret), false);
      assert.strictEqual(result.sanitizedText.includes(shortSecret), false);
      assert.strictEqual(result.sanitizedText.includes("LONG]"), false); // No corrupted trailing fragments
    });

    it("should gate vaultMap behind includeRaw to avoid returning plaintext credentials in SDK by default", () => {
      const secret = "sk-proj-1234567890123456789012345678901234567890";
      const defaultResult = engine.scanAndRedact(`api_key = "${secret}"`);
      assert.strictEqual(defaultResult.vaultMap.size, 0);

      const optedInResult = engine.scanAndRedact(`api_key = "${secret}"`, { includeRaw: true });
      assert.strictEqual(optedInResult.vaultMap.size > 0, true);
      assert.strictEqual(Array.from(optedInResult.vaultMap.values()).includes(secret), true);
    });

    it("should safely handle custom patterns without 'g' flag and zero-length matches without hanging", () => {
      const hungEngine = new AgentShieldEngine([
        {
          id: "custom-no-g",
          name: "Custom Pattern",
          category: "generic",
          severity: "high",
          regex: /\bSECRET_[a-z0-9]{12}\b/i, // Deliberately missing 'g'
          description: "No global flag test",
        },
      ]);

      const res = hungEngine.scanAndRedact("SECRET_9876543210ab first, and another SECRET_9876543210ab");
      assert.strictEqual(res.hasSecrets, true);
      assert.strictEqual(res.totalFound >= 1, true);
    });
  });

  describe("5. False Positive Guard: Public Keys Allowed", () => {
    it("should allow id_rsa.pub to be committed without blocking in an active git repository", async () => {
      const { execFileSync } = await import("node:child_process");
      const { mkdtempSync, rmSync, writeFileSync } = await import("node:fs");
      const { tmpdir } = await import("node:os");
      const { join } = await import("node:path");

      const tempRepo = mkdtempSync(join(tmpdir(), "agentshield-gate-test-"));
      try {
        execFileSync("git", ["init"], { cwd: tempRepo, stdio: "ignore" });
        execFileSync("git", ["config", "user.name", "TestUser"], { cwd: tempRepo, stdio: "ignore" });
        execFileSync("git", ["config", "user.email", "test@ritualdev.in"], { cwd: tempRepo, stdio: "ignore" });

        // Stage public key (should pass)
        const pubKeyContent = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC12345 user@example.com";
        writeFileSync(join(tempRepo, "id_rsa.pub"), pubKeyContent, "utf8");
        execFileSync("git", ["add", "id_rsa.pub"], { cwd: tempRepo, stdio: "ignore" });

        const originalCwd = process.cwd();
        try {
          process.chdir(tempRepo);
          const gate = new GitPreCommitGate();
          const auditPass = gate.auditStagedFiles();
          assert.strictEqual(auditPass.passed, true);
          assert.strictEqual(auditPass.blockedFiles.length, 0);

          // Now stage an actual private key and verify gate blocks it
          writeFileSync(join(tempRepo, "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n", "utf8");
          execFileSync("git", ["add", "id_rsa"], { cwd: tempRepo, stdio: "ignore" });

          const auditBlock = gate.auditStagedFiles();
          assert.strictEqual(auditBlock.passed, false);
          assert.strictEqual(auditBlock.blockedFiles.includes("id_rsa"), true);
        } finally {
          process.chdir(originalCwd);
        }
      } finally {
        rmSync(tempRepo, { recursive: true, force: true });
      }
    });
  });
});
