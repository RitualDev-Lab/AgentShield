import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { GitPreCommitGate } from "../src/gate.js";

describe("Phase 1: Local Pre-Commit & Git Hooks Integration", () => {
  const tempRepo = join(
    tmpdir(),
    `agentshield-hook-test-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
  );

  before(() => {
    mkdirSync(tempRepo, { recursive: true });
    // Initialize temporary git repo
    execFileSync("git", ["init"], { cwd: tempRepo, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "AgentShield Tester"], {
      cwd: tempRepo,
      stdio: "ignore",
    });
    execFileSync("git", ["config", "user.email", "tester@agentshield.ritualdev.in"], {
      cwd: tempRepo,
      stdio: "ignore",
    });
  });

  after(() => {
    try {
      rmSync(tempRepo, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup on Windows
    }
  });

  it("should install git pre-commit hook in .git/hooks/pre-commit", () => {
    const gate = new GitPreCommitGate();
    const installed = gate.installHook(tempRepo);
    assert.strictEqual(installed, true);

    const hookFile = join(tempRepo, ".git", "hooks", "pre-commit");
    assert.strictEqual(existsSync(hookFile), true);
    const content = readFileSync(hookFile, "utf8");
    assert.ok(content.includes("# --- AgentShield Pre-Commit Gate ---"));
    assert.ok(content.includes("agentshield hook check"));
  });

  it("should not duplicate snippet if hook is installed multiple times", () => {
    const gate = new GitPreCommitGate();
    gate.installHook(tempRepo);
    gate.installHook(tempRepo);

    const hookFile = join(tempRepo, ".git", "hooks", "pre-commit");
    const content = readFileSync(hookFile, "utf8");
    const occurrences = (content.match(/# --- AgentShield Pre-Commit Gate ---/g) || []).length;
    assert.strictEqual(occurrences, 1);
  });

  it("should allow clean staged files to pass audit", () => {
    const cleanFile = join(tempRepo, "clean-code.ts");
    writeFileSync(cleanFile, "export const add = (a: number, b: number) => a + b;\n", "utf8");
    execFileSync("git", ["add", "clean-code.ts"], { cwd: tempRepo });

    const gate = new GitPreCommitGate();
    const result = gate.auditStagedFiles(tempRepo);

    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.blockedFiles.length, 0);
    assert.ok(result.report.includes("[PASSED]"));
  });

  it("should block commits staging critical credential files (e.g., .env)", () => {
    const envFile = join(tempRepo, ".env");
    writeFileSync(envFile, "DATABASE_URL=postgres://localhost:5432\n", "utf8");
    execFileSync("git", ["add", ".env"], { cwd: tempRepo });

    const gate = new GitPreCommitGate();
    const result = gate.auditStagedFiles(tempRepo);

    assert.strictEqual(result.passed, false);
    assert.ok(result.blockedFiles.includes(".env"));
    assert.ok(result.report.includes("CRITICAL_FILE"));
    assert.ok(result.report.includes(".env"));

    // Unstage .env so next tests are clean
    execFileSync("git", ["reset", ".env"], { cwd: tempRepo });
    rmSync(envFile, { force: true });
  });

  it("should block commits staging code with embedded secrets", () => {
    const leakedFile = join(tempRepo, "ai-client.ts");
    writeFileSync(
      leakedFile,
      'const apiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890LONG";\n',
      "utf8",
    );
    execFileSync("git", ["add", "ai-client.ts"], { cwd: tempRepo });

    const gate = new GitPreCommitGate();
    const result = gate.auditStagedFiles(tempRepo);

    assert.strictEqual(result.passed, false);
    assert.ok(result.blockedFiles.includes("ai-client.ts"));
    assert.ok(result.findingsCount >= 1);
    assert.ok(result.report.includes("SECRET_DETECTED"));

    // Unstage leakedFile
    execFileSync("git", ["reset", "ai-client.ts"], { cwd: tempRepo });
    rmSync(leakedFile, { force: true });
  });

  it("should configure Husky pre-commit hook when .husky directory exists", () => {
    const huskyDir = join(tempRepo, ".husky");
    mkdirSync(huskyDir, { recursive: true });

    const gate = new GitPreCommitGate();
    const configured = gate.installHuskyHook(tempRepo);
    assert.strictEqual(configured, true);

    const huskyHook = join(huskyDir, "pre-commit");
    assert.strictEqual(existsSync(huskyHook), true);
    const content = readFileSync(huskyHook, "utf8");
    assert.ok(content.includes("npx @ritualdev-lab/agentshield hook check"));
  });

  it("should cleanly uninstall git pre-commit hook", () => {
    const gate = new GitPreCommitGate();
    const uninstalled = gate.uninstallHook(tempRepo);
    assert.strictEqual(uninstalled, true);

    const hookFile = join(tempRepo, ".git", "hooks", "pre-commit");
    if (existsSync(hookFile)) {
      const content = readFileSync(hookFile, "utf8");
      assert.strictEqual(content.includes("# --- AgentShield Pre-Commit Gate ---"), false);
    }
  });
});
