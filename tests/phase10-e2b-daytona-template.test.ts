import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { AgentCommandSandbox } from "../src/sandbox.js";

const TEMPLATE_DIR = resolve("examples/e2b-daytona-template");

test("Phase 10: E2B / Daytona cloud sandbox template ships hardened Dockerfile, DevContainer, and entrypoint", () => {
  const dockerfilePath = resolve(TEMPLATE_DIR, "e2b.Dockerfile");
  const devcontainerPath = resolve(TEMPLATE_DIR, "daytona-devcontainer.json");
  const entrypointPath = resolve(TEMPLATE_DIR, "entrypoint.sh");
  const readmePath = resolve(TEMPLATE_DIR, "README.md");

  assert.ok(existsSync(dockerfilePath), "e2b.Dockerfile must exist");
  assert.ok(existsSync(devcontainerPath), "daytona-devcontainer.json must exist");
  assert.ok(existsSync(entrypointPath), "entrypoint.sh must exist");
  assert.ok(existsSync(readmePath), "README.md must exist");

  const dockerfile = readFileSync(dockerfilePath, "utf8");
  assert.match(dockerfile, /@ritualdev-lab\/agentshield@>=0\.2\.2/);
  assert.match(dockerfile, /@ritualdev-lab\/dbshield@>=0\.2\.1/);
  assert.match(dockerfile, /USER 10001:10001/);
  assert.match(dockerfile, /RITUAL_AIR_GAPPED=1/);
  assert.match(dockerfile, /DBSHIELD_SAFETY_TIER=STRICT/);
  assert.match(dockerfile, /ENTRYPOINT \["\/usr\/local\/bin\/ritual-entrypoint\.sh"\]/);

  const devcontainer = JSON.parse(readFileSync(devcontainerPath, "utf8"));
  assert.equal(devcontainer.remoteUser, "agent");
  assert.equal(devcontainer.containerEnv.RITUAL_AIR_GAPPED, "1");
  assert.equal(devcontainer.containerEnv.DBSHIELD_SAFETY_TIER, "STRICT");
  assert.ok(devcontainer.runArgs.includes("--cap-drop=ALL"));
  assert.ok(devcontainer.runArgs.includes("--security-opt=no-new-privileges:true"));
  assert.ok(devcontainer.runArgs.includes("--read-only"));
  assert.ok(devcontainer.forwardPorts.includes(5433));
  assert.ok(
    devcontainer.customizations.vscode.extensions.includes("ritualdev-lab.agentshield-defense"),
  );

  const entrypoint = readFileSync(entrypointPath, "utf8");
  assert.match(entrypoint, /set -euo pipefail/);
  assert.match(entrypoint, /agentshield doctor --json/);
  assert.match(entrypoint, /agentshield exec/);
});

test("Phase 10: step-by-step microVM tool & credential interception enforces zero-leak guarantees", () => {
  const sandbox = new AgentCommandSandbox();
  const engine = new AgentShieldEngine();

  // Step 1: Benign workspace command permitted inside microVM
  const safeCheck = sandbox.inspectCommand("git status --short");
  assert.equal(safeCheck.isBlocked, false);

  // Step 2: Adversarial credential dump command blocked before execution
  const envDump = sandbox.inspectCommand("cat /proc/self/environ && cat .env");
  assert.equal(envDump.isBlocked, true);

  // Step 3: Tool output carrying synthetic runtime credential is redacted cleanly
  const syntheticPat = ["ghp", "a".repeat(36)].join("_");
  const redacted = engine.scanAndRedact(`psql output: token=${syntheticPat}`);
  assert.ok(redacted.findings.length >= 1);
  assert.equal(redacted.sanitizedText.includes(syntheticPat), false);
});
