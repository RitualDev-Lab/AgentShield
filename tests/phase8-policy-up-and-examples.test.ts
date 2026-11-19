import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import test from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import {
  generateDefaultRitualPolicyYaml,
  parseRitualPolicyYaml,
  resolveOrchestrationPlan,
} from "../src/policy-manifest.js";

test("Phase 8: parseRitualPolicyYaml parses and validates unified 3-layer ritual.policy.yaml", () => {
  const yaml = generateDefaultRitualPolicyYaml();
  const result = parseRitualPolicyYaml(yaml);

  assert.equal(result.valid, true, `Expected valid manifest, got: ${result.errors.join("; ")}`);
  assert.equal(result.errors.length, 0);
  assert.equal(result.manifest.version, "1.0");
  assert.equal(result.manifest.airGapped, true);
  assert.equal(result.manifest.agentshield.enabled, true);
  assert.equal(result.manifest.agentshield.sandboxProfile, "strict");
  assert.equal(result.manifest.dbshield.enabled, true);
  assert.equal(result.manifest.dbshield.listenPort, 5433);
  assert.equal(result.manifest.dbshield.safetyTier, "STRICT");
  assert.equal(result.manifest.skillprism.enabled, true);
  assert.equal(result.manifest.skillprism.listenPort, 4310);
  assert.equal(result.manifest.skillprism.promptGuard, true);

  const plan = resolveOrchestrationPlan(result.manifest, "ritual.policy.yaml");
  assert.deepEqual(plan.layersEnabled, ["agentshield", "dbshield", "skillprism"]);
  assert.equal(plan.steps.length, 3);
  assert.equal(plan.steps[1].env.RITUAL_AIR_GAPPED, "1");
  assert.equal(plan.steps[2].env.SKILLPRISM_PROMPT_GUARD, "1");
});

test("Phase 8: parseRitualPolicyYaml rejects port conflicts and invalid tiers/versions", () => {
  const badYaml = `
version: "9.9"
dbshield:
  enabled: true
  listenPort: 5433
  safetyTier: INVALID_TIER
skillprism:
  enabled: true
  listenPort: 5433
`;
  const result = parseRitualPolicyYaml(badYaml);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.includes("Unsupported policy schema version")));
  assert.ok(result.errors.some((e) => e.includes("Invalid dbshield.safetyTier")));
  assert.ok(result.errors.some((e) => e.includes("Port conflict")));
});

test("Phase 8: CLI 'agentshield up --config examples/ritual.policy.yaml --dry-run --json' resolves all 3 layers", () => {
  const repoRoot = resolve(".");
  const builtCli = resolve(repoRoot, "dist/cli.js");
  const tsxCli = resolve(repoRoot, "node_modules/tsx/dist/cli.mjs");
  const srcCli = resolve(repoRoot, "src/cli.ts");
  const configPath = resolve(repoRoot, "examples/ritual.policy.yaml");
  assert.ok(existsSync(configPath), "examples/ritual.policy.yaml must exist");

  const execArgs = existsSync(builtCli)
    ? [builtCli, "up", "--config", configPath, "--dry-run", "--json"]
    : [tsxCli, srcCli, "up", "--config", configPath, "--dry-run", "--json"];

  const stdout = execFileSync(process.execPath, execArgs, {
    encoding: "utf8",
    cwd: repoRoot,
  });

  const parsed = JSON.parse(stdout);
  assert.equal(parsed.valid, true);
  assert.equal(parsed.dryRun, true);
  assert.deepEqual(parsed.plan.layersEnabled, ["agentshield", "dbshield", "skillprism"]);
  assert.equal(parsed.plan.steps.length, 3);
  assert.equal(parsed.plan.airGapped, true);
});

test("Phase 8: consolidated examples (langgraph-starter & claude-code-starter) exist and pass smoke test", async () => {
  const langgraphAgent = resolve("examples/langgraph-starter/agent.py");
  const langgraphReqs = resolve("examples/langgraph-starter/requirements.txt");
  const claudeHook = resolve("examples/claude-code-starter/.claude/config.json");
  const claudeDemo = resolve("examples/claude-code-starter/demo-tool.js");

  assert.ok(existsSync(langgraphAgent));
  assert.ok(existsSync(langgraphReqs));
  assert.ok(existsSync(claudeHook));
  assert.ok(existsSync(claudeDemo));

  assert.match(readFileSync(langgraphReqs, "utf8"), /agentshield-defense>=0\.2\.2/);
  assert.match(readFileSync(claudeHook, "utf8"), /@ritualdev-lab\/agentshield@>=0\.2\.2/);

  // Smoke-test claude-code-starter demo-tool.js output through AgentShieldEngine
  const mod = await import("../examples/claude-code-starter/demo-tool.js");
  const rawPayload = JSON.stringify(mod.executeQuery("SELECT id FROM users LIMIT 1"));
  const engine = new AgentShieldEngine();
  const scan = engine.scanAndRedact(rawPayload);
  assert.ok(scan.findings.length >= 1, "Expected AgentShieldEngine to intercept synthetic PAT");
  assert.equal(scan.sanitizedText.includes("ghp_"), false, "Synthetic PAT must be fully redacted");
});
