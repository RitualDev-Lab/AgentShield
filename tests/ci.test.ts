import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CiGateRunner } from "../src/ci.js";

describe("AgentShield CI/CD Security Gate", () => {
  it("should initialize CiGateRunner in workspace", () => {
    const runner = new CiGateRunner(process.cwd());
    assert.ok(runner);
  });

  it("should run auditPullRequest without crashing", () => {
    const runner = new CiGateRunner(process.cwd());
    const result = runner.auditPullRequest("HEAD");
    assert.ok(typeof result.passed === "boolean");
    assert.ok(typeof result.markdownReport === "string");
    assert.ok(result.markdownReport.includes("AgentShield CI/CD Security Gate Report"));
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
