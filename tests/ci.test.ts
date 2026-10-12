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
});
