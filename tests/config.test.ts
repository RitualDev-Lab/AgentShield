import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { type AgentShieldConfig, parseCustomPatterns } from "../src/config.js";

describe("AgentShield Team Config Parser", () => {
  it("should return empty array if no custom patterns are provided", () => {
    assert.deepEqual(parseCustomPatterns(null), []);
    assert.deepEqual(parseCustomPatterns({}), []);
    assert.deepEqual(parseCustomPatterns({ customPatterns: [] }), []);
  });

  it("should compile valid custom regex patterns", () => {
    const config: AgentShieldConfig = {
      version: "1.0.0",
      customPatterns: [
        {
          id: "internal-corp-token",
          name: "Internal Corporate Secret Token",
          regex: "CORP_SEC_[a-zA-Z0-9]{12}",
          severity: "critical",
          category: "generic",
        },
      ],
    };

    const patterns = parseCustomPatterns(config);
    assert.equal(patterns.length, 1);
    assert.equal(patterns[0].id, "internal-corp-token");
    assert.equal(patterns[0].severity, "critical");

    const sample = "Authorization: CORP_SEC_abc123XYZ999";
    assert.equal(patterns[0].regex.test(sample), true);
  });

  it("should safely ignore malformed regex patterns without throwing", () => {
    const config: AgentShieldConfig = {
      customPatterns: [
        {
          id: "invalid-rule",
          name: "Broken Regex Rule",
          regex: "[a-z(+broken",
        },
        {
          id: "valid-rule",
          name: "Good Rule",
          regex: "VALID_[0-9]{4}",
        },
      ],
    };

    const patterns = parseCustomPatterns(config);
    assert.equal(patterns.length, 1);
    assert.equal(patterns[0].id, "valid-rule");
  });

  it("should allow configuring allowlist and maskStyle on engine", async () => {
    const { AgentShieldEngine } = await import("../src/engine.js");
    const engine = new AgentShieldEngine();

    const allowedSecret = ["sk_live_", "ALLOWEDTOKEN123456789012345"].join("");
    const res = engine.scanAndRedact(`Authorization: ${allowedSecret}`, {
      allowlist: [allowedSecret],
    });
    assert.equal(res.hasSecrets, false);

    const targetSecret = ["sk_live_", "TARGETTOKEN987654321012345"].join("");
    const asteriskRes = engine.scanAndRedact(`Authorization: ${targetSecret}`, {
      maskStyle: "asterisk",
    });
    assert.equal(asteriskRes.hasSecrets, true);
    assert.equal(asteriskRes.sanitizedText.includes("********"), true);
  });
});
