import assert from "node:assert/strict";
import test, { describe } from "node:test";
import { VerifiedBadgeGenerator } from "../src/badge-generator.js";

describe("Phase 2: Secured by AgentShield Verified Sponsor Badge Suite", () => {
  const toolName = "SuperFile";
  const repoUrl = "https://github.com/yorukot/superfile";

  test("generates deterministic HMAC audit signature and validates correctly", () => {
    const signature = VerifiedBadgeGenerator.signAuditRecord(toolName, repoUrl, "verified");
    assert.ok(signature, "Signature should not be empty");
    assert.strictEqual(typeof signature, "string");
    assert.strictEqual(signature.length, 16);

    // Verify valid signature
    const isValid = VerifiedBadgeGenerator.verifyAuditRecord(
      toolName,
      repoUrl,
      "verified",
      signature,
    );
    assert.strictEqual(isValid, true, "Valid audit signature must pass verification");

    // Verify tampered signature fails
    const tampered = VerifiedBadgeGenerator.verifyAuditRecord(
      toolName,
      repoUrl,
      "verified",
      "deadbeefcafebabe",
    );
    assert.strictEqual(tampered, false, "Tampered audit signature must be rejected");

    // Verify tier mismatch fails
    const tierMismatch = VerifiedBadgeGenerator.verifyAuditRecord(
      toolName,
      repoUrl,
      "sponsor",
      signature,
    );
    assert.strictEqual(tierMismatch, false, "Tier mismatch must fail verification");
  });

  test("renders valid SVG badge with correct dimensions and theme styling", () => {
    const verifiedSvg = VerifiedBadgeGenerator.generateSvgBadge(toolName, { tier: "verified" });
    assert.ok(verifiedSvg.includes("<svg"), "Output must contain SVG tag");
    assert.ok(verifiedSvg.includes("SECURED BY"), "Output must contain upper label");
    assert.ok(verifiedSvg.includes("AgentShield Zero-Leak"), "Output must contain Zero-Leak text");
    assert.ok(verifiedSvg.includes("#8b5cf6"), "Verified tier should use violet accent");

    const sponsorSvg = VerifiedBadgeGenerator.generateSvgBadge(toolName, { tier: "sponsor" });
    assert.ok(
      sponsorSvg.includes("AgentShield ★ Sponsor"),
      "Sponsor badge must include sponsor star",
    );
    assert.ok(sponsorSvg.includes("#ec4899"), "Sponsor tier should use hot pink accent");

    const owaspSvg = VerifiedBadgeGenerator.generateSvgBadge(toolName, { tier: "owasp-llm06" });
    assert.ok(
      owaspSvg.includes("OWASP LLM06 Compliant"),
      "OWASP badge must include OWASP LLM06 text",
    );
    assert.ok(owaspSvg.includes("#10b981"), "OWASP badge should use emerald accent");
  });

  test("generates valid markdown and html badge snippets for README.md", () => {
    const snippet = VerifiedBadgeGenerator.getMarkdownSnippet(
      toolName,
      "https://agentshield.ritualdev.in",
      "verified",
    );
    assert.ok(snippet.markdown.startsWith("[![Secured by AgentShield]("));
    const targetUrlMatch = snippet.markdown.match(/\((https:\/\/[^)]+)\)$/);
    assert.ok(targetUrlMatch, "Markdown snippet must contain target verify URL");
    const targetUrl = new URL(targetUrlMatch[1]);
    assert.strictEqual(targetUrl.origin, "https://agentshield.ritualdev.in");
    assert.strictEqual(targetUrl.pathname, "/verify/superfile");
    assert.ok(snippet.shieldsIoBadgeUrl.includes("Secured%20by"));
    assert.ok(snippet.html.includes("<img src="));

    // Test OWASP LLM06 markdown snippet
    const owaspSnippet = VerifiedBadgeGenerator.getMarkdownSnippet(
      toolName,
      "https://agentshield.ritualdev.in",
      "owasp-llm06",
    );
    assert.ok(owaspSnippet.markdown.includes("OWASP%20LLM06%20Compliant"));
    assert.ok(owaspSnippet.shieldsIoBadgeUrl.includes("10b981"));
  });
});
