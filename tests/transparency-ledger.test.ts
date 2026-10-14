import assert from "node:assert/strict";
import test, { describe } from "node:test";
import { PublicTransparencyLedger } from "../src/transparency-ledger.js";

describe("Phase 4: Public Transparency Ledger & Automated Patron Badging Suite", () => {
  const ledger = new PublicTransparencyLedger();

  test("records entries and maintains cryptographic HMAC chain integrity", () => {
    const entry = ledger.record(
      "DONATION",
      "Sponsor Company Inc",
      500,
      "Enterprise AI Security Research Grant",
    );

    assert.ok(entry.sequence > 0);
    assert.strictEqual(entry.amountUsd, 500);
    assert.ok(entry.hash, "Entry must have computed HMAC hash");
    assert.ok(entry.previousHash, "Entry must link to previous hash");

    const verification = ledger.verifyChain();
    assert.strictEqual(verification.isValid, true, "Transparency ledger chain must be 100% valid");
  });

  test("computes accurate summary and bounty fund reserves", () => {
    const summary = ledger.getSummary();
    assert.ok(summary.totalInflowUsd >= 625);
    assert.ok(summary.totalBountiesPaidUsd >= 50);
    assert.ok(summary.currentDefenseFundReserveUsd > 0);
    assert.strictEqual(summary.isChainValid, true);
  });

  test("generates valid Patron Backer SVG badge with username", () => {
    const svg = PublicTransparencyLedger.generatePatronSvgBadge("alice_dev", "Security Patron");
    assert.ok(svg.includes("<svg"));
    assert.ok(svg.includes("AGENTSHIELD PATRON"));
    assert.ok(svg.includes("alice_dev"));
    assert.ok(svg.includes("Security Patron"));
    assert.ok(svg.includes("#f43f5e"));
  });
});
