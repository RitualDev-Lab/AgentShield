import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test, { describe } from "node:test";
import { DodoPaymentsService, SPONSORED_PRODUCTS } from "../src/dodo-payments.js";

describe("Phase 3: Dodo Payments Sponsored Placements & Self-Serve Checkout Suite", () => {
  const service = new DodoPaymentsService(
    "IlOYnHQslUViToGJ.cVrp8qUVYfPVb2WeDXrh2C1iSxcYI5BDx-IHqJNlc8etLr0h",
    "test",
  );

  test("retrieves available sponsorship and audit products with correct pricing", () => {
    const products = service.getAvailableProducts();
    assert.ok(products["sponsor-verified-badge"]);
    assert.strictEqual(products["sponsor-verified-badge"].priceUsd, 29);
    assert.strictEqual(products["sponsor-verified-badge"].type, "one_time");

    assert.ok(products["devshelf-featured-spotlight"]);
    assert.strictEqual(products["devshelf-featured-spotlight"].priceUsd, 79);

    assert.ok(products["team-ci-gate"]);
    assert.strictEqual(products["team-ci-gate"].priceUsd, 19);
    assert.strictEqual(products["team-ci-gate"].type, "subscription");
  });

  test("creates valid checkout session payload and hosted URL for tool creators", async () => {
    const result = await service.createCheckoutSession({
      tierId: "sponsor-verified-badge",
      toolName: "SuperFile",
      repoUrl: "https://github.com/yorukot/superfile",
      customerEmail: "creator@superfile.dev",
      customerName: "SuperFile Maintainer",
    });

    assert.ok(result.sessionId.startsWith("cks_"));
    const parsedCheckoutUrl = new URL(result.checkoutUrl);
    assert.ok(
      parsedCheckoutUrl.hostname === "test.checkout.dodopayments.com" ||
        parsedCheckoutUrl.hostname === "checkout.dodopayments.com",
      "Checkout host must strictly match official Dodo Payments domain",
    );
    assert.strictEqual(result.product.id, "pdt_agentshield_verified_badge");
    assert.strictEqual(result.mode, "test");
  });

  test("validates webhook event signature correctly", () => {
    const secret = "test_webhook_secret_key";
    const payload = JSON.stringify({ event: "payment.succeeded", id: "pay_12345" });
    const validSignature = createHmac("sha256", secret).update(payload).digest("hex");

    const isValid = service.verifyWebhookEvent(payload, validSignature, secret);
    assert.strictEqual(isValid, true, "Authentic webhook signature must pass");

    const isTampered = service.verifyWebhookEvent(payload, "invalid_signature_hash", secret);
    assert.strictEqual(isTampered, false, "Tampered signature must be rejected");
  });
});
