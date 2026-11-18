import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  CoreRedactor,
  calculateShannonEntropy,
  redactStagedDiff,
  redactText,
} from "../src/core-redactor.js";
import { formatDoctorReport, runSandboxDoctor } from "../src/doctor.js";
import { OsKeystoreAdapter } from "../src/keystore.js";
import { TamperEvidentLedger } from "../src/ledger.js";

test("Phase 3: Ed25519 ledger signs entries and defeats HMAC-salt forgery", () => {
  const dir = mkdtempSync(join(tmpdir(), "ashield-p3-ledger-"));
  try {
    const ledgerPath = join(dir, "audit.ledger");
    const salt = "known-local-salt";
    const ledger = new TamperEvidentLedger(ledgerPath, salt, {
      keystore: { preferredBackend: "memory" },
    });

    const e1 = ledger.record("npm test", "ALLOWED", "safe dev command", "agent-1");
    const e2 = ledger.record("cat .env", "BLOCKED", "sensitive file access", "agent-1");

    assert.equal(e1.signatureAlgorithm, "ed25519");
    assert.ok(e1.ed25519Signature);
    assert.ok(e2.ed25519Signature);
    assert.equal(e2.previousHash, e1.hash);

    const pubKey = ledger.getPublicKeyPem();
    assert.ok(pubKey);

    // Public-key-only verification succeeds without any HMAC salt
    const pubVerify = TamperEvidentLedger.verifyWithPublicKey(ledger.getEntries(), pubKey);
    assert.equal(pubVerify.isValid, true);
    assert.equal(pubVerify.verifiedAsymmetricEntries, 2);

    // Attach remote counter-signature
    assert.equal(ledger.attachRemoteCounterSignature(2, "rfc3161-relay-sig-abc123"), true);

    // Simulate a compromised local process that knows `salt` and recomputes HMAC hashes
    const forgedEntries = ledger.getEntries().map((e) => ({ ...e }));
    forgedEntries[1].command = "echo benign";
    const forgedPayload = `${forgedEntries[1].previousHash}|${forgedEntries[1].sequence}|${forgedEntries[1].timestamp}|${forgedEntries[1].actor}|${forgedEntries[1].command}|${forgedEntries[1].verdict}|${forgedEntries[1].reason}`;
    forgedEntries[1].hash = createHmac("sha256", salt).update(forgedPayload).digest("hex");

    // Even with a valid forged HMAC hash, Ed25519 verification MUST reject the tampered block
    const forgedCheck = TamperEvidentLedger.verifyWithPublicKey(forgedEntries, pubKey);
    assert.equal(forgedCheck.isValid, false);
    assert.equal(forgedCheck.corruptedSequence, 2);
    assert.match(forgedCheck.error || "", /Ed25519/i);

    const dualCheck = TamperEvidentLedger.verifyEntries(forgedEntries, salt, pubKey);
    assert.equal(dualCheck.isValid, false);
    assert.equal(dualCheck.corruptedSequence, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Phase 3: OsKeystoreAdapter persists and reloads file-0600 Ed25519 keypair deterministically", () => {
  const dir = mkdtempSync(join(tmpdir(), "ashield-p3-ks-"));
  try {
    const adapter1 = new OsKeystoreAdapter({
      keyDir: dir,
      preferredBackend: "file-0600",
      serviceName: "test-ed25519",
    });
    const pair1 = adapter1.loadOrCreateKeyPair();
    assert.equal(pair1.backend, "file-0600");
    assert.ok(pair1.fingerprint.startsWith("sha256:"));

    const adapter2 = new OsKeystoreAdapter({
      keyDir: dir,
      preferredBackend: "file-0600",
      serviceName: "test-ed25519",
    });
    const pair2 = adapter2.loadOrCreateKeyPair();
    assert.equal(pair2.fingerprint, pair1.fingerprint);
    assert.equal(pair2.publicKeyPem, pair1.publicKeyPem);
    assert.equal(pair2.privateKeyPem, pair1.privateKeyPem);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Phase 3: runSandboxDoctor produces valid diagnostics across Linux, macOS, and Windows", () => {
  const liveReport = runSandboxDoctor();
  assert.ok(liveReport.checks.some((c) => c.id === "node-runtime" && c.status === "PASS"));
  assert.ok(liveReport.checks.some((c) => c.id === "crypto-ed25519" && c.status === "PASS"));
  const formatted = formatDoctorReport(liveReport);
  assert.match(formatted, /AgentShield Sandbox & Kernel Diagnostics/);

  const linuxReport = runSandboxDoctor({ platformOverride: "linux", dryRun: true });
  assert.ok(linuxReport.checks.some((c) => c.id === "linux-landlock"));
  assert.ok(linuxReport.checks.some((c) => c.id === "linux-bwrap"));
  assert.ok(linuxReport.checks.some((c) => c.id === "linux-apparmor-userns"));

  const macReport = runSandboxDoctor({ platformOverride: "darwin", dryRun: true });
  assert.ok(macReport.checks.some((c) => c.id === "macos-seatbelt"));
  assert.ok(macReport.checks.some((c) => c.id === "macos-keychain"));

  const winReport = runSandboxDoctor({ platformOverride: "win32", dryRun: true });
  assert.ok(winReport.checks.some((c) => c.id === "windows-dpapi"));
  assert.ok(winReport.checks.some((c) => c.id === "windows-sandbox-boundary"));
});

test("Phase 3: CoreRedactor detects secrets, entropy assignments, staged diffs, and stays linear-time", () => {
  const syntheticOpenAi = [
    "sk",
    "proj",
    `${"AbCdEfGh"}${"IjKlMnOp"}${"QrStUvWx"}${"Yz012345"}6789`,
  ].join("-");
  const syntheticAws = ["AKIA", "IOSFODNN", "7EXAMPLE"].join("");
  const syntheticGh = ["ghp", `${"12345678"}${"90abcdef"}${"ghijklmn"}${"opqrstuv"}wxyz1234`].join(
    "_",
  );
  const syntheticDsn = [
    "postgresql://",
    "admin",
    ":",
    "Sup3rS3cret",
    "P4ssword!@",
    "db.internal:5432/prod",
  ].join("");
  const syntheticHighEntropy = ["x9K!mP2q", "R7vW4nL8", "zB3cF6hJ", "1tY5dG0sA"].join("");

  const payload = [
    `OPENAI_KEY=${syntheticOpenAi}`,
    `AWS_ACCESS_KEY_ID=${syntheticAws}`,
    `GH_TOKEN=${syntheticGh}`,
    `DATABASE_URL="${syntheticDsn}"`,
    `api_secret_key = "${syntheticHighEntropy}"`,
  ].join("\n");

  const res = redactText(payload);
  assert.equal(res.hasSecrets, true);
  assert.ok(res.totalFound >= 4);
  assert.equal(res.sanitizedText.includes(syntheticOpenAi), false);
  assert.equal(res.sanitizedText.includes(syntheticAws), false);
  assert.equal(res.sanitizedText.includes(syntheticGh), false);
  assert.equal(res.sanitizedText.includes("P4ssword!"), false);

  // Shannon entropy check
  assert.ok(calculateShannonEntropy(syntheticHighEntropy) > 4.5);
  assert.ok(calculateShannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") < 1.0);

  // Adversarial 100KB payload must finish rapidly without ReDoS
  const adversarial = `${"sk-".repeat(30_000)} ${"a".repeat(20_000)}`;
  const redactor = new CoreRedactor({ maxScanMs: 25 });
  const advRes = redactor.scanAndRedact(adversarial);
  assert.ok(advRes.elapsedMs < 250, `Expected linear-time execution, got ${advRes.elapsedMs}ms`);

  // Staged Git diff AST/line redaction
  const diff = [
    "diff --git a/src/config.ts b/src/config.ts",
    "--- a/src/config.ts",
    "+++ b/src/config.ts",
    "@@ -10,3 +10,4 @@ export const cfg = {",
    "   env: 'prod',",
    `+  openaiKey: "${syntheticOpenAi}",`,
    " };",
  ].join("\n");

  const diffRes = redactStagedDiff(diff);
  assert.equal(diffRes.passed, false);
  assert.equal(diffRes.filesScanned, 1);
  assert.equal(diffRes.findings.length, 1);
  assert.equal(diffRes.findings[0].file, "src/config.ts");
  assert.equal(diffRes.findings[0].line, 11);
  assert.equal(diffRes.sanitizedDiff.includes(syntheticOpenAi), false);
});

test("Phase 3: Unified CLI supports doctor, db-proxy/compact dry-run routing, and ledger verify --pub-key", () => {
  const dir = mkdtempSync(join(tmpdir(), "ashield-p3-cli-"));
  try {
    const cliDist = join(process.cwd(), "dist", "cli.js");

    // 1. doctor --json
    const docOut = execFileSync(process.execPath, [cliDist, "doctor", "--json"], {
      encoding: "utf8",
    });
    const docJson = JSON.parse(docOut);
    assert.ok(Array.isArray(docJson.checks));
    assert.ok(docJson.overallStatus);

    // 2. db-proxy --dry-run
    const dbOut = execFileSync(process.execPath, [cliDist, "db-proxy", "--dry-run"], {
      encoding: "utf8",
    });
    const dbJson = JSON.parse(dbOut);
    assert.equal(dbJson.targetPackage, "@ritualdev-lab/dbshield");

    // 3. compact --dry-run
    const compactOut = execFileSync(process.execPath, [cliDist, "compact", "--dry-run"], {
      encoding: "utf8",
    });
    const compactJson = JSON.parse(compactOut);
    assert.equal(compactJson.targetPackage, "@ritualdev-lab/skillprism");

    // 4. ledger verify <path> --pub-key <pem> --json
    const ledgerPath = join(dir, "audit.ledger");
    const pubKeyPath = join(dir, "signer.pub.pem");
    const ledger = new TamperEvidentLedger(ledgerPath, "cli-test-salt", {
      keystore: { preferredBackend: "memory" },
    });
    ledger.record("git status", "ALLOWED", "readonly");
    writeFileSync(pubKeyPath, ledger.getPublicKeyPem() || "", "utf8");

    const verifyOut = execFileSync(
      process.execPath,
      [cliDist, "ledger", "verify", ledgerPath, "--pub-key", pubKeyPath, "--json"],
      { encoding: "utf8" },
    );
    const verifyJson = JSON.parse(verifyOut);
    assert.equal(verifyJson.isValid, true);
    assert.equal(verifyJson.verifiedAsymmetricEntries, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
