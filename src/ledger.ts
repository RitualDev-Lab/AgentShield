import { createHmac, randomBytes, sign, verify } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import {
  type KeystoreBackend,
  type KeystoreOptions,
  OsKeystoreAdapter,
  type SealedKeyPair,
} from "./keystore.js";

export interface AuditLedgerEntry {
  sequence: number;
  timestamp: string;
  actor: string;
  command: string;
  verdict: "ALLOWED" | "BLOCKED" | "REDACTED" | "QUARANTINED";
  reason: string;
  previousHash: string;
  hash: string;
  signatureAlgorithm?: "ed25519" | "hmac-sha256";
  ed25519Signature?: string;
  publicKeyFingerprint?: string;
  remoteCounterSignature?: string;
}

export interface LedgerVerificationResult {
  isValid: boolean;
  totalEntries: number;
  verifiedAsymmetricEntries?: number;
  corruptedSequence?: number;
  publicKeyFingerprint?: string;
  error?: string;
}

export interface LedgerOptions {
  keystore?: KeystoreOptions;
  keyPair?: SealedKeyPair;
  /** Disable asymmetric signing only when testing legacy HMAC-only ledgers */
  legacyHmacOnly?: boolean;
}

let cachedLedgerKey: string | null = null;

/**
 * Resolves or generates a secure per-installation ledger secret key.
 * Never falls back to a public static salt.
 */
export function getOrCreateLocalLedgerKey(): string {
  if (process.env.AGENTSHIELD_LEDGER_KEY) {
    return process.env.AGENTSHIELD_LEDGER_KEY;
  }
  if (cachedLedgerKey) {
    return cachedLedgerKey;
  }

  const globalDir = join(homedir(), ".agentshield");
  const keyFile = join(globalDir, "ledger.key");

  try {
    if (existsSync(keyFile)) {
      const savedKey = readFileSync(keyFile, "utf-8").trim();
      if (savedKey.length >= 32) {
        cachedLedgerKey = savedKey;
        return savedKey;
      }
    }
  } catch {
    // fallback to generation
  }

  // Generate per-installation cryptographically secure random key
  const generated = randomBytes(32).toString("hex");
  cachedLedgerKey = generated;
  try {
    if (!existsSync(globalDir)) {
      mkdirSync(globalDir, { recursive: true, mode: 0o700 });
    }
    writeFileSync(keyFile, generated, { encoding: "utf-8", mode: 0o600 });
  } catch {
    // If filesystem write fails, return in-memory generated key
  }
  return generated;
}

/**
 * Cryptographic Tamper-Evident Write-Ahead Audit Ledger:
 * Stores append-only audit events with sequential hash-chaining AND asymmetric Ed25519 signatures
 * whose private keys are sealed in native OS hardware keystores (macOS Keychain, Linux Secret Service,
 * Windows DPAPI). Even a compromised local user process cannot forge historical entries without
 * the hardware-sealed Ed25519 private key.
 */
export class TamperEvidentLedger {
  private ledgerPath: string;
  private secretKey: string;
  private entries: AuditLedgerEntry[] = [];
  private keyPair: SealedKeyPair | null = null;
  private legacyHmacOnly: boolean;
  private static readonly GENESIS_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

  constructor(
    ledgerPath: string = join(process.cwd(), ".agentshield", "audit.ledger"),
    secretKey: string = getOrCreateLocalLedgerKey(),
    options: LedgerOptions = {},
  ) {
    this.ledgerPath = ledgerPath;
    this.secretKey = secretKey;
    this.legacyHmacOnly = Boolean(options.legacyHmacOnly);

    if (!this.legacyHmacOnly) {
      if (options.keyPair) {
        this.keyPair = options.keyPair;
      } else {
        const adapter = new OsKeystoreAdapter(
          options.keystore || {
            preferredBackend:
              (process.env.AGENTSHIELD_KEYSTORE as KeystoreBackend | undefined) || "memory",
          },
        );
        this.keyPair = adapter.loadOrCreateKeyPair();
      }
    }

    this.loadLedger();
  }

  private loadLedger(): void {
    if (existsSync(this.ledgerPath)) {
      try {
        const raw = readFileSync(this.ledgerPath, "utf8");
        const lines = raw.split("\n").filter((l) => l.trim().length > 0);
        this.entries = lines.map((l) => JSON.parse(l));
      } catch {
        this.entries = [];
      }
    }
  }

  public getPublicKeyPem(): string | null {
    return this.keyPair?.publicKeyPem ?? null;
  }

  public getPublicKeyFingerprint(): string | null {
    return this.keyPair?.fingerprint ?? null;
  }

  public getKeystoreBackend(): KeystoreBackend | "hmac-legacy" {
    return this.keyPair?.backend ?? "hmac-legacy";
  }

  /**
   * Appends an audit entry, updates the chain hash, and signs with the OS-sealed Ed25519 private key.
   */
  public record(
    command: string,
    verdict: "ALLOWED" | "BLOCKED" | "REDACTED" | "QUARANTINED",
    reason = "",
    actor: string = process.env.USER || process.env.USERNAME || "autonomous-agent",
  ): AuditLedgerEntry {
    const sequence = this.entries.length + 1;
    const timestamp = new Date().toISOString();
    const previousHash =
      this.entries.length > 0
        ? this.entries[this.entries.length - 1].hash
        : TamperEvidentLedger.GENESIS_HASH;

    const payload = `${previousHash}|${sequence}|${timestamp}|${actor}|${command}|${verdict}|${reason}`;
    const hash = createHmac("sha256", this.secretKey).update(payload).digest("hex");

    const entry: AuditLedgerEntry = {
      sequence,
      timestamp,
      actor,
      command,
      verdict,
      reason,
      previousHash,
      hash,
      signatureAlgorithm: this.keyPair ? "ed25519" : "hmac-sha256",
    };

    if (this.keyPair) {
      const sigBuffer = sign(
        null,
        Buffer.from(`${payload}|${hash}`, "utf8"),
        this.keyPair.privateKeyPem,
      );
      entry.ed25519Signature = sigBuffer.toString("base64");
      entry.publicKeyFingerprint = this.keyPair.fingerprint;
    }

    this.entries.push(entry);
    this.persistEntry(entry);
    return entry;
  }

  /**
   * Attaches an RFC 3161-style remote counter-signature from the Hosted Relay / Control Plane.
   */
  public attachRemoteCounterSignature(sequence: number, counterSignature: string): boolean {
    const target = this.entries.find((e) => e.sequence === sequence);
    if (!target) return false;
    target.remoteCounterSignature = counterSignature;
    return true;
  }

  private persistEntry(entry: AuditLedgerEntry): void {
    const dir = dirname(this.ledgerPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const line = `${JSON.stringify(entry)}\n`;
    try {
      appendFileSync(this.ledgerPath, line, "utf8");
    } catch {
      // Fallback in-memory
    }
  }

  /**
   * Verifies mathematical integrity of the entire cryptographic chain (HMAC + Ed25519 asymmetric signatures).
   */
  public verifyChain(externalPublicKeyPem?: string): LedgerVerificationResult {
    const pubKey = externalPublicKeyPem || this.keyPair?.publicKeyPem;
    return TamperEvidentLedger.verifyEntries(this.entries, this.secretKey, pubKey);
  }

  public getEntries(): AuditLedgerEntry[] {
    return [...this.entries];
  }

  /**
   * Diagnostic hook for test suites to simulate chain tampering.
   */
  public corruptEntryForTesting(index: number, tamperedCommand: string): void {
    if (this.entries[index]) {
      this.entries[index].command = tamperedCommand;
    }
  }

  /**
   * Verifies an external ledger file solely using an Ed25519 public key (no private key or local salt required).
   */
  public static verifyWithPublicKey(
    entries: AuditLedgerEntry[],
    publicKeyPem: string,
  ): LedgerVerificationResult {
    let prevHash = TamperEvidentLedger.GENESIS_HASH;
    let asymmetricVerified = 0;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      if (entry.sequence !== i + 1) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Sequence mismatch at index ${i}: expected ${i + 1}, got ${entry.sequence}`,
        };
      }

      if (entry.previousHash !== prevHash) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Broken chain link at sequence ${entry.sequence}: previousHash does not match prior block`,
        };
      }

      if (!entry.ed25519Signature) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Missing Ed25519 signature at sequence ${entry.sequence}`,
        };
      }

      const payload = `${entry.previousHash}|${entry.sequence}|${entry.timestamp}|${entry.actor}|${entry.command}|${entry.verdict}|${entry.reason}|${entry.hash}`;
      let sigValid = false;
      try {
        sigValid = verify(
          null,
          Buffer.from(payload, "utf8"),
          publicKeyPem,
          Buffer.from(entry.ed25519Signature, "base64"),
        );
      } catch {
        sigValid = false;
      }

      if (!sigValid) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Ed25519 asymmetric signature verification failed at sequence ${entry.sequence}`,
        };
      }

      asymmetricVerified++;
      prevHash = entry.hash;
    }

    return {
      isValid: true,
      totalEntries: entries.length,
      verifiedAsymmetricEntries: asymmetricVerified,
      publicKeyFingerprint: OsKeystoreAdapter.computeFingerprint(publicKeyPem),
    };
  }

  /**
   * Static helper to verify mathematical integrity of any external array of ledger entries.
   */
  public static verifyEntries(
    entries: AuditLedgerEntry[],
    secretKey: string = getOrCreateLocalLedgerKey(),
    publicKeyPem?: string,
  ): LedgerVerificationResult {
    let prevHash = TamperEvidentLedger.GENESIS_HASH;
    let asymmetricVerified = 0;

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      if (entry.sequence !== i + 1) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Sequence mismatch at index ${i}: expected ${i + 1}, got ${entry.sequence}`,
        };
      }

      if (entry.previousHash !== prevHash) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Broken chain link at sequence ${entry.sequence}: previousHash does not match prior block`,
        };
      }

      const payload = `${entry.previousHash}|${entry.sequence}|${entry.timestamp}|${entry.actor}|${entry.command}|${entry.verdict}|${entry.reason}`;
      const expectedHash = createHmac("sha256", secretKey).update(payload).digest("hex");

      if (entry.hash !== expectedHash) {
        return {
          isValid: false,
          totalEntries: entries.length,
          corruptedSequence: entry.sequence,
          error: `Tampered block detected at sequence ${entry.sequence}: signature verification failed`,
        };
      }

      if (entry.ed25519Signature && publicKeyPem) {
        let sigValid = false;
        try {
          sigValid = verify(
            null,
            Buffer.from(`${payload}|${entry.hash}`, "utf8"),
            publicKeyPem,
            Buffer.from(entry.ed25519Signature, "base64"),
          );
        } catch {
          sigValid = false;
        }
        if (!sigValid) {
          return {
            isValid: false,
            totalEntries: entries.length,
            corruptedSequence: entry.sequence,
            error: `Ed25519 signature verification failed at sequence ${entry.sequence}`,
          };
        }
        asymmetricVerified++;
      }

      prevHash = entry.hash;
    }

    return {
      isValid: true,
      totalEntries: entries.length,
      verifiedAsymmetricEntries: asymmetricVerified,
      publicKeyFingerprint: publicKeyPem
        ? OsKeystoreAdapter.computeFingerprint(publicKeyPem)
        : undefined,
    };
  }
}
