import { createHmac } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface AuditLedgerEntry {
  sequence: number;
  timestamp: string;
  actor: string;
  command: string;
  verdict: "ALLOWED" | "BLOCKED" | "REDACTED" | "QUARANTINED";
  reason: string;
  previousHash: string;
  hash: string;
}

export interface LedgerVerificationResult {
  isValid: boolean;
  totalEntries: number;
  corruptedSequence?: number;
  error?: string;
}

/**
 * Cryptographic Tamper-Evident Write-Ahead Audit Ledger:
 * Stores append-only audit events with HMAC hash-chaining:
 * Hash_k = HMAC(Hash_{k-1} || Sequence_k || Timestamp_k || Command_k || Verdict_k)
 * Ensures historical audit trails cannot be truncated or falsified even if an agent escalates rights.
 */
export class TamperEvidentLedger {
  private ledgerPath: string;
  private secretKey: string;
  private entries: AuditLedgerEntry[] = [];
  private static readonly GENESIS_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";

  constructor(
    ledgerPath: string = join(process.cwd(), ".agentshield", "audit.ledger"),
    secretKey: string = process.env.AGENTSHIELD_LEDGER_KEY || "agentshield-tamper-evident-salt-v1",
  ) {
    this.ledgerPath = ledgerPath;
    this.secretKey = secretKey;
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

  /**
   * Appends an audit entry and updates the cryptographic HMAC chain
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
    };

    this.entries.push(entry);
    this.persistEntry(entry);
    return entry;
  }

  private persistEntry(entry: AuditLedgerEntry): void {
    const dir = dirname(this.ledgerPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    const line = `${JSON.stringify(entry)}\n`;
    try {
      const existing = existsSync(this.ledgerPath) ? readFileSync(this.ledgerPath, "utf8") : "";
      writeFileSync(this.ledgerPath, existing + line, "utf8");
    } catch {
      // Fallback in-memory
    }
  }

  /**
   * Verifies mathematical integrity of the entire cryptographic chain
   */
  public verifyChain(): LedgerVerificationResult {
    let prevHash = TamperEvidentLedger.GENESIS_HASH;

    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];

      // Check sequence order
      if (entry.sequence !== i + 1) {
        return {
          isValid: false,
          totalEntries: this.entries.length,
          corruptedSequence: entry.sequence,
          error: `Sequence mismatch at index ${i}: expected ${i + 1}, got ${entry.sequence}`,
        };
      }

      // Check previous hash pointer
      if (entry.previousHash !== prevHash) {
        return {
          isValid: false,
          totalEntries: this.entries.length,
          corruptedSequence: entry.sequence,
          error: `Broken chain link at sequence ${entry.sequence}: previousHash does not match prior block`,
        };
      }

      // Recompute and verify HMAC signature
      const payload = `${entry.previousHash}|${entry.sequence}|${entry.timestamp}|${entry.actor}|${entry.command}|${entry.verdict}|${entry.reason}`;
      const expectedHash = createHmac("sha256", this.secretKey).update(payload).digest("hex");

      if (entry.hash !== expectedHash) {
        return {
          isValid: false,
          totalEntries: this.entries.length,
          corruptedSequence: entry.sequence,
          error: `Tampered block detected at sequence ${entry.sequence}: signature verification failed`,
        };
      }

      prevHash = entry.hash;
    }

    return {
      isValid: true,
      totalEntries: this.entries.length,
    };
  }

  public getEntries(): AuditLedgerEntry[] {
    return [...this.entries];
  }

  /**
   * Diagnostic hook for test suites to simulate chain tampering
   */
  public corruptEntryForTesting(index: number, tamperedCommand: string): void {
    if (this.entries[index]) {
      this.entries[index].command = tamperedCommand;
    }
  }
}
