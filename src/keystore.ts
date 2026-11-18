import { execFileSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join } from "node:path";

export type KeystoreBackend =
  | "macos-keychain"
  | "linux-keyring"
  | "windows-dpapi"
  | "file-0600"
  | "memory";

export interface SealedKeyPair {
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
  backend: KeystoreBackend;
}

export interface KeystoreOptions {
  serviceName?: string;
  accountName?: string;
  keyDir?: string;
  preferredBackend?: KeystoreBackend;
}

/**
 * OS Hardware Keystore Sealing Adapter for Ed25519 Audit Ledger Signing Keys.
 * Seals asymmetric private keys in native OS credential stores:
 * - macOS: Keychain (`security`)
 * - Linux: Secret Service (`secret-tool`) / Kernel Keyring (`keyctl`)
 * - Windows: DPAPI (`System.Security.Cryptography.ProtectedData`, CurrentUser scope)
 * Falls back cleanly to 0600-restricted key file or ephemeral memory in headless CI.
 */
export class OsKeystoreAdapter {
  private readonly serviceName: string;
  private readonly accountName: string;
  private readonly keyDir: string;
  private readonly preferredBackend?: KeystoreBackend;
  private memoryStore: SealedKeyPair | null = null;

  constructor(options: KeystoreOptions = {}) {
    this.serviceName = options.serviceName || "agentshield-ledger-ed25519";
    this.accountName = options.accountName || "ritualdev-audit-signer";
    this.keyDir = options.keyDir || join(homedir(), ".agentshield", "keys");
    this.preferredBackend =
      options.preferredBackend || (process.env.AGENTSHIELD_KEYSTORE as KeystoreBackend | undefined);
  }

  public static computeFingerprint(publicKeyPem: string): string {
    return `sha256:${createHash("sha256").update(publicKeyPem.trim()).digest("hex")}`;
  }

  public detectPreferredBackend(): KeystoreBackend {
    if (this.preferredBackend) {
      return this.preferredBackend;
    }
    if (process.env.CI === "true" || process.env.NODE_ENV === "test") {
      return "memory";
    }
    const os = platform();
    if (os === "darwin") return "macos-keychain";
    if (os === "win32") return "windows-dpapi";
    if (os === "linux") return "linux-keyring";
    return "file-0600";
  }

  public getPublicKeyPath(): string {
    return join(this.keyDir, `${this.serviceName}.pub.pem`);
  }

  private getSealedBlobPath(): string {
    return join(this.keyDir, `${this.serviceName}.sealed`);
  }

  private getFileKeyPath(): string {
    return join(this.keyDir, `${this.serviceName}.key.pem`);
  }

  /**
   * Loads an existing sealed Ed25519 keypair or generates and seals a new one.
   */
  public loadOrCreateKeyPair(): SealedKeyPair {
    if (this.memoryStore) {
      return this.memoryStore;
    }

    const backend = this.detectPreferredBackend();
    if (backend === "memory") {
      const generated = this.generateFreshPair("memory");
      this.memoryStore = generated;
      return generated;
    }

    const existing = this.tryLoadFromBackend(backend);
    if (existing) {
      this.memoryStore = existing;
      return existing;
    }

    const fresh = this.generateFreshPair(backend);
    const actualBackend = this.sealToBackend(fresh, backend);
    fresh.backend = actualBackend;
    this.persistPublicKey(fresh.publicKeyPem);
    this.memoryStore = fresh;
    return fresh;
  }

  private generateFreshPair(backend: KeystoreBackend): SealedKeyPair {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    return {
      publicKeyPem: publicKey,
      privateKeyPem: privateKey,
      fingerprint: OsKeystoreAdapter.computeFingerprint(publicKey),
      backend,
    };
  }

  private persistPublicKey(publicKeyPem: string): void {
    try {
      const pubPath = this.getPublicKeyPath();
      const dir = dirname(pubPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(pubPath, publicKeyPem, "utf8");
    } catch {
      // Non-fatal in read-only sandboxes
    }
  }

  private tryLoadFromBackend(backend: KeystoreBackend): SealedKeyPair | null {
    const pubPath = this.getPublicKeyPath();
    if (!existsSync(pubPath)) return null;

    let publicKeyPem = "";
    try {
      publicKeyPem = readFileSync(pubPath, "utf8");
    } catch {
      return null;
    }

    let privateKeyPem: string | null = null;
    let resolvedBackend: KeystoreBackend = backend;

    if (backend === "macos-keychain") {
      privateKeyPem = this.readMacOsKeychain();
    } else if (backend === "linux-keyring") {
      privateKeyPem = this.readLinuxKeyring();
    } else if (backend === "windows-dpapi") {
      privateKeyPem = this.readWindowsDpapi();
    }

    if (!privateKeyPem) {
      privateKeyPem = this.readFile0600();
      if (privateKeyPem) resolvedBackend = "file-0600";
    }

    if (!privateKeyPem) return null;

    return {
      publicKeyPem,
      privateKeyPem,
      fingerprint: OsKeystoreAdapter.computeFingerprint(publicKeyPem),
      backend: resolvedBackend,
    };
  }

  private sealToBackend(pair: SealedKeyPair, backend: KeystoreBackend): KeystoreBackend {
    if (backend === "macos-keychain" && this.writeMacOsKeychain(pair.privateKeyPem)) {
      return "macos-keychain";
    }
    if (backend === "linux-keyring" && this.writeLinuxKeyring(pair.privateKeyPem)) {
      return "linux-keyring";
    }
    if (backend === "windows-dpapi" && this.writeWindowsDpapi(pair.privateKeyPem)) {
      return "windows-dpapi";
    }
    if (this.writeFile0600(pair.privateKeyPem)) {
      return "file-0600";
    }
    return "memory";
  }

  private writeMacOsKeychain(privateKeyPem: string): boolean {
    try {
      const b64 = Buffer.from(privateKeyPem, "utf8").toString("base64");
      execFileSync(
        "security",
        ["add-generic-password", "-U", "-a", this.accountName, "-s", this.serviceName, "-w", b64],
        { stdio: "ignore", timeout: 3000 },
      );
      return true;
    } catch {
      return false;
    }
  }

  private readMacOsKeychain(): string | null {
    try {
      const b64 = execFileSync(
        "security",
        ["find-generic-password", "-a", this.accountName, "-s", this.serviceName, "-w"],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3000 },
      ).trim();
      return b64 ? Buffer.from(b64, "base64").toString("utf8") : null;
    } catch {
      return null;
    }
  }

  private writeLinuxKeyring(privateKeyPem: string): boolean {
    try {
      const b64 = Buffer.from(privateKeyPem, "utf8").toString("base64");
      execFileSync(
        "secret-tool",
        [
          "store",
          "--label=AgentShield Ed25519 Audit Signer",
          "service",
          this.serviceName,
          "account",
          this.accountName,
        ],
        { input: b64, stdio: ["pipe", "ignore", "ignore"], timeout: 3000 },
      );
      return true;
    } catch {
      return false;
    }
  }

  private readLinuxKeyring(): string | null {
    try {
      const b64 = execFileSync(
        "secret-tool",
        ["lookup", "service", this.serviceName, "account", this.accountName],
        { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3000 },
      ).trim();
      return b64 ? Buffer.from(b64, "base64").toString("utf8") : null;
    } catch {
      return null;
    }
  }

  private writeWindowsDpapi(privateKeyPem: string): boolean {
    try {
      const blobPath = this.getSealedBlobPath();
      const dir = dirname(blobPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const b64Plain = Buffer.from(privateKeyPem, "utf8").toString("base64");
      const script =
        "Add-Type -AssemblyName System.Security; " +
        "$plain = [Convert]::FromBase64String($env:AS_KEY_PLAIN); " +
        "$enc = [System.Security.Cryptography.ProtectedData]::Protect($plain, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); " +
        "[Convert]::ToBase64String($enc)";
      const protectedB64 = execFileSync(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", script],
        {
          encoding: "utf8",
          env: { ...process.env, AS_KEY_PLAIN: b64Plain },
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 4000,
        },
      ).trim();
      if (!protectedB64) return false;
      writeFileSync(blobPath, protectedB64, "utf8");
      return true;
    } catch {
      return false;
    }
  }

  private readWindowsDpapi(): string | null {
    try {
      const blobPath = this.getSealedBlobPath();
      if (!existsSync(blobPath)) return null;
      const protectedB64 = readFileSync(blobPath, "utf8").trim();
      const script =
        "Add-Type -AssemblyName System.Security; " +
        "$enc = [Convert]::FromBase64String($env:AS_KEY_BLOB); " +
        "$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser); " +
        "[Convert]::ToBase64String($plain)";
      const plainB64 = execFileSync(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", script],
        {
          encoding: "utf8",
          env: { ...process.env, AS_KEY_BLOB: protectedB64 },
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 4000,
        },
      ).trim();
      return plainB64 ? Buffer.from(plainB64, "base64").toString("utf8") : null;
    } catch {
      return null;
    }
  }

  private writeFile0600(privateKeyPem: string): boolean {
    try {
      const keyPath = this.getFileKeyPath();
      const dir = dirname(keyPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(keyPath, privateKeyPem, { encoding: "utf8", mode: 0o600 });
      try {
        chmodSync(keyPath, 0o600);
      } catch {
        // Ignore on Windows filesystems
      }
      return true;
    } catch {
      return false;
    }
  }

  private readFile0600(): string | null {
    try {
      const keyPath = this.getFileKeyPath();
      if (!existsSync(keyPath)) return null;
      return readFileSync(keyPath, "utf8");
    } catch {
      return null;
    }
  }
}
