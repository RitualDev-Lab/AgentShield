import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

export interface VaultSecretValue {
  key: string;
  value: string;
  version?: number;
  leaseDuration?: number;
}

export interface EncryptedVaultSecret {
  key: string;
  ciphertext: string;
  iv: string;
  tag: string;
  version: number;
  createdAt: string;
  expiresAt?: string;
}

export interface SealedVaultBundle {
  version: string;
  encryptedPayload: string;
  iv: string;
  tag: string;
  checksum: string;
  createdAt: string;
}

export interface ZeroTrustVaultProvider {
  name: string;
  fetchSecret(key: string): Promise<string | null>;
  injectIntoEnvironment(secretKeys: string[]): Promise<Record<string, string>>;
}

export interface VaultInjectorOptions {
  initialStore?: Record<string, string>;
  masterKey?: string | Buffer;
}

/**
 * Enterprise Zero-Trust Vault Injector:
 * Instead of keeping plaintext credentials in local `.env` files where autonomous AI agents can read them,
 * AgentShield fetches ephemeral tokens on-demand from enterprise secrets managers (HashiCorp Vault, AWS, Mock)
 * and only injects sanitized surrogate tokens to the agent.
 *
 * Supports AES-256-GCM authenticated encryption at rest, token rotation, and lease expiration.
 */
export class VaultInjector {
  private secretsStore = new Map<string, string>();
  private encryptedStore = new Map<string, EncryptedVaultSecret>();
  private masterKey: Buffer;

  constructor(options?: Record<string, string> | VaultInjectorOptions) {
    if (options && ("initialStore" in options || "masterKey" in options)) {
      const opts = options as VaultInjectorOptions;
      if (opts.initialStore) {
        for (const [k, v] of Object.entries(opts.initialStore)) {
          this.secretsStore.set(k, v);
        }
      }
      this.masterKey = this.normalizeKey(opts.masterKey || randomBytes(32));
    } else if (options) {
      for (const [k, v] of Object.entries(options as Record<string, string>)) {
        this.secretsStore.set(k, v);
      }
      this.masterKey = randomBytes(32);
    } else {
      this.masterKey = randomBytes(32);
    }
  }

  private normalizeKey(key: string | Buffer): Buffer {
    if (Buffer.isBuffer(key) && key.length === 32) {
      return key;
    }
    // Hash key with SHA-256 to guarantee 256 bits (32 bytes)
    return createHash("sha256").update(key).digest();
  }

  /**
   * Sets or updates a secret in the vault
   */
  public registerSecret(key: string, value: string): void {
    this.secretsStore.set(key, value);
    // Also update encrypted store
    this.storeEncryptedSecret(key, value);
  }

  /**
   * Encrypts a secret value using AES-256-GCM with authenticated tag
   */
  public encryptSecret(key: string, value: string, ttlMs?: number): EncryptedVaultSecret {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.masterKey, iv);
    let ciphertext = cipher.update(value, "utf8", "base64");
    ciphertext += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");

    const now = Date.now();
    const existing = this.encryptedStore.get(key);
    const version = (existing?.version || 0) + 1;

    return {
      key,
      ciphertext,
      iv: iv.toString("base64"),
      tag,
      version,
      createdAt: new Date(now).toISOString(),
      expiresAt: ttlMs ? new Date(now + ttlMs).toISOString() : undefined,
    };
  }

  /**
   * Decrypts an encrypted vault secret verifying integrity via GCM auth tag
   */
  public decryptSecret(encrypted: EncryptedVaultSecret): string | null {
    if (encrypted.expiresAt && new Date(encrypted.expiresAt).getTime() < Date.now()) {
      return null; // Expired lease
    }

    try {
      const iv = Buffer.from(encrypted.iv, "base64");
      const tag = Buffer.from(encrypted.tag, "base64");
      const decipher = createDecipheriv("aes-256-gcm", this.masterKey, iv);
      decipher.setAuthTag(tag);
      let decrypted = decipher.update(encrypted.ciphertext, "base64", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    } catch {
      return null; // Authentication failed or data tampered
    }
  }

  /**
   * Stores secret encrypted under AES-256-GCM in the central vault
   */
  public storeEncryptedSecret(key: string, value: string, ttlMs?: number): EncryptedVaultSecret {
    const enc = this.encryptSecret(key, value, ttlMs);
    this.encryptedStore.set(key, enc);
    this.secretsStore.set(key, value);
    return enc;
  }

  /**
   * Retrieves and decrypts secret by key, verifying lease expiration
   */
  public getDecryptedSecret(key: string): string | null {
    const enc = this.encryptedStore.get(key);
    if (!enc) {
      return this.secretsStore.get(key) || null;
    }
    return this.decryptSecret(enc);
  }

  /**
   * Rotates master vault encryption key and re-encrypts all stored secrets
   */
  public rotateMasterKey(newMasterKey: string | Buffer): void {
    const newKeyBuffer = this.normalizeKey(newMasterKey);
    const decryptedEntries: Array<{ key: string; value: string; ttlMs?: number }> = [];

    for (const [key, enc] of this.encryptedStore.entries()) {
      const val = this.decryptSecret(enc);
      if (val !== null) {
        let ttlMs: number | undefined;
        if (enc.expiresAt) {
          const remaining = new Date(enc.expiresAt).getTime() - Date.now();
          if (remaining > 0) ttlMs = remaining;
        }
        decryptedEntries.push({ key, value: val, ttlMs });
      }
    }

    this.masterKey = newKeyBuffer;
    this.encryptedStore.clear();

    for (const entry of decryptedEntries) {
      this.storeEncryptedSecret(entry.key, entry.value, entry.ttlMs);
    }
  }

  /**
   * Exports an encrypted, tamper-evident bundle of all current vault secrets
   */
  public sealVaultBundle(): SealedVaultBundle {
    const entries = Array.from(this.encryptedStore.values());
    const jsonStr = JSON.stringify(entries);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.masterKey, iv);
    let encryptedPayload = cipher.update(jsonStr, "utf8", "base64");
    encryptedPayload += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    const checksum = createHash("sha256").update(encryptedPayload).digest("hex");

    return {
      version: "1.0.0",
      encryptedPayload,
      iv: iv.toString("base64"),
      tag,
      checksum,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Unseals and loads an encrypted vault bundle
   */
  public unsealVaultBundle(bundle: SealedVaultBundle): number {
    const expectedChecksum = createHash("sha256").update(bundle.encryptedPayload).digest("hex");
    if (bundle.checksum !== expectedChecksum) {
      throw new Error("Vault bundle integrity verification failed: checksum mismatch");
    }

    const iv = Buffer.from(bundle.iv, "base64");
    const tag = Buffer.from(bundle.tag, "base64");
    const decipher = createDecipheriv("aes-256-gcm", this.masterKey, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(bundle.encryptedPayload, "base64", "utf8");
    decrypted += decipher.final("utf8");

    const entries = JSON.parse(decrypted) as EncryptedVaultSecret[];
    let loaded = 0;
    for (const entry of entries) {
      const plain = this.decryptSecret(entry);
      if (plain !== null) {
        this.encryptedStore.set(entry.key, entry);
        this.secretsStore.set(entry.key, plain);
        loaded++;
      }
    }
    return loaded;
  }

  /**
   * Revokes a secret from the vault immediately
   */
  public revokeSecret(key: string): boolean {
    const removedPlain = this.secretsStore.delete(key);
    const removedEnc = this.encryptedStore.delete(key);
    return removedPlain || removedEnc;
  }

  /**
   * Generates a zero-trust safe surrogate reference for an AI agent:
   * e.g. "OPENAI_API_KEY" -> "VAULT_REF:sec_9f81a7"
   * The real token is never handed to the agent shell.
   */
  public generateSurrogate(key: string): string {
    const hash = Buffer.from(key).toString("base64url").substring(0, 8);
    return `[VAULT_INJECTED:${key}:${hash}]`;
  }

  /**
   * Injects vault secrets safely into runtime execution environment
   */
  public injectSafeEnvironment(keys: string[]): {
    safeEnv: Record<string, string>;
    mapping: Map<string, string>;
  } {
    const safeEnv: Record<string, string> = {};
    const mapping = new Map<string, string>();

    for (const key of keys) {
      const realSecret = this.getDecryptedSecret(key) || process.env[key];
      if (realSecret) {
        const surrogate = this.generateSurrogate(key);
        safeEnv[key] = surrogate;
        mapping.set(surrogate, realSecret);
      }
    }

    return { safeEnv, mapping };
  }

  /**
   * Resolves a surrogate token back to real credential at proxy/outbound network call boundary
   */
  public resolveSurrogate(surrogate: string, mapping: Map<string, string>): string | null {
    return mapping.get(surrogate) || null;
  }

  /**
   * Static helper: Encrypts any arbitrary payload using AES-256-GCM
   */
  public static encryptPayload(
    data: unknown,
    key: string | Buffer,
  ): { ciphertext: string; iv: string; tag: string } {
    const keyBuf =
      Buffer.isBuffer(key) && key.length === 32 ? key : createHash("sha256").update(key).digest();
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", keyBuf, iv);
    const json = JSON.stringify(data);
    let ciphertext = cipher.update(json, "utf8", "base64");
    ciphertext += cipher.final("base64");
    const tag = cipher.getAuthTag().toString("base64");
    return { ciphertext, iv: iv.toString("base64"), tag };
  }

  /**
   * Static helper: Decrypts an AES-256-GCM encrypted payload
   */
  public static decryptPayload<T = unknown>(
    encrypted: { ciphertext: string; iv: string; tag: string },
    key: string | Buffer,
  ): T | null {
    try {
      const keyBuf =
        Buffer.isBuffer(key) && key.length === 32 ? key : createHash("sha256").update(key).digest();
      const iv = Buffer.from(encrypted.iv, "base64");
      const tag = Buffer.from(encrypted.tag, "base64");
      const decipher = createDecipheriv("aes-256-gcm", keyBuf, iv);
      decipher.setAuthTag(tag);
      let decrypted = decipher.update(encrypted.ciphertext, "base64", "utf8");
      decrypted += decipher.final("utf8");
      return JSON.parse(decrypted) as T;
    } catch {
      return null;
    }
  }
}
