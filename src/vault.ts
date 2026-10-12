export interface VaultSecretValue {
  key: string;
  value: string;
  version?: number;
  leaseDuration?: number;
}

export interface ZeroTrustVaultProvider {
  name: string;
  fetchSecret(key: string): Promise<string | null>;
  injectIntoEnvironment(secretKeys: string[]): Promise<Record<string, string>>;
}

/**
 * Enterprise Zero-Trust Vault Injector:
 * Instead of keeping plaintext credentials in local `.env` files where autonomous AI agents can read them,
 * AgentShield fetches ephemeral tokens on-demand from enterprise secrets managers (HashiCorp Vault, AWS, Mock)
 * and only injects sanitized surrogate tokens to the agent.
 */
export class VaultInjector {
  private secretsStore = new Map<string, string>();

  constructor(initialStore?: Record<string, string>) {
    if (initialStore) {
      for (const [k, v] of Object.entries(initialStore)) {
        this.secretsStore.set(k, v);
      }
    }
  }

  /**
   * Sets or updates a secret in the vault
   */
  public registerSecret(key: string, value: string): void {
    this.secretsStore.set(key, value);
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
      const realSecret = this.secretsStore.get(key) || process.env[key];
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
}
