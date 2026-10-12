export interface CanaryDecoyAsset {
  id: string;
  type: "env_var" | "decoy_file" | "jwt_token";
  name: string;
  syntheticValue: string;
  alertTriggered: boolean;
  detectedAt?: string;
  actor?: string;
}

export interface CanaryDetectionResult {
  hasCanaryTriggered: boolean;
  canariesTripped: CanaryDecoyAsset[];
  quarantineRequired: boolean;
  alertMessage?: string;
}

/**
 * Honeypot Canary Decoys & Tripwire Defense:
 * Positions synthetic canary variables (e.g., `AWS_SECRET_CANARY_DO_NOT_USE`)
 * and breadcrumb tokens in runtime memory and virtual filesystems.
 * Any read, extraction, or exfiltration attempt against decoy assets instantly
 * triggers an emergency isolation lock on the agent session.
 */
export class CanaryDecoyManager {
  private decopAssets = new Map<string, CanaryDecoyAsset>();

  constructor() {
    this.seedDefaultCanaries();
  }

  private seedDefaultCanaries(): void {
    this.registerCanary({
      id: "CANARY-AWS-001",
      type: "env_var",
      name: "AWS_SECRET_ACCESS_KEY_CANARY",
      syntheticValue: "CANARY_TRIPWIRE_AKIA9999999999999999",
      alertTriggered: false,
    });

    this.registerCanary({
      id: "CANARY-OPENAI-002",
      type: "env_var",
      name: "OPENAI_API_KEY_CANARY",
      syntheticValue: "sk-proj-CANARY_HONEYPOT_TOKEN_99999999999999999999",
      alertTriggered: false,
    });

    this.registerCanary({
      id: "CANARY-FILE-003",
      type: "decoy_file",
      name: ".env.backup.decoy",
      syntheticValue: "DATABASE_URL_CANARY=postgres://canary_honeypot:tripwire@db:5432/secrets",
      alertTriggered: false,
    });
  }

  public registerCanary(asset: CanaryDecoyAsset): void {
    this.decopAssets.set(asset.id, asset);
  }

  /**
   * Evaluates text buffer, command string, or network payload for tripped canary assets
   */
  public inspectPayload(payload: string, actor = "autonomous-agent"): CanaryDetectionResult {
    const tripped: CanaryDecoyAsset[] = [];

    for (const canary of this.decopAssets.values()) {
      if (payload.includes(canary.syntheticValue) || payload.includes(canary.name)) {
        canary.alertTriggered = true;
        canary.detectedAt = new Date().toISOString();
        canary.actor = actor;
        tripped.push({ ...canary });
      }
    }

    if (tripped.length > 0) {
      return {
        hasCanaryTriggered: true,
        canariesTripped: tripped,
        quarantineRequired: true,
        alertMessage: `🚨 EMERGENCY CANARY TRIPWIRE ACTIVATED: Agent attempted to access decoy honeypot asset '${tripped[0].name}'. Session quarantined immediately!`,
      };
    }

    return {
      hasCanaryTriggered: false,
      canariesTripped: [],
      quarantineRequired: false,
    };
  }

  public getCanaryEnvMap(): Record<string, string> {
    const envMap: Record<string, string> = {};
    for (const canary of this.decopAssets.values()) {
      if (canary.type === "env_var") {
        envMap[canary.name] = canary.syntheticValue;
      }
    }
    return envMap;
  }
}
