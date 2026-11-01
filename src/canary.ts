import { StringDecoder } from "node:string_decoder";

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
 * Stream-aware Canary Detector:
 * Hardened to detect canary secrets fragmented across arbitrary multi-byte UTF-8 boundaries
 * and chunk sizes (down to 1 byte at a time) using an internal lookback window and UTF-8 decoder.
 */
export class CanaryStreamDetector {
  private manager: CanaryDecoyManager;
  private actor: string;
  private decoder: StringDecoder;
  private pendingBuffer = "";
  private lookbackSize: number;

  constructor(manager: CanaryDecoyManager, actor = "autonomous-agent", lookbackSize = 256) {
    this.manager = manager;
    this.actor = actor;
    this.decoder = new StringDecoder("utf8");
    this.lookbackSize = Math.max(lookbackSize, manager.getLookbackWindowSize());
  }

  /**
   * Processes a streaming chunk (string or Buffer), maintaining state across chunk seams
   * and properly assembling multi-byte UTF-8 characters.
   */
  public write(chunk: Buffer | string): CanaryDetectionResult {
    const textChunk = Buffer.isBuffer(chunk) ? this.decoder.write(chunk) : chunk;
    this.pendingBuffer += textChunk;

    const check = this.manager.inspectPayload(this.pendingBuffer, this.actor);
    if (check.hasCanaryTriggered) {
      return check;
    }

    // Keep sliding lookback window for seamless cross-chunk canary detection
    if (this.pendingBuffer.length > this.lookbackSize) {
      this.pendingBuffer = this.pendingBuffer.slice(-this.lookbackSize);
    }

    return {
      hasCanaryTriggered: false,
      canariesTripped: [],
      quarantineRequired: false,
    };
  }

  /**
   * Finalizes the stream, decoding any trailing multibyte UTF-8 fragment and checking the final buffer.
   */
  public flush(): CanaryDetectionResult {
    const trailing = this.decoder.end();
    this.pendingBuffer += trailing;

    const result = this.manager.inspectPayload(this.pendingBuffer, this.actor);
    this.pendingBuffer = "";
    return result;
  }

  public reset(): void {
    this.decoder = new StringDecoder("utf8");
    this.pendingBuffer = "";
  }
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
  private defaultStreamDetector: CanaryStreamDetector | null = null;

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
    this.defaultStreamDetector = null; // Re-create with new size on demand
  }

  public getLookbackWindowSize(): number {
    let maxLen = 128;
    for (const c of this.decopAssets.values()) {
      if (c.syntheticValue.length > maxLen) maxLen = c.syntheticValue.length;
      if (c.name.length > maxLen) maxLen = c.name.length;
    }
    return maxLen * 2;
  }

  public createStreamDetector(actor = "autonomous-agent"): CanaryStreamDetector {
    return new CanaryStreamDetector(this, actor);
  }

  /**
   * Stateful stream inspection method that handles fragmented chunks
   */
  public inspectStreamChunk(
    chunk: Buffer | string,
    actor = "autonomous-agent",
  ): CanaryDetectionResult {
    if (!this.defaultStreamDetector) {
      this.defaultStreamDetector = this.createStreamDetector(actor);
    }
    return this.defaultStreamDetector.write(chunk);
  }

  public flushStream(): CanaryDetectionResult {
    if (this.defaultStreamDetector) {
      const res = this.defaultStreamDetector.flush();
      this.defaultStreamDetector = null;
      return res;
    }
    return {
      hasCanaryTriggered: false,
      canariesTripped: [],
      quarantineRequired: false,
    };
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
