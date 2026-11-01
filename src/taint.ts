import { StringDecoder } from "node:string_decoder";

export type TaintLevel = "CLEAN" | "SUSPICIOUS" | "CONFIDENTIAL" | "CRITICAL";

export interface TaintNode {
  id: string; // File path, memory buffer identifier, or variable name
  taintLevel: TaintLevel;
  sourceTool: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface TaintTransition {
  fromNodeId: string;
  toNodeId: string;
  operation: string; // e.g., "copy", "parse", "read", "export"
  timestamp: string;
}

export interface TaintFlowCheckResult {
  isBlocked: boolean;
  reason?: string;
  taintedSource?: string;
  targetDestination?: string;
  taintLevel: TaintLevel;
}

/**
 * Stream-aware Taint Flow Detector:
 * Inspects streaming egress chunks against active tainted tokens and confidential signatures,
 * maintaining an internal sliding window and multi-byte UTF-8 decoder across chunk seams.
 */
export class TaintStreamDetector {
  private graph: DirectionalTaintGraph;
  private destination: string;
  private decoder: StringDecoder;
  private pendingBuffer = "";
  private lookbackSize: number;

  constructor(graph: DirectionalTaintGraph, destination: string, lookbackSize = 256) {
    this.graph = graph;
    this.destination = destination;
    this.decoder = new StringDecoder("utf8");
    this.lookbackSize = lookbackSize;
  }

  /**
   * Processes a stream chunk (string or Buffer), checking for tainted tokens split across boundaries.
   */
  public write(chunk: Buffer | string): TaintFlowCheckResult {
    const textChunk = Buffer.isBuffer(chunk) ? this.decoder.write(chunk) : chunk;
    this.pendingBuffer += textChunk;

    const signatures = this.graph.getSignatures();
    for (const [sig, meta] of signatures.entries()) {
      if (this.pendingBuffer.includes(sig)) {
        return {
          isBlocked: true,
          reason: `Exfiltration blocked: tainted signature '${sig}' found in streaming egress to '${this.destination}'.`,
          taintedSource: meta.resourceId,
          targetDestination: this.destination,
          taintLevel: meta.level,
        };
      }
    }

    if (this.pendingBuffer.length > this.lookbackSize) {
      this.pendingBuffer = this.pendingBuffer.slice(-this.lookbackSize);
    }

    return { isBlocked: false, taintLevel: "CLEAN" };
  }

  /**
   * Flushes any remaining bytes in the UTF-8 decoder and inspects the tail of the stream.
   */
  public flush(): TaintFlowCheckResult {
    const trailing = this.decoder.end();
    this.pendingBuffer += trailing;

    const signatures = this.graph.getSignatures();
    for (const [sig, meta] of signatures.entries()) {
      if (this.pendingBuffer.includes(sig)) {
        return {
          isBlocked: true,
          reason: `Exfiltration blocked: tainted signature '${sig}' detected at end of stream to '${this.destination}'.`,
          taintedSource: meta.resourceId,
          targetDestination: this.destination,
          taintLevel: meta.level,
        };
      }
    }

    this.pendingBuffer = "";
    return { isBlocked: false, taintLevel: "CLEAN" };
  }
}

/**
 * Cross-Turn Directional Data Taint Graph:
 * Tracks data lineage across multi-stage autonomous agent tool calls.
 * Defeats tool-chaining attacks where an agent reads private configs in Turn 1,
 * stages them in Turn 2, and transmits them to external network endpoints in Turn 3.
 */
export class DirectionalTaintGraph {
  private nodes = new Map<string, TaintNode>();
  private transitions: TaintTransition[] = [];
  private signatures = new Map<string, { resourceId: string; level: TaintLevel }>();

  /**
   * Taints a node when sensitive files or memory buffers are accessed
   */
  public taintResource(
    resourceId: string,
    level: TaintLevel,
    sourceTool: string,
    metadata?: Record<string, unknown>,
  ): TaintNode {
    const node: TaintNode = {
      id: resourceId,
      taintLevel: level,
      sourceTool,
      timestamp: new Date().toISOString(),
      metadata,
    };
    this.nodes.set(resourceId, node);
    return node;
  }

  /**
   * Associates a secret signature or token pattern with a tainted resource
   */
  public registerResourceSignature(
    resourceId: string,
    signature: string,
    level: TaintLevel = "CRITICAL",
  ): void {
    this.signatures.set(signature, { resourceId, level });
  }

  public getSignatures(): Map<string, { resourceId: string; level: TaintLevel }> {
    return new Map(this.signatures);
  }

  /**
   * Propagates taint from a source resource to a derived resource (e.g. file -> memory buffer or temp file)
   */
  public propagate(fromResourceId: string, toResourceId: string, operation: string): void {
    const source = this.nodes.get(fromResourceId);
    if (!source || source.taintLevel === "CLEAN") return;

    const existingDest = this.nodes.get(toResourceId);
    const newLevel: TaintLevel =
      existingDest && existingDest.taintLevel === "CRITICAL" ? "CRITICAL" : source.taintLevel;

    this.nodes.set(toResourceId, {
      id: toResourceId,
      taintLevel: newLevel,
      sourceTool: source.sourceTool,
      timestamp: new Date().toISOString(),
    });

    this.transitions.push({
      fromNodeId: fromResourceId,
      toNodeId: toResourceId,
      operation,
      timestamp: new Date().toISOString(),
    });
  }

  /**
   * Creates a stream detector that inspects chunked streams to a destination
   */
  public createStreamDetector(destination: string, lookbackSize = 256): TaintStreamDetector {
    return new TaintStreamDetector(this, destination, lookbackSize);
  }

  /**
   * Checks whether a destination operation (e.g., outbound network HTTP or git push) is allowed
   * given the taint lineage of the data payload.
   */
  public evaluateEgress(resourceId: string, destination: string): TaintFlowCheckResult {
    const node = this.nodes.get(resourceId);
    if (!node || node.taintLevel === "CLEAN") {
      return { isBlocked: false, taintLevel: "CLEAN" };
    }

    if (node.taintLevel === "CRITICAL" || node.taintLevel === "CONFIDENTIAL") {
      return {
        isBlocked: true,
        reason: `Exfiltration blocked: data from tainted resource '${node.id}' (tainted by '${node.sourceTool}') cannot egress to '${destination}'.`,
        taintedSource: node.id,
        targetDestination: destination,
        taintLevel: node.taintLevel,
      };
    }

    return { isBlocked: false, taintLevel: node.taintLevel };
  }

  public getTaintedNodesCount(): number {
    return Array.from(this.nodes.values()).filter((n) => n.taintLevel !== "CLEAN").length;
  }

  public clear(): void {
    this.nodes.clear();
    this.transitions = [];
    this.signatures.clear();
  }
}
