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
 * Cross-Turn Directional Data Taint Graph:
 * Tracks data lineage across multi-stage autonomous agent tool calls.
 * Defeats tool-chaining attacks where an agent reads private configs in Turn 1,
 * stages them in Turn 2, and transmits them to external network endpoints in Turn 3.
 */
export class DirectionalTaintGraph {
  private nodes = new Map<string, TaintNode>();
  private transitions: TaintTransition[] = [];

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
  }
}
