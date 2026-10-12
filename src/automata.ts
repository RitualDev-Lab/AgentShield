import type { NativeAutomataMatch } from "./mcp-types.js";

interface AutomataNode {
  next: Map<string, AutomataNode>;
  fail: AutomataNode | null;
  outputs: Array<{ patternId: string; length: number }>;
}

/**
 * High-Velocity Aho-Corasick Multi-Pattern Automata Engine:
 * Evaluates thousands of credential prefix signatures simultaneously in O(n + m) time,
 * completely immune to ReDoS (Regular Expression Denial of Service).
 * Serves as the zero-latency fast-filter preceding downstream validation.
 */
export class FastAutomataScanner {
  private root: AutomataNode;
  private patternCount = 0;

  constructor() {
    this.root = this.createNode();
  }

  private createNode(): AutomataNode {
    return {
      next: new Map<string, AutomataNode>(),
      fail: null,
      outputs: [],
    };
  }

  /**
   * Adds a keyword or prefix signature to the trie (e.g., "sk-proj-", "AKIA", "ghp_")
   */
  public addSignature(signature: string, patternId: string): void {
    if (!signature) return;
    let current = this.root;

    for (const char of signature) {
      let nextNode = current.next.get(char);
      if (!nextNode) {
        nextNode = this.createNode();
        current.next.set(char, nextNode);
      }
      current = nextNode;
    }

    current.outputs.push({ patternId, length: signature.length });
    this.patternCount++;
  }

  /**
   * Builds the failure links (Aho-Corasick BFS construction)
   */
  public buildFailureTransitions(): void {
    const queue: AutomataNode[] = [];

    // Root children fail transitions point back to root
    for (const child of this.root.next.values()) {
      child.fail = this.root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) continue;

      for (const [char, child] of current.next.entries()) {
        let fallback = current.fail;

        while (fallback && !fallback.next.has(char)) {
          fallback = fallback.fail;
        }

        const fallbackTarget = fallback?.next.get(char);
        child.fail = fallbackTarget || this.root;

        // Copy outputs from failure node
        if (child.fail) {
          child.outputs.push(...child.fail.outputs);
        }

        queue.push(child);
      }
    }
  }

  /**
   * Ultra-fast linear multi-pattern search across raw text buffer
   */
  public scanBuffer(text: string): NativeAutomataMatch[] {
    const matches: NativeAutomataMatch[] = [];
    let current = this.root;

    for (let i = 0; i < text.length; i++) {
      const char = text[i];

      while (current !== this.root && !current.next.has(char)) {
        current = current.fail || this.root;
      }

      current = current.next.get(char) || this.root;

      if (current.outputs.length > 0) {
        for (const out of current.outputs) {
          const start = i - out.length + 1;
          matches.push({
            patternId: out.patternId,
            start,
            end: i + 1,
            matchedText: text.substring(start, i + 1),
          });
        }
      }
    }

    return matches;
  }

  public getPatternCount(): number {
    return this.patternCount;
  }
}
