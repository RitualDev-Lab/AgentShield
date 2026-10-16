import { spawn, type ChildProcess } from "node:child_process";
import { homedir, platform } from "node:os";
import { Transform } from "node:stream";
import { StringDecoder } from "node:string_decoder";
import { AgentShieldEngine } from "./engine.js";
import { KernelSandboxConfinement } from "./kernel.js";
import { AgentCommandSandbox, type CommandInspectionResult } from "./sandbox.js";

export interface StdioInterceptorOptions {
  workspaceDir?: string;
  enableKernelSandbox?: boolean;
  maskStyle?: "token" | "hash" | "asterisk";
  onBlock?: (inspection: CommandInspectionResult) => void;
}

export type IsolationMechanism =
  | "macos_sandbox_exec"
  | "process_level_firewall";

export interface InterceptedExecutionResult {
  exitCode: number;
  isBlocked: boolean;
  blockReason?: string;
  totalSecretsScrubbed: number;
  isolationMechanism: IsolationMechanism;
  isolationNotice: string;
}

export interface RedactingStreamOptions {
  maskStyle?: "token" | "hash" | "asterisk";
  onSecretFound?: (count: number) => void;
  maxWindowSize?: number;
  maxMultilineBuffer?: number;
}

const PEM_START_REGEX =
  /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?(?:PRIVATE )?KEY(?: BLOCK)?-----/;
const PEM_END_REGEX =
  /-----END (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?(?:PRIVATE )?KEY(?: BLOCK)?-----/;

function findUnclosedPemStartIndex(text: string): number {
  let searchPos = 0;
  while (searchPos < text.length) {
    const remaining = text.slice(searchPos);
    const startMatch = remaining.match(PEM_START_REGEX);
    if (!startMatch || startMatch.index === undefined) {
      return -1;
    }
    const absStart = searchPos + startMatch.index;
    const afterStart = text.slice(absStart + startMatch[0].length);
    const endMatch = afterStart.match(PEM_END_REGEX);
    if (!endMatch || endMatch.index === undefined) {
      return absStart;
    }
    searchPos = absStart + startMatch[0].length + endMatch.index + endMatch[0].length;
  }
  return -1;
}

function findPotentialPemPrefixIndex(text: string): number {
  if (PEM_END_REGEX.test(text.trimEnd())) return -1;
  const match = text.match(
    /(?<!END [A-Z0-9 ]*)-{1,5}(?:B(?:E(?:G(?:I(?:N(?: (?:[A-Z0-9 ]*)?)?)?)?)?)?)?$/,
  );
  return match && match.index !== undefined ? match.index : -1;
}

/**
 * Boundary-Safe Real-Time Redacting Stream:
 * Protects against stream fragmentation, multi-byte UTF-8 boundary slicing,
 * multiline PEM private key exposure, and oversized payload denial-of-service.
 */
export class RedactingStream extends Transform {
  private engine: AgentShieldEngine;
  private maskStyle: "token" | "hash" | "asterisk";
  private onSecretFound?: (count: number) => void;
  private maxWindowSize: number;
  private maxMultilineBuffer: number;
  private maxUnbrokenBuffer: number;
  private decoder: StringDecoder;
  private pendingBuffer = "";

  constructor(engine: AgentShieldEngine, options: RedactingStreamOptions = {}) {
    super();
    this.engine = engine;
    this.maskStyle = options.maskStyle || "token";
    this.onSecretFound = options.onSecretFound;
    this.maxWindowSize = options.maxWindowSize ?? 512;
    this.maxMultilineBuffer = options.maxMultilineBuffer ?? 64 * 1024;
    this.maxUnbrokenBuffer = 16 * 1024;
    this.decoder = new StringDecoder("utf8");
  }

  override _transform(
    chunk: Buffer | string,
    _encoding: BufferEncoding,
    callback: (error?: Error | null, data?: Buffer) => void,
  ): void {
    const textChunk = Buffer.isBuffer(chunk) ? this.decoder.write(chunk) : chunk;
    this.pendingBuffer += textChunk;

    let candidateText = "";

    // 1. Check for multiline PEM blocks
    const unclosedPemIdx = findUnclosedPemStartIndex(this.pendingBuffer);
    if (unclosedPemIdx !== -1) {
      const openLength = this.pendingBuffer.length - unclosedPemIdx;
      if (openLength > this.maxMultilineBuffer) {
        // Fail-closed: oversized unclosed private key block
        this.pendingBuffer = `${this.pendingBuffer.slice(0, unclosedPemIdx)}[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED_OVERSIZED]`;
        if (this.onSecretFound) this.onSecretFound(1);
        candidateText = this.pendingBuffer;
        this.pendingBuffer = "";
      } else {
        // Hold unclosed PEM block in pendingBuffer; process preceding text
        candidateText = this.pendingBuffer.slice(0, unclosedPemIdx);
        this.pendingBuffer = this.pendingBuffer.slice(unclosedPemIdx);
      }
    } else {
      // Check for partial PEM header at the very tail
      const potentialPemIdx = findPotentialPemPrefixIndex(this.pendingBuffer);
      if (potentialPemIdx !== -1) {
        candidateText = this.pendingBuffer.slice(0, potentialPemIdx);
        this.pendingBuffer = this.pendingBuffer.slice(potentialPemIdx);
      } else {
        candidateText = this.pendingBuffer;
        this.pendingBuffer = "";
      }
    }

    if (candidateText.length === 0) {
      callback(null, Buffer.alloc(0));
      return;
    }

    // 2. Safe single-line & delimiter boundary windowing
    let safeSlice = "";
    let trailingSlice = "";

    // Check if there are closed PEM blocks ending in candidateText to preserve them intact
    let lastClosedPemEnd = -1;
    let pemSearchPos = 0;
    while (pemSearchPos < candidateText.length) {
      const remaining = candidateText.slice(pemSearchPos);
      const startMatch = remaining.match(PEM_START_REGEX);
      if (!startMatch || startMatch.index === undefined) break;
      const absStart = pemSearchPos + startMatch.index;
      const afterStart = candidateText.slice(absStart + startMatch[0].length);
      const endMatch = afterStart.match(PEM_END_REGEX);
      if (!endMatch || endMatch.index === undefined) break;
      const absEnd = absStart + startMatch[0].length + endMatch.index + endMatch[0].length;
      lastClosedPemEnd = absEnd;
      pemSearchPos = absEnd;
    }

    if (lastClosedPemEnd !== -1) {
      safeSlice = candidateText.slice(0, lastClosedPemEnd);
      const postPem = candidateText.slice(lastClosedPemEnd);
      const lastNewline = postPem.lastIndexOf("\n");
      if (lastNewline !== -1) {
        safeSlice += postPem.slice(0, lastNewline + 1);
        trailingSlice = postPem.slice(lastNewline + 1);
      } else {
        trailingSlice = postPem;
      }
    } else {
      const lastNewline = candidateText.lastIndexOf("\n");
      if (lastNewline !== -1) {
        safeSlice = candidateText.slice(0, lastNewline + 1);
        trailingSlice = candidateText.slice(lastNewline + 1);
      } else {
        trailingSlice = candidateText;
      }
    }

    // If trailingSlice without newline exceeds safety threshold, split at safe delimiter
    if (trailingSlice.length > this.maxWindowSize * 2) {
      let splitIndex = -1;
      const searchEnd = trailingSlice.length - this.maxWindowSize;
      for (let i = searchEnd; i >= 0; i--) {
        const char = trailingSlice[i];
        if (
          char === " " ||
          char === "\t" ||
          char === "," ||
          char === ";" ||
          char === "}" ||
          char === "]"
        ) {
          splitIndex = i + 1;
          break;
        }
      }

      if (splitIndex !== -1) {
        safeSlice += trailingSlice.slice(0, splitIndex);
        trailingSlice = trailingSlice.slice(splitIndex);
      } else if (trailingSlice.length > this.maxUnbrokenBuffer) {
        // Fail-closed forced cut for unbroken oversized tokens
        const forcedSplit = trailingSlice.length - this.maxWindowSize;
        safeSlice += trailingSlice.slice(0, forcedSplit);
        trailingSlice = trailingSlice.slice(forcedSplit);
      }
    }

    // Restore trailingSlice to front of pendingBuffer
    this.pendingBuffer = trailingSlice + this.pendingBuffer;

    if (safeSlice.length > 0) {
      const result = this.engine.scanAndRedact(safeSlice, { maskStyle: this.maskStyle });
      if (result.hasSecrets && this.onSecretFound) {
        this.onSecretFound(result.totalFound);
      }
      callback(null, Buffer.from(result.sanitizedText, "utf8"));
    } else {
      callback(null, Buffer.alloc(0));
    }
  }

  override _flush(callback: (error?: Error | null, data?: Buffer) => void): void {
    const trailingUtf8 = this.decoder.end();
    this.pendingBuffer += trailingUtf8;

    if (this.pendingBuffer.length === 0) {
      callback();
      return;
    }

    // Fail-closed check: unclosed PEM block or partial header at EOF
    const unclosedIdx = findUnclosedPemStartIndex(this.pendingBuffer);
    if (unclosedIdx !== -1) {
      this.pendingBuffer = `${this.pendingBuffer.slice(0, unclosedIdx)}[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED]`;
      if (this.onSecretFound) this.onSecretFound(1);
    } else {
      const partialHeaderIdx = findPotentialPemPrefixIndex(this.pendingBuffer);
      if (partialHeaderIdx !== -1 && this.pendingBuffer.slice(partialHeaderIdx).length >= 5) {
        this.pendingBuffer = `${this.pendingBuffer.slice(0, partialHeaderIdx)}[AGENT_SHIELD:PRIVATE_KEY_BLOCK:TRUNCATED]`;
        if (this.onSecretFound) this.onSecretFound(1);
      }
    }

    const result = this.engine.scanAndRedact(this.pendingBuffer, { maskStyle: this.maskStyle });
    if (result.hasSecrets && this.onSecretFound) {
      this.onSecretFound(result.totalFound);
    }

    this.pendingBuffer = "";
    callback(null, Buffer.from(result.sanitizedText, "utf8"));
  }
}

/**
 * Creates a Node.js Transform stream that transparently scrubs credentials and high-entropy
 * secrets from output streams chunk-by-chunk in real time.
 */
export function createRedactingStream(
  engine: AgentShieldEngine,
  maskStyle: "token" | "hash" | "asterisk" = "token",
  onSecretFound?: (count: number) => void,
  options?: Omit<RedactingStreamOptions, "maskStyle" | "onSecretFound">,
): RedactingStream {
  return new RedactingStream(engine, {
    ...options,
    maskStyle,
    onSecretFound,
  });
}

/**
 * High-Assurance Agent Stdio Interceptor:
 * Replaces pure regex blocklists with real-time stream scrubbing and OS-level containment.
 */
export class AgentStdioInterceptor {
  private engine: AgentShieldEngine;
  private sandbox: AgentCommandSandbox;
  private kernel: KernelSandboxConfinement;

  constructor(engine?: AgentShieldEngine, workspaceDir: string = process.cwd()) {
    this.engine = engine || new AgentShieldEngine();
    this.sandbox = new AgentCommandSandbox();
    this.kernel = new KernelSandboxConfinement(workspaceDir);
  }

  /**
   * Evaluates command against AST heuristics and kernel isolation rules, then executes
   * with transparent bi-directional stream redaction.
   */
  public async execute(
    command: string,
    options: StdioInterceptorOptions = {},
  ): Promise<InterceptedExecutionResult> {
    // 1. AST Pre-flight inspection
    const astCheck = this.sandbox.inspectCommand(command);
    if (astCheck.isBlocked) {
      if (options.onBlock) options.onBlock(astCheck);
      return {
        exitCode: 1,
        isBlocked: true,
        blockReason: astCheck.reason,
        totalSecretsScrubbed: 0,
        isolationMechanism: "process_level_firewall",
        isolationNotice: "Command blocked by AST pre-flight policy firewall before OS execution.",
      };
    }

    // 2. Kernel filesystem boundary verification
    const kernelCheck = this.kernel.verifyTargetPaths(command);
    if (!kernelCheck.isSafe) {
      const blockedRes: CommandInspectionResult = {
        isBlocked: true,
        reason: kernelCheck.reason,
        category: "dangerous_mutation",
      };
      if (options.onBlock) options.onBlock(blockedRes);
      return {
        exitCode: 1,
        isBlocked: true,
        blockReason: kernelCheck.reason,
        totalSecretsScrubbed: 0,
        isolationMechanism: "process_level_firewall",
        isolationNotice: "Command blocked by kernel path containment verification.",
      };
    }

    // 3. Execution with Real-Time Stdio Redaction Stream
    let totalScrubbed = 0;
    const maskStyle = options.maskStyle || "token";

    return new Promise((resolve) => {
      let child: ChildProcess;
      const osType = platform();
      let isolationMechanism: IsolationMechanism = "process_level_firewall";
      let isolationNotice = "";

      // Wrap in OS-level sandbox if requested and supported
      let execCmd = command;
      if (options.enableKernelSandbox && osType === "darwin") {
        isolationMechanism = "macos_sandbox_exec";
        isolationNotice = "Enforcing OS-level kernel confinement via macOS sandbox-exec.";
        const home = homedir().replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        const ws = (options.workspaceDir || process.cwd())
          .replace(/\\/g, "\\\\")
          .replace(/"/g, '\\"');
        execCmd = `sandbox-exec -p '(version 1)(deny default)(allow process-exec)(allow sysctl-read)(allow file-read* (subpath "${ws}"))(allow file-write* (subpath "${ws}"))(allow file-read* (subpath "/usr/lib"))(allow file-read* (subpath "/dev/null"))(deny file-read* (subpath "${home}/.ssh"))(deny file-read* (subpath "${home}/.aws"))' ${command}`;
      } else if (options.enableKernelSandbox) {
        isolationMechanism = "process_level_firewall";
        isolationNotice = `Kernel sandbox requested, but OS-level sandbox-exec is only supported on macOS (current host: ${osType}). Executing under AST pattern firewall and real-time streaming redaction.`;
      } else {
        isolationMechanism = "process_level_firewall";
        isolationNotice = "Executing under AST pattern inspection firewall and real-time stdio stream redaction.";
      }

      try {
        child = spawn(execCmd, {
          shell: true,
          cwd: options.workspaceDir || process.cwd(),
          stdio: ["inherit", "pipe", "pipe"],
        });
      } catch (err: unknown) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        resolve({
          exitCode: 1,
          isBlocked: false,
          blockReason: errorMsg,
          totalSecretsScrubbed: 0,
          isolationMechanism,
          isolationNotice,
        });
        return;
      }

      const stdoutTransform = createRedactingStream(this.engine, maskStyle, (count) => {
        totalScrubbed += count;
      });
      const stderrTransform = createRedactingStream(this.engine, maskStyle, (count) => {
        totalScrubbed += count;
      });

      child.stdout?.pipe(stdoutTransform).pipe(process.stdout);
      child.stderr?.pipe(stderrTransform).pipe(process.stderr);

      child.on("close", (code) => {
        resolve({
          exitCode: code ?? 0,
          isBlocked: false,
          totalSecretsScrubbed: totalScrubbed,
          isolationMechanism,
          isolationNotice,
        });
      });

      child.on("error", (err) => {
        resolve({
          exitCode: 1,
          isBlocked: false,
          blockReason: err.message,
          totalSecretsScrubbed: totalScrubbed,
          isolationMechanism,
          isolationNotice,
        });
      });
    });
  }
}
