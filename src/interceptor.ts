import { spawn, type ChildProcess } from "node:child_process";
import { homedir, platform } from "node:os";
import { Transform } from "node:stream";
import { AgentShieldEngine } from "./engine.js";
import { KernelSandboxConfinement } from "./kernel.js";
import { AgentCommandSandbox, type CommandInspectionResult } from "./sandbox.js";

export interface StdioInterceptorOptions {
  workspaceDir?: string;
  enableKernelSandbox?: boolean;
  maskStyle?: "token" | "hash" | "asterisk";
  onBlock?: (inspection: CommandInspectionResult) => void;
}

export interface InterceptedExecutionResult {
  exitCode: number;
  isBlocked: boolean;
  blockReason?: string;
  totalSecretsScrubbed: number;
}

/**
 * Creates a Node.js Transform stream that transparently scrubs credentials and high-entropy
 * secrets from output streams chunk-by-chunk in real time.
 */
export function createRedactingStream(
  engine: AgentShieldEngine,
  maskStyle: "token" | "hash" | "asterisk" = "token",
  onSecretFound?: (count: number) => void,
): Transform {
  let pendingBuffer = "";

  return new Transform({
    transform(chunk: Buffer, _encoding, callback) {
      const text = pendingBuffer + chunk.toString("utf8");
      // Keep trailing slice if split across boundary (max token length 128)
      if (text.length > 256) {
        const toProcess = text.slice(0, text.length - 128);
        pendingBuffer = text.slice(text.length - 128);
        const result = engine.scanAndRedact(toProcess, { maskStyle });
        if (result.hasSecrets && onSecretFound) {
          onSecretFound(result.totalFound);
        }
        callback(null, Buffer.from(result.sanitizedText, "utf8"));
      } else {
        pendingBuffer = text;
        callback(null, Buffer.alloc(0));
      }
    },
    flush(callback) {
      if (pendingBuffer.length > 0) {
        const result = engine.scanAndRedact(pendingBuffer, { maskStyle });
        if (result.hasSecrets && onSecretFound) {
          onSecretFound(result.totalFound);
        }
        callback(null, Buffer.from(result.sanitizedText, "utf8"));
      } else {
        callback();
      }
    },
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
      };
    }

    // 3. Execution with Real-Time Stdio Redaction Stream
    let totalScrubbed = 0;
    const maskStyle = options.maskStyle || "token";

    return new Promise((resolve) => {
      let child: ChildProcess;
      const osType = platform();

      // Wrap in OS-level sandbox if requested and supported
      let execCmd = command;
      if (options.enableKernelSandbox && osType === "darwin") {
        const home = homedir().replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        const ws = (options.workspaceDir || process.cwd()).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        // Note: Workspace allow permits subpath file-read*; reading workspace .env directly
        // is captured and scrubbed by the stdio output transform stream and AST pre-flight gate.
        execCmd = `sandbox-exec -p '(version 1)(deny default)(allow process-exec)(allow sysctl-read)(allow file-read* (subpath "${ws}"))(allow file-write* (subpath "${ws}"))(allow file-read* (subpath "/usr/lib"))(allow file-read* (subpath "/dev/null"))(deny file-read* (subpath "${home}/.ssh"))(deny file-read* (subpath "${home}/.aws"))' ${command}`;
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
        });
      });

      child.on("error", (err) => {
        resolve({
          exitCode: 1,
          isBlocked: false,
          blockReason: err.message,
          totalSecretsScrubbed: totalScrubbed,
        });
      });
    });
  }
}
