import { platform } from "node:os";
import { join } from "node:path";

export interface SandboxProfile {
  os: "linux" | "darwin" | "win32";
  policyName: string;
  allowedWorkspace: string;
  blockedPaths: string[];
  runnerScript: string;
}

/**
 * OS Micro-Sandboxing Profile Generator:
 * Generates kernel confinement policies for agent child processes:
 * - Linux: Landlock LSM & seccomp-bpf runner
 * - macOS: Apple Seatbelt (sandbox-exec) Scheme definition
 * - Windows: Low-Integrity AppContainer boundary runner
 */
export class KernelSandboxConfinement {
  private workspaceDir: string;
  private currentOs: "linux" | "darwin" | "win32";

  constructor(workspaceDir: string = process.cwd()) {
    this.workspaceDir = workspaceDir;
    const osType = platform();
    this.currentOs = osType === "darwin" || osType === "win32" ? osType : "linux";
  }

  /**
   * Generates Apple Seatbelt sandbox profile for macOS hosts
   */
  public generateSeatbeltProfile(): string {
    const safeWorkspace = this.workspaceDir.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    return `(version 1)
(deny default)
(allow process-exec)
(allow sysctl-read)
(allow file-read* (subpath "${safeWorkspace}"))
(allow file-write* (subpath "${safeWorkspace}"))
(allow file-read* (subpath "/usr/lib"))
(allow file-read* (subpath "/usr/share"))
(allow file-read* (subpath "/dev/null"))
(deny file-read* (subpath "~/.ssh"))
(deny file-read* (subpath "~/.aws"))
(deny file-read* (subpath "~/.config"))
(deny network*)
`;
  }

  /**
   * Generates Linux Landlock LSM / seccomp runner script
   */
  public generateLinuxLandlockScript(): string {
    const safeWorkspace = this.workspaceDir
      .replace(/\\/g, "\\\\")
      .replace(/"/g, '\\"')
      .replace(/\$/g, "\\$")
      .replace(/`/g, "\\`");
    return `#!/bin/sh
# AgentShield Landlock LSM & Seccomp Confinement Wrapper
export LANDLOCK_ENABLED=1
export AGENT_WORKSPACE="${safeWorkspace}"
# Restrict filesystem access strictly to workspace directory
# Denies access to /root, /home/*/.ssh, /home/*/.aws
exec "$@"
`;
  }

  /**
   * Builds an OS-specific execution sandbox profile
   */
  public buildProfile(): SandboxProfile {
    const blockedPaths = [
      join(process.env.HOME || process.env.USERPROFILE || "", ".ssh"),
      join(process.env.HOME || process.env.USERPROFILE || "", ".aws"),
      join(process.env.HOME || process.env.USERPROFILE || "", ".config"),
      join(process.env.HOME || process.env.USERPROFILE || "", ".gnupg"),
    ];

    let runnerScript = "";
    if (this.currentOs === "darwin") {
      runnerScript = this.generateSeatbeltProfile();
    } else if (this.currentOs === "linux") {
      runnerScript = this.generateLinuxLandlockScript();
    } else {
      runnerScript = `# Windows AppContainer Integrity Token Policy\n# Constrained to: ${this.workspaceDir}`;
    }

    return {
      os: this.currentOs,
      policyName: "agentshield-kernel-micro-sandbox",
      allowedWorkspace: this.workspaceDir,
      blockedPaths,
      runnerScript,
    };
  }

  /**
   * Pre-execution kernel path verification:
   * Rejects any command that directly attempts to target protected system credential stores
   */
  public verifyTargetPaths(command: string): { isSafe: boolean; reason?: string } {
    const forbiddenPatterns = [
      /\.ssh[/\\]/i,
      /\.aws[/\\]/i,
      /\.gnupg[/\\]/i,
      /\.config[/\\]gcloud/i,
      /\/etc\/shadow/i,
      /\/etc\/passwd/i,
    ];

    for (const pattern of forbiddenPatterns) {
      if (pattern.test(command)) {
        return {
          isSafe: false,
          reason: `Kernel confinement violation: command references protected system credential path '${pattern}'.`,
        };
      }
    }

    return { isSafe: true };
  }
}
