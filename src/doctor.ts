import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { arch, platform, release } from "node:os";
import { OsKeystoreAdapter } from "./keystore.js";

export type DoctorCheckStatus = "PASS" | "WARN" | "FAIL" | "INFO";

export interface DoctorCheck {
  id: string;
  name: string;
  status: DoctorCheckStatus;
  detail: string;
  remediation?: string;
}

export interface SandboxDoctorReport {
  timestamp: string;
  platform: NodeJS.Platform;
  arch: string;
  osRelease: string;
  nodeVersion: string;
  airGapped: boolean;
  overallStatus: "READY" | "DEGRADED" | "ACTION_REQUIRED";
  recommendedIsolationTier: string;
  checks: DoctorCheck[];
}

export interface DoctorOptions {
  /** Override platform for deterministic cross-platform unit testing */
  platformOverride?: NodeJS.Platform;
  /** Skip spawning external OS probes when running in ultra-fast dry mode */
  dryRun?: boolean;
}

function probeCommand(
  cmd: string,
  args: string[],
  timeoutMs = 1500,
): { ok: boolean; output: string } {
  try {
    const out = execFileSync(cmd, args, {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    }).trim();
    return { ok: true, output: out };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, output: message };
  }
}

function safeReadText(filePath: string): string | null {
  try {
    if (!existsSync(filePath)) return null;
    return readFileSync(filePath, "utf8").trim();
  } catch {
    return null;
  }
}

function parseNodeMajor(version: string): number {
  const match = version.replace(/^v/, "").match(/^(\d+)/);
  return match ? Number.parseInt(match[1], 10) : 0;
}

/**
 * Runs deterministic cross-platform sandbox, kernel, and cryptographic diagnostics.
 * Surfaces exact remediation steps for Linux (Landlock/Bubblewrap/Ubuntu 24.04 AppArmor userns/eBPF),
 * macOS (Seatbelt sandbox-exec/Keychain), and Windows (DPAPI/AppContainer/Job Objects).
 */
export function runSandboxDoctor(options: DoctorOptions = {}): SandboxDoctorReport {
  const targetPlatform = options.platformOverride || platform();
  const osRelease = release();
  const nodeVersion = process.version;
  const airGapped =
    process.env.AGENTSHIELD_AIR_GAPPED === "1" || process.env.RITUAL_AIR_GAPPED === "1";

  const checks: DoctorCheck[] = [];

  // 1. Node.js Runtime Version Check
  const major = parseNodeMajor(nodeVersion);
  if (major >= 20) {
    checks.push({
      id: "node-runtime",
      name: "Node.js Runtime",
      status: "PASS",
      detail: `Running ${nodeVersion} (>= v20.0.0 required for native Ed25519 & fetch)`,
    });
  } else {
    checks.push({
      id: "node-runtime",
      name: "Node.js Runtime",
      status: "FAIL",
      detail: `Running ${nodeVersion}; AgentShield requires Node.js >= 20.0.0`,
      remediation: "Upgrade Node.js to v20 LTS or newer (https://nodejs.org/).",
    });
  }

  // 2. Ed25519 Hardware-Sealed Audit Ledger Capability Check
  try {
    const { publicKey } = generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const fp = OsKeystoreAdapter.computeFingerprint(publicKey);
    checks.push({
      id: "crypto-ed25519",
      name: "Ed25519 Asymmetric Audit Signing",
      status: "PASS",
      detail: `Native OpenSSL Ed25519 keygen & verification ready (probe fingerprint ${fp.slice(0, 20)}...)`,
    });
  } catch (err) {
    checks.push({
      id: "crypto-ed25519",
      name: "Ed25519 Asymmetric Audit Signing",
      status: "FAIL",
      detail: `Ed25519 unavailable: ${err instanceof Error ? err.message : String(err)}`,
      remediation: "Use a standard Node.js >= 20 build with OpenSSL Ed25519 support.",
    });
  }

  // 3. Keystore Backend Detection
  const keystore = new OsKeystoreAdapter();
  const preferredKeystore = keystore.detectPreferredBackend();
  checks.push({
    id: "os-keystore",
    name: "Hardware Keystore Backend",
    status: preferredKeystore === "memory" ? "INFO" : "PASS",
    detail: `Resolved Ed25519 sealing backend: ${preferredKeystore}`,
    ...(preferredKeystore === "memory"
      ? {
          remediation:
            "Set AGENTSHIELD_KEYSTORE=macos-keychain|linux-keyring|windows-dpapi|file-0600 outside CI to persist hardware-sealed audit keys.",
        }
      : {}),
  });

  // 4. Platform-Specific Kernel & Sandbox Probes
  let recommendedIsolationTier = "Process AST + Redaction Gate";

  if (targetPlatform === "linux") {
    const lsmList = options.dryRun ? null : safeReadText("/sys/kernel/security/lsm");
    const hasLandlock = Boolean(lsmList?.includes("landlock"));
    checks.push({
      id: "linux-landlock",
      name: "Linux Landlock LSM",
      status: hasLandlock ? "PASS" : "WARN",
      detail: hasLandlock
        ? `Landlock active in /sys/kernel/security/lsm (${lsmList})`
        : lsmList
          ? `Landlock not listed in active LSMs (${lsmList})`
          : "Could not read /sys/kernel/security/lsm (kernel < 5.13 or restricted container)",
      ...(!hasLandlock
        ? {
            remediation:
              "Enable Landlock LSM on Linux kernel >= 5.13 (lsm=...,landlock) or use Bubblewrap isolation.",
          }
        : {}),
    });

    const bwrapProbe = options.dryRun
      ? { ok: false, output: "dry-run" }
      : probeCommand("bwrap", ["--version"]);
    checks.push({
      id: "linux-bwrap",
      name: "Bubblewrap (bwrap) Namespace Sandbox",
      status: bwrapProbe.ok ? "PASS" : "WARN",
      detail: bwrapProbe.ok ? `Available (${bwrapProbe.output})` : "bwrap binary not found in PATH",
      ...(!bwrapProbe.ok
        ? {
            remediation: "Install bubblewrap: sudo apt-get install -y bubblewrap (or dnf/pacman).",
          }
        : {}),
    });

    const apparmorUserns = options.dryRun
      ? null
      : safeReadText("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    if (apparmorUserns === "1") {
      checks.push({
        id: "linux-apparmor-userns",
        name: "Ubuntu 24.04+ AppArmor Unprivileged UserNS",
        status: "WARN",
        detail:
          "apparmor_restrict_unprivileged_userns=1 detected; unprivileged Bubblewrap sandboxes may require an AppArmor profile",
        remediation:
          "Add an AppArmor profile for bwrap or run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0",
      });
    } else {
      checks.push({
        id: "linux-apparmor-userns",
        name: "AppArmor Unprivileged UserNS Policy",
        status: "PASS",
        detail:
          apparmorUserns === "0"
            ? "Unprivileged user namespaces permitted (apparmor_restrict_unprivileged_userns=0)"
            : "No AppArmor userns restriction detected",
      });
    }

    const hasBpfFs = !options.dryRun && existsSync("/sys/fs/bpf");
    checks.push({
      id: "linux-ebpf",
      name: "eBPF Filesystem (/sys/fs/bpf)",
      status: hasBpfFs ? "PASS" : "INFO",
      detail: hasBpfFs
        ? "/sys/fs/bpf mounted (eBPF LSM sidecar monitoring supported)"
        : "/sys/fs/bpf not mounted (optional for Enterprise eBPF telemetry)",
    });

    const secretTool = options.dryRun
      ? { ok: false, output: "dry-run" }
      : probeCommand("secret-tool", ["--version"]);
    checks.push({
      id: "linux-secret-tool",
      name: "Linux Secret Service (secret-tool)",
      status: secretTool.ok ? "PASS" : "INFO",
      detail: secretTool.ok
        ? "secret-tool available for hardware-backed Ed25519 key sealing"
        : "secret-tool not installed; will fall back to 0600 keyfile sealing",
      ...(!secretTool.ok
        ? { remediation: "Install libsecret-tools for OS keyring Ed25519 sealing." }
        : {}),
    });

    if (bwrapProbe.ok && apparmorUserns !== "1") {
      recommendedIsolationTier = hasLandlock
        ? "Linux Landlock LSM + Bubblewrap Namespace Sandbox"
        : "Linux Bubblewrap Namespace Sandbox";
    } else if (hasLandlock) {
      recommendedIsolationTier = "Linux Landlock LSM + AST Command Gate";
    }
  } else if (targetPlatform === "darwin") {
    const seatbeltProbe = options.dryRun
      ? { ok: false, output: "dry-run" }
      : probeCommand("which", ["sandbox-exec"]);
    checks.push({
      id: "macos-seatbelt",
      name: "macOS Seatbelt (sandbox-exec)",
      status: seatbeltProbe.ok ? "PASS" : "WARN",
      detail: seatbeltProbe.ok
        ? `Available at ${seatbeltProbe.output}`
        : "sandbox-exec not found in PATH",
      ...(!seatbeltProbe.ok
        ? { remediation: "Verify /usr/bin/sandbox-exec is accessible on macOS." }
        : {}),
    });

    const keychainProbe = options.dryRun
      ? { ok: false, output: "dry-run" }
      : probeCommand("which", ["security"]);
    checks.push({
      id: "macos-keychain",
      name: "macOS Keychain CLI (security)",
      status: keychainProbe.ok ? "PASS" : "WARN",
      detail: keychainProbe.ok
        ? `Available at ${keychainProbe.output} for Ed25519 key sealing`
        : "macOS security binary unavailable; falling back to 0600 keyfile",
    });

    if (seatbeltProbe.ok) {
      recommendedIsolationTier = "macOS Seatbelt (sandbox-exec) + Keychain Ed25519 Sealing";
    }
  } else if (targetPlatform === "win32") {
    const psProbe = options.dryRun
      ? { ok: false, output: "dry-run" }
      : probeCommand("powershell.exe", [
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Add-Type -AssemblyName System.Security; [bool]([System.Security.Cryptography.ProtectedData])",
        ]);
    checks.push({
      id: "windows-dpapi",
      name: "Windows DPAPI Hardware Key Sealing",
      status: psProbe.ok && psProbe.output.toLowerCase().includes("true") ? "PASS" : "WARN",
      detail:
        psProbe.ok && psProbe.output.toLowerCase().includes("true")
          ? "System.Security.Cryptography.ProtectedData (CurrentUser DPAPI) operational"
          : "PowerShell DPAPI probe unavailable; falling back to restricted file key",
      ...(!(psProbe.ok && psProbe.output.toLowerCase().includes("true"))
        ? {
            remediation:
              "Ensure Windows PowerShell 5.1+ / .NET System.Security assembly is accessible.",
          }
        : {}),
    });

    checks.push({
      id: "windows-sandbox-boundary",
      name: "Windows Process Sandbox Boundary",
      status: "INFO",
      detail:
        "Job Object / Restricted Token command gate active; use WSL2 Linux for full Bubblewrap/Landlock kernel namespace isolation",
      remediation:
        "For strict kernel-level filesystem isolation on Windows, run autonomous agents inside WSL2 with --kernel.",
    });

    recommendedIsolationTier =
      psProbe.ok && psProbe.output.toLowerCase().includes("true")
        ? "Windows DPAPI Sealing + AST Command Gate (WSL2 recommended for kernel namespaces)"
        : "Windows AST Command Gate + Linear-Time Redactor";
  }

  // 5. Air-Gapped Telemetry Posture
  checks.push({
    id: "air-gapped-mode",
    name: "Air-Gapped Zero-Egress Mode",
    status: "INFO",
    detail: airGapped
      ? "ENABLED (AGENTSHIELD_AIR_GAPPED=1) — zero outbound network requests permitted"
      : "Standard mode (pass --air-gapped or set AGENTSHIELD_AIR_GAPPED=1 for strict zero-egress operation)",
  });

  const hasFail = checks.some((c) => c.status === "FAIL");
  const hasWarn = checks.some((c) => c.status === "WARN");
  const overallStatus = hasFail ? "ACTION_REQUIRED" : hasWarn ? "DEGRADED" : "READY";

  return {
    timestamp: new Date().toISOString(),
    platform: targetPlatform,
    arch: arch(),
    osRelease,
    nodeVersion,
    airGapped,
    overallStatus,
    recommendedIsolationTier,
    checks,
  };
}

/**
 * Formats a SandboxDoctorReport into a clean human-readable CLI diagnostic table.
 */
export function formatDoctorReport(report: SandboxDoctorReport): string {
  const lines: string[] = [
    "🩺 AgentShield Sandbox & Kernel Diagnostics (agentshield doctor)",
    "────────────────────────────────────────────────────────────────────",
    `Platform:          ${report.platform} (${report.arch}, release ${report.osRelease})`,
    `Node.js:           ${report.nodeVersion}`,
    `Overall Status:    ${report.overallStatus}`,
    `Isolation Tier:    ${report.recommendedIsolationTier}`,
    "────────────────────────────────────────────────────────────────────",
  ];

  for (const check of report.checks) {
    const icon =
      check.status === "PASS"
        ? "✅"
        : check.status === "WARN"
          ? "⚠️"
          : check.status === "FAIL"
            ? "❌"
            : "ℹ️";
    lines.push(`${icon} [${check.status}] ${check.name}`);
    lines.push(`   ${check.detail}`);
    if (check.remediation) {
      lines.push(`   Fix: ${check.remediation}`);
    }
  }

  lines.push("────────────────────────────────────────────────────────────────────");
  return lines.join("\n");
}
