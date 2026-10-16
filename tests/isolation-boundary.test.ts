import assert from "node:assert";
import { existsSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { AgentShieldEngine } from "../src/engine.js";
import { AgentStdioInterceptor } from "../src/interceptor.js";
import {
  KernelSandboxConfinement,
  getOsIsolationGuarantee,
} from "../src/kernel.js";
import type { CommandInspectionResult } from "../src/sandbox.js";

describe("A2 Regression: Strict Isolation Enforcement & Defense-in-Depth Boundary", () => {
  const engine = new AgentShieldEngine();
  const kernel = new KernelSandboxConfinement();

  describe("1. OS Isolation Guarantees Matrix & Boundary Taxonomy", () => {
    it("reports kernel-enforced boundary for macOS darwin", () => {
      const guarantee = getOsIsolationGuarantee("darwin");
      assert.strictEqual(guarantee.os, "darwin");
      assert.strictEqual(guarantee.kernelIsolationSupported, true);
      assert.strictEqual(guarantee.primaryMechanism, "macos_sandbox_exec");
      assert.strictEqual(guarantee.boundaryType, "kernel_enforced");
      assert.ok(guarantee.securityBoundaryLimitations.length > 0);
    });

    it("documents defense-in-depth boundary for Linux default runtime", () => {
      const guarantee = getOsIsolationGuarantee("linux");
      assert.strictEqual(guarantee.os, "linux");
      assert.strictEqual(guarantee.kernelIsolationSupported, false);
      assert.strictEqual(guarantee.primaryMechanism, "linux_landlock");
      assert.strictEqual(guarantee.boundaryType, "defense_in_depth_firewall");
      assert.ok(guarantee.securityBoundaryLimitations.length > 0);
    });

    it("documents defense-in-depth boundary for Windows", () => {
      const guarantee = getOsIsolationGuarantee("win32");
      assert.strictEqual(guarantee.os, "win32");
      assert.strictEqual(guarantee.kernelIsolationSupported, false);
      assert.strictEqual(guarantee.primaryMechanism, "windows_appcontainer");
      assert.strictEqual(guarantee.boundaryType, "defense_in_depth_firewall");
      assert.ok(guarantee.securityBoundaryLimitations.length > 0);
    });

    it("handles unknown/other operating systems cleanly", () => {
      const guarantee = getOsIsolationGuarantee("freebsd" as NodeJS.Platform);
      assert.strictEqual(guarantee.os, "freebsd");
      assert.strictEqual(guarantee.kernelIsolationSupported, false);
      assert.strictEqual(guarantee.primaryMechanism, "process_level_firewall");
      assert.strictEqual(guarantee.boundaryType, "defense_in_depth_firewall");
    });

    it("KernelSandboxConfinement.checkIsolationSupport matches guarantee status", () => {
      const darwinCheck = kernel.checkIsolationSupport("darwin");
      assert.strictEqual(darwinCheck.supported, true);
      assert.strictEqual(darwinCheck.mechanism, "macos_sandbox_exec");
      assert.strictEqual(darwinCheck.reason, undefined);

      const linuxCheck = kernel.checkIsolationSupport("linux");
      assert.strictEqual(linuxCheck.supported, false);
      assert.strictEqual(linuxCheck.mechanism, "linux_landlock");
      assert.ok(linuxCheck.reason?.includes("does not support active kernel sandbox"));

      const winCheck = kernel.checkIsolationSupport("win32");
      assert.strictEqual(winCheck.supported, false);
      assert.strictEqual(winCheck.mechanism, "windows_appcontainer");
      assert.ok(winCheck.reason?.includes("does not support active kernel sandbox"));
    });
  });

  describe("2. requireIsolation Mode (Fail-Closed on Unsupported Host)", () => {
    it("refuses execution when requireIsolation: true on non-darwin platform", async () => {
      const interceptor = new AgentStdioInterceptor(engine);
      let blockedEvent: CommandInspectionResult | undefined;

      const result = await interceptor.execute('node -e "console.log(123)"', {
        requireIsolation: true,
        targetPlatform: "linux",
        onBlock: (inspection) => {
          blockedEvent = inspection;
        },
      });

      assert.strictEqual(result.isBlocked, true);
      assert.strictEqual(result.exitCode, 1);
      assert.strictEqual(result.isolationMechanism, "isolated_refusal");
      assert.strictEqual(result.downgradedIsolation, false);
      assert.ok(result.blockReason?.includes("requireIsolation is enabled"));
      assert.ok(result.blockReason?.includes("linux"));
      assert.ok(result.isolationNotice.includes("strict isolation policy"));

      assert.ok(blockedEvent);
      assert.strictEqual(blockedEvent?.isBlocked, true);
      assert.strictEqual(blockedEvent?.category, "dangerous_mutation");
    });

    it("guarantees child process is NEVER spawned when requireIsolation refuses execution", async () => {
      const interceptor = new AgentStdioInterceptor(engine);
      const probeFile = join(process.cwd(), `test-probe-${Date.now()}.tmp`);

      try {
        if (existsSync(probeFile)) unlinkSync(probeFile);

        const sideEffectCmd = `node -e "require('fs').writeFileSync('${probeFile.replace(/\\/g, "\\\\")}', 'hacked')"`;

        const result = await interceptor.execute(sideEffectCmd, {
          requireIsolation: true,
          targetPlatform: "win32",
        });

        assert.strictEqual(result.isBlocked, true);
        assert.strictEqual(result.isolationMechanism, "isolated_refusal");
        assert.strictEqual(existsSync(probeFile), false, "Probe file MUST NOT be created if execution was refused");
      } finally {
        if (existsSync(probeFile)) {
          try {
            unlinkSync(probeFile);
          } catch {
            // ignore cleanup failure
          }
        }
      }
    });
  });

  describe("3. Permissive Downgrade Transparency (enableKernelSandbox without requireIsolation)", () => {
    it("flags downgradedIsolation: true and includes defense-in-depth warning on non-darwin", async () => {
      const interceptor = new AgentStdioInterceptor(engine);

      const result = await interceptor.execute('node -e "console.log(42)"', {
        enableKernelSandbox: true,
        requireIsolation: false,
        targetPlatform: "linux",
      });

      assert.strictEqual(result.isBlocked, false);
      assert.strictEqual(result.exitCode, 0);
      assert.strictEqual(result.isolationMechanism, "process_level_firewall");
      assert.strictEqual(result.downgradedIsolation, true);
      assert.ok(result.isolationNotice.includes("Kernel sandbox requested, but OS-level sandbox-exec is only supported on macOS"));
      assert.ok(result.isolationNotice.includes("defense-in-depth"));
      assert.ok(result.isolationNotice.includes("requireIsolation: true"));
    });

    it("flags downgradedIsolation: false when no sandbox was requested", async () => {
      const interceptor = new AgentStdioInterceptor(engine);

      const result = await interceptor.execute('node -e "console.log(42)"', {
        enableKernelSandbox: false,
        requireIsolation: false,
      });

      assert.strictEqual(result.isBlocked, false);
      assert.strictEqual(result.exitCode, 0);
      assert.strictEqual(result.isolationMechanism, "process_level_firewall");
      assert.strictEqual(result.downgradedIsolation, false);
      assert.ok(result.isolationNotice.includes("defense-in-depth"));
    });
  });
});
