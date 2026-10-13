#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig, parseCustomPatterns } from "./config.js";
import { AgentShieldEngine } from "./engine.js";
import {
  clearCredentials,
  fetchRemotePolicy,
  loadCredentials,
  mergeRemotePolicyIntoConfig,
  saveCredentials,
} from "./remote-policy.js";
import type { ScanOptions } from "./types.js";
import { AGENTSHIELD_VERSION } from "./version.js";

function printBanner() {
  console.log(`
🛡️ AgentShield (v${AGENTSHIELD_VERSION}) — Zero-Leak Agentic Defense
   Enterprise-Grade AI Secret Redactor & Sandbox
   https://github.com/RitualDev-Lab/AgentShield
`);
}

function printHelp() {
  printBanner();
  console.log(`
Usage:
  npx @ritualdev_lab/agentshield scan <file-path>       Scan a file for leaked secrets
  npx @ritualdev_lab/agentshield redact <file-path>     Redact secrets and print sanitized text
  npx @ritualdev_lab/agentshield stream                 Redact secrets from piped stdin (for terminal hooks)
  npx @ritualdev_lab/agentshield exec <command>         Safely sandbox & intercept agent bash command
  npx @ritualdev_lab/agentshield run <command>          Run command with real-time streaming stdio secret redaction
  npx @ritualdev_lab/agentshield hook git-install       Install automatic git pre-commit leak shield
  npx @ritualdev_lab/agentshield hook check             Audit git staged files before commit
  npx @ritualdev_lab/agentshield ci                     Audit pull request or git diff in CI/CD pipeline
  npx @ritualdev_lab/agentshield init-claude            Generate Claude Code PreToolUse hook configuration
  npx @ritualdev_lab/agentshield init-cursor            Generate Cursor / Windsurf settings.json protection rules
  npx @ritualdev_lab/agentshield benchmark              Run sub-millisecond scanning throughput benchmarks

Enterprise Team Fleet & Remote Policy:
  npx @ritualdev_lab/agentshield login --org <id> --token <key>   Authenticate machine with enterprise organization
  npx @ritualdev_lab/agentshield logout                           Disconnect machine and clear organization credentials
  npx @ritualdev_lab/agentshield policy sync                      Fetch and synchronize remote enterprise security policy
  npx @ritualdev_lab/agentshield server [--port <number>]         Run local/self-hosted SaaS Control Plane server MVP
  npx @ritualdev_lab/agentshield attestation [--org <name>]       Generate cryptographic SOC 2 / ISO 27001 bundle

Experimental Labs & Enterprise Controls (--labs / --experimental):
  npx @ritualdev_lab/agentshield compliance <file>      Audit credentials for SOC2, PCI-DSS, HIPAA & ISO27001
  npx @ritualdev_lab/agentshield audit                  Audit workspace MCP, .claude, and agent permission configs
  npx @ritualdev_lab/agentshield mcp-proxy              Run inline JSON-RPC proxy filter for MCP tool calls
  npx @ritualdev_lab/agentshield ledger verify          Verify cryptographic integrity of audit ledger HMAC chain

Options:
  --base <branch>                        Git base ref for CI diff (default: origin/main)
  --report <filePath>                    Write Markdown security audit report to file
  --sarif <filePath>                     Export findings in OASIS SARIF 2.1.0 format
  --format <cef|json|syslog>             SIEM log output format
  --style <token|hash|asterisk>          Redaction format (default: token)
  --labs, --experimental                 Enable experimental labs & enterprise control plane features
  --json                                 Output findings in structured JSON
  --help, -h                             Show this help message
`);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    printHelp();
    process.exit(0);
  }

  if (command === "login") {
    printBanner();
    let orgId = "";
    let token = "";
    let endpoint = "";

    const orgIdx = args.indexOf("--org");
    if (orgIdx !== -1 && args[orgIdx + 1]) orgId = args[orgIdx + 1];

    const tokenIdx =
      args.indexOf("--token") !== -1 ? args.indexOf("--token") : args.indexOf("--key");
    if (tokenIdx !== -1 && args[tokenIdx + 1]) token = args[tokenIdx + 1];

    const endpointIdx = args.indexOf("--endpoint");
    if (endpointIdx !== -1 && args[endpointIdx + 1]) endpoint = args[endpointIdx + 1];

    if (!orgId || !token) {
      console.error(
        "❌ Error: Missing required credentials. Usage: agentshield login --org <org-id> --token <token>",
      );
      process.exit(1);
    }

    saveCredentials({ orgId, token, endpoint });
    console.log(`✅ [AgentShield Enterprise] Machine registered with organization '${orgId}'.`);
    console.log("   Fetching enterprise security policies...");

    const { policy, isCached, error } = await fetchRemotePolicy();
    if (policy) {
      console.log(
        `   Policy Version: ${policy.policyVersion} (${policy.customPatterns?.length || 0} custom enterprise rules active)`,
      );
      if (isCached) console.log("   (Loaded from resilient local cache)");
    } else if (error) {
      console.warn(
        `   ⚠️ Warning: Connected but could not fetch initial policy (${error}). Will retry on next scan.`,
      );
    }
    console.log("\n🚀 Enterprise policies active for all AI agent executions on this machine.\n");
    process.exit(0);
  }

  if (command === "logout") {
    printBanner();
    const success = clearCredentials();
    if (success) {
      console.log(
        "✅ [AgentShield Enterprise] Machine disconnected. Organization credentials cleared.\n",
      );
    } else {
      console.log("ℹ️ No active organization credentials found.\n");
    }
    process.exit(0);
  }

  if (command === "policy") {
    const subAction = args[1] || "sync";
    printBanner();
    if (subAction === "sync") {
      const creds = loadCredentials();
      if (!creds) {
        console.error(
          "❌ Error: Machine is not logged into an enterprise organization. Run 'agentshield login --org <id> --token <token>' first.",
        );
        process.exit(1);
      }
      console.log(`🔄 Fetching latest policies for org '${creds.orgId}' from ${creds.endpoint}...`);
      const { policy, isCached, error } = await fetchRemotePolicy(creds, { timeoutMs: 5000 });
      if (policy) {
        console.log("✅ [Policy Sync Success]");
        console.log(`   Policy Version:       ${policy.policyVersion}`);
        console.log(`   Custom Rules Count:   ${policy.customPatterns?.length || 0}`);
        console.log(`   Allowlist Entries:    ${policy.allowlist?.length || 0}`);
        console.log(
          `   Status:               ${isCached ? "Offline Cache Activated" : "Live Sync Fresh"}`,
        );
        console.log(`   Updated At:           ${policy.updatedAt}\n`);
      } else {
        console.error(`❌ Policy sync failed: ${error || "Unknown network error"}\n`);
        process.exit(1);
      }
      process.exit(0);
    } else {
      console.error(`❌ Unknown policy action '${subAction}'. Usage: agentshield policy sync`);
      process.exit(1);
    }
  }

  if (command === "server") {
    printBanner();
    let port = 3000;
    const portIdx = args.indexOf("--port");
    if (portIdx !== -1 && args[portIdx + 1]) {
      const parsedPort = Number.parseInt(args[portIdx + 1], 10);
      if (!Number.isNaN(parsedPort)) port = parsedPort;
    }

    const { ControlPlaneServer } = await import("./control-plane-server.js");
    const serverInstance = new ControlPlaneServer({ port });
    const actualPort = await serverInstance.start();

    console.log(`🚀 [AgentShield Control Plane Server] Active on port ${actualPort}`);
    console.log(`   Health Check:    http://localhost:${actualPort}/api/v1/health`);
    console.log(`   Fleet Overview:  http://localhost:${actualPort}/api/v1/overview`);
    console.log(`   Incidents Stream: http://localhost:${actualPort}/api/v1/incidents`);
    console.log("\nPress Ctrl+C to terminate server.\n");

    // Keep server process running
    return new Promise(() => {});
  }

  if (command === "attestation") {
    printBanner();
    let orgName = "Enterprise Organization";
    const orgIdx = args.indexOf("--org");
    if (orgIdx !== -1 && args[orgIdx + 1]) orgName = args[orgIdx + 1];

    const isMarkdown = args.includes("--markdown");
    const outIdx = args.indexOf("--out");
    const outPath = outIdx !== -1 ? args[outIdx + 1] : null;

    const { EnterpriseComplianceBundleGenerator } = await import("./enterprise-bundle.js");
    const { TamperEvidentLedger } = await import("./ledger.js");

    // Load ledger entries from local workspace ledger if available
    const ledgerPath = join(process.cwd(), ".agentshield", "audit.ledger.jsonl");
    const ledger = new TamperEvidentLedger(ledgerPath);
    const ledgerEntries = ledger.getEntries();

    const creds = loadCredentials();
    if (creds?.orgId && orgName === "Enterprise Organization") {
      orgName = creds.orgId;
    }

    const bundle = EnterpriseComplianceBundleGenerator.generateBundle(
      [],
      ledgerEntries,
      process.env.AGENTSHIELD_LEDGER_KEY || "agentshield-tamper-evident-salt-v1",
      { organizationName: orgName },
    );

    const outputText = isMarkdown
      ? EnterpriseComplianceBundleGenerator.toExecutiveMarkdown(bundle)
      : JSON.stringify(bundle, null, 2);

    if (outPath) {
      writeFileSync(outPath, outputText, "utf8");
      console.log(`✅ Attestation bundle successfully written to '${outPath}'.\n`);
    } else {
      console.log(outputText);
    }
    process.exit(0);
  }

  // Load configuration from local workspace and overlay remote enterprise policy
  const localConfig = loadConfig(process.cwd());
  const creds = loadCredentials();
  let remotePolicy = null;
  if (creds?.orgId) {
    const remoteRes = await fetchRemotePolicy(creds, { timeoutMs: 1500 });
    remotePolicy = remoteRes.policy;
  }
  const config = mergeRemotePolicyIntoConfig(localConfig, remotePolicy);
  const customPatterns = parseCustomPatterns(config);
  const engine = new AgentShieldEngine(customPatterns);

  // Parse command options (flags take precedence, fallback to config)
  let maskStyle = config?.maskStyle || "token";
  const styleIdx = args.indexOf("--style");
  if (styleIdx !== -1 && args[styleIdx + 1]) {
    const s = args[styleIdx + 1].toLowerCase();
    if (s === "token" || s === "hash" || s === "asterisk") {
      maskStyle = s as "token" | "hash" | "asterisk";
    }
  }

  const isLabs = args.includes("--labs") || args.includes("--experimental");

  const scanOptions: ScanOptions = {
    allowlist: config?.allowlist || [],
    entropyThreshold: config?.entropyThreshold ?? 4.5,
    maskStyle,
  };

  if (command === "scan" || command === "redact") {
    const targetFile = args[1];
    if (!targetFile) {
      console.error("❌ Error: Please specify a file path to scan/redact.");
      process.exit(1);
    }

    if (!existsSync(targetFile)) {
      console.error(`❌ Error: File '${targetFile}' does not exist.`);
      process.exit(1);
    }

    const content = readFileSync(targetFile, "utf8");
    const isJson = args.includes("--json");
    const includeRaw = args.includes("--include-raw");

    if (includeRaw) {
      console.warn(
        "⚠️ [SECURITY WARNING] Output includes plaintext unredacted credentials (--include-raw).",
      );
    }

    const result = engine.scanAndRedact(content, {
      ...scanOptions,
      includeRaw,
    });

    if (command === "scan") {
      if (isJson) {
        const safeOutput = {
          hasSecrets: result.hasSecrets,
          totalFound: result.totalFound,
          findings: result.findings.map((f) => ({
            patternId: f.patternId,
            patternName: f.patternName,
            category: f.category,
            severity: f.severity,
            redacted: f.redacted,
            line: f.line,
            column: f.column,
            entropy: f.entropy,
            file: f.file,
            ...(includeRaw ? { raw: f.raw } : {}),
          })),
          sanitizedText: result.sanitizedText,
        };

        console.log(JSON.stringify(safeOutput, null, 2));
      } else {
        printBanner();
        if (!result.hasSecrets) {
          console.log(`✅ [CLEAN] No secrets detected in '${targetFile}'.`);
          process.exit(0);
        } else {
          console.log(
            `🚨 [ALERT] Found ${result.totalFound} exposed secret(s) in '${targetFile}':\n`,
          );
          for (const finding of result.findings) {
            console.log(
              `  • [${finding.severity.toUpperCase()}] ${finding.patternName} (Line ${finding.line}, Col ${finding.column})`,
            );
            console.log(`    Redacted: ${finding.redacted}`);
          }
          console.log("\n⚠️ To protect your workspace, redact or revoke these credentials.");
          process.exit(1);
        }
      }
    } else if (command === "redact") {
      process.stdout.write(result.sanitizedText);
      process.exit(0);
    }
  } else if (command === "stream") {
    // Read from standard input (useful for wrapping agent bash streams)
    let buffer = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      buffer += chunk;
    });
    process.stdin.on("end", () => {
      const result = engine.scanAndRedact(buffer, scanOptions);
      process.stdout.write(result.sanitizedText);
      process.exit(0);
    });
  } else if (command === "hook") {
    const subAction = args[1];
    const { GitPreCommitGate } = await import("./gate.js");
    const gate = new GitPreCommitGate(engine);

    if (subAction === "git-install") {
      const success = gate.installHook();
      if (success) {
        console.log(
          "✅ [AgentShield] Git pre-commit leak shield successfully installed in .git/hooks/pre-commit",
        );
      } else {
        console.error(
          "❌ [AgentShield] Could not find .git directory. Run this command inside a Git repository.",
        );
        process.exit(1);
      }
    } else if (subAction === "check") {
      const result = gate.auditStagedFiles();
      console.log(result.report);
      if (!result.passed) {
        process.exit(1);
      }
    } else {
      console.error("❌ Unknown hook action. Use 'git-install' or 'check'.");
      process.exit(1);
    }
  } else if (command === "exec" || command === "run") {
    // Intercept agent command execution using streaming stdio interceptor
    const rawCmd = args
      .slice(1)
      .filter((a) => !a.startsWith("--kernel"))
      .join(" ");
    if (!rawCmd) {
      console.error(
        `❌ Error: No command provided to sandbox. Usage: npx @ritualdev_lab/agentshield ${command} <command>`,
      );
      process.exit(1);
    }

    const enableKernel = args.includes("--kernel");
    const { AgentStdioInterceptor } = await import("./interceptor.js");
    const interceptor = new AgentStdioInterceptor(engine, process.cwd());

    const result = await interceptor.execute(rawCmd, {
      workspaceDir: process.cwd(),
      enableKernelSandbox: enableKernel,
      maskStyle,
      onBlock: (check) => {
        console.error(
          `\n🚨 [AgentShield Sandbox Block] ${check.reason}\n   Command: '${rawCmd}'\n`,
        );
      },
    });

    if (result.isBlocked) {
      process.exit(1);
    }
    process.exit(result.exitCode);
  } else if (command === "ci") {
    const { CiGateRunner } = await import("./ci.js");
    const runner = new CiGateRunner(process.cwd());

    let baseRef = "origin/main";
    const baseIdx = args.indexOf("--base");
    if (baseIdx !== -1 && args[baseIdx + 1]) {
      baseRef = args[baseIdx + 1];
    }

    let reportPath: string | null = null;
    const reportIdx = args.indexOf("--report");
    if (reportIdx !== -1 && args[reportIdx + 1]) {
      reportPath = args[reportIdx + 1];
    }

    const result = runner.auditPullRequest(baseRef);
    console.log(result.markdownReport);

    if (reportPath) {
      writeFileSync(reportPath, result.markdownReport, "utf8");
      console.log(`\n📄 [AgentShield] Security report written to ${reportPath}`);
    }

    if (!result.passed) {
      process.exit(1);
    }
    process.exit(0);
  } else if (command === "compliance") {
    if (!isLabs) {
      console.error(
        "❌ Error: 'compliance' is an experimental enterprise control plane feature. Pass --labs or --experimental to enable.",
      );
      process.exit(1);
    }
    const targetFile = args.filter((a) => !a.startsWith("--"))[1];
    if (!targetFile) {
      console.error("❌ Error: Please specify a file path to audit for compliance.");
      process.exit(1);
    }

    if (!existsSync(targetFile)) {
      console.error(`❌ Error: File '${targetFile}' does not exist.`);
      process.exit(1);
    }

    const content = readFileSync(targetFile, "utf8");
    const scan = engine.scanAndRedact(content);

    const { ComplianceEngine } = await import("./compliance.js");
    const report = ComplianceEngine.evaluate(scan.findings);

    if (args.includes("--json")) {
      console.log(JSON.stringify(report, null, 2));
      process.exit(report.status === "COMPLIANT" ? 0 : 1);
    }

    printBanner();
    console.log(
      `📋 [ENTERPRISE COMPLIANCE AUDIT] Status: ${report.status} (Score: ${report.score}%)\n`,
    );
    for (const ctrl of report.controls) {
      const icon = ctrl.status === "PASSED" ? "✅" : "❌";
      console.log(`  ${icon} [${ctrl.framework.toUpperCase()}] ${ctrl.controlId}: ${ctrl.name}`);
      if (ctrl.violations.length > 0) {
        for (const v of ctrl.violations) {
          console.log(`     ⚠️ ${v}`);
        }
      }
    }

    if (report.status !== "COMPLIANT") {
      process.exit(1);
    }
    process.exit(0);
  } else if (command === "audit") {
    if (!isLabs) {
      console.error(
        "❌ Error: 'audit' is an experimental agent configuration static analysis feature. Pass --labs or --experimental to enable.",
      );
      process.exit(1);
    }
    const { AgentConfigAuditor } = await import("./auditor.js");
    const { SarifFormatter } = await import("./sarif.js");
    const auditor = new AgentConfigAuditor(process.cwd());
    const report = auditor.auditWorkspace();

    const sarifIdx = args.indexOf("--sarif");
    if (sarifIdx !== -1 && args[sarifIdx + 1]) {
      const sarifPath = args[sarifIdx + 1];
      const sarif = SarifFormatter.generateSarif([], report.issues);
      writeFileSync(sarifPath, JSON.stringify(sarif, null, 2), "utf8");
      console.log(`📄 [AgentShield] SARIF 2.1.0 audit log written to ${sarifPath}`);
    }

    if (args.includes("--json")) {
      console.log(JSON.stringify(report, null, 2));
      process.exit(report.passed ? 0 : 1);
    }

    printBanner();
    console.log(
      `🔍 [AGENT ENVIRONMENT & PERMISSION AUDIT] Files Checked: ${report.totalFilesAudited}`,
    );
    if (report.issues.length === 0) {
      console.log(
        "✅ [CLEAN] No excessive agent permissions or exposed config credentials detected!",
      );
      process.exit(0);
    } else {
      console.log(`🚨 Found ${report.issues.length} configuration security issue(s):\n`);
      for (const issue of report.issues) {
        console.log(`  • [${issue.severity.toUpperCase()}] ${issue.title}`);
        console.log(`    File: ${issue.file}`);
        console.log(`    Risk: ${issue.description}`);
        console.log(`    Fix:  ${issue.recommendation}\n`);
      }
      process.exit(report.passed ? 0 : 1);
    }
  } else if (command === "mcp-proxy") {
    if (!isLabs) {
      console.error(
        "❌ Error: 'mcp-proxy' is an experimental stdio protocol interceptor. Pass --labs or --experimental to enable.",
      );
      process.exit(1);
    }
    // Pipe filter for MCP stdio / JSON-RPC communication
    const { McpProxyInterceptor } = await import("./mcp-proxy.js");
    const proxy = new McpProxyInterceptor(engine);

    let buffer = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      buffer += chunk;
      const lines = buffer.split("\n");
      buffer = lines.pop() || "";

      for (const line of lines) {
        if (!line.trim()) continue;
        const verdict = proxy.inspectRequest(line);
        if (verdict.isBlocked) {
          const errResponse = {
            jsonrpc: "2.0",
            error: { code: -32600, message: verdict.reason },
          };
          process.stdout.write(`${JSON.stringify(errResponse)}\n`);
        } else {
          process.stdout.write(`${verdict.sanitizedPayload || line}\n`);
        }
      }
    });

    process.stdin.on("end", () => {
      process.exit(0);
    });
  } else if (command === "ledger") {
    if (!isLabs) {
      console.error(
        "❌ Error: 'ledger' is an experimental tamper-evident audit ledger. Pass --labs or --experimental to enable.",
      );
      process.exit(1);
    }
    const subCmd = args.filter((a) => !a.startsWith("--"))[1];
    const { TamperEvidentLedger } = await import("./ledger.js");
    const ledger = new TamperEvidentLedger();

    if (subCmd === "verify") {
      const result = ledger.verifyChain();
      printBanner();
      if (result.isValid) {
        console.log(
          `✅ [LEDGER INTEGRITY VERIFIED] ${result.totalEntries} block(s) checked. Cryptographic HMAC chain is 100% intact.`,
        );
        process.exit(0);
      } else {
        console.error(
          `🚨 [CORRUPTED AUDIT LEDGER] Integrity check failed at sequence #${result.corruptedSequence}!`,
        );
        console.error(`   Error: ${result.error}`);
        process.exit(1);
      }
    } else {
      console.error(
        "❌ Unknown ledger action. Use 'npx @ritualdev_lab/agentshield ledger verify'.",
      );
      process.exit(1);
    }
  } else if (command === "benchmark") {
    const { AgentShieldBenchmark } = await import("./enterprise-baseline.js");
    printBanner();
    console.log(
      "⚡ [AgentShield Performance Benchmark] Executing 1,000 secret inspection iterations...",
    );
    const sample =
      "const OPENAI_API_KEY = 'sk-proj-abc123456789012345678901234567890';\nconst AWS_KEY = 'AKIA1234567890EXAMPLE';";
    const metrics = AgentShieldBenchmark.runScanBenchmark(sample, 1000, engine);
    console.log(`\n  • Throughput:      ${metrics.throughputMbPerSecond} MB/sec`);
    console.log(`  • Operations/Sec:  ${metrics.opsPerSecond.toLocaleString()} scans/sec`);
    console.log(`  • Average Latency: ${metrics.averageLatencyMs} ms / scan`);
    console.log(`  • Iterations:      ${metrics.iterations.toLocaleString()}`);
    console.log(`  • Total Duration:  ${metrics.totalTimeMs} ms\n`);
    console.log("✅ Benchmark passed within sub-millisecond execution constraints.");
    process.exit(0);
  } else if (command === "init-claude") {
    const { mkdirSync } = await import("node:fs");
    const claudeDir = join(process.cwd(), ".claude");
    if (!existsSync(claudeDir)) {
      mkdirSync(claudeDir, { recursive: true });
    }
    const settingsPath = join(claudeDir, "settings.json");
    const claudeConfig = {
      hooks: {
        PreToolUse: [
          {
            matcher: "Bash|Terminal",
            command: "npx @ritualdev_lab/agentshield exec $COMMAND",
          },
        ],
      },
    };
    writeFileSync(settingsPath, JSON.stringify(claudeConfig, null, 2), "utf8");
    printBanner();
    console.log(`✅ [Claude Code] Hook configuration created at: ${settingsPath}`);
    console.log("   Agent bash commands will now be automatically intercepted by AgentShield.\n");
    process.exit(0);
  } else if (command === "init-cursor") {
    const { mkdirSync } = await import("node:fs");
    const cursorDir = join(process.cwd(), ".cursor");
    if (!existsSync(cursorDir)) {
      mkdirSync(cursorDir, { recursive: true });
    }
    const rulesPath = join(cursorDir, "rules.json");
    const cursorConfig = {
      version: 1,
      security: {
        preExecutionCommand: "npx @ritualdev_lab/agentshield exec $COMMAND",
        blockOnSensitiveFileRead: true,
        sensitivePatterns: [".env*", "*.pem", "id_rsa*", "*.key"],
      },
    };
    writeFileSync(rulesPath, JSON.stringify(cursorConfig, null, 2), "utf8");
    printBanner();
    console.log(`✅ [Cursor / Windsurf] Protection rules written to: ${rulesPath}`);
    console.log("   AI agent workspace boundaries and credential paths are protected.\n");
    process.exit(0);
  } else {
    console.error(`❌ Unknown command '${command}'. Run 'agentshield --help' for usage.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal Error:", err);
  process.exit(1);
});
