#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import { AgentShieldEngine } from "./engine.js";

function printBanner() {
  console.log(`
🛡️ AgentShield (v0.1.0) — Zero-Leak Agentic Defense
   Enterprise-Grade AI Secret Redactor & Sandbox
   https://github.com/RitualDev-Lab/AgentShield
`);
}

function printHelp() {
  printBanner();
  console.log(`
Usage:
  npx agentshield scan <file-path>       Scan a file for leaked secrets
  npx agentshield redact <file-path>     Redact secrets and print sanitized text
  npx agentshield stream                 Redact secrets from piped stdin (for terminal hooks)
  npx agentshield hook git-install       Install automatic git pre-commit leak shield

Options:
  --style <token|asterisk>               Redaction format (default: token)
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

  const engine = new AgentShieldEngine();

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
    const result = engine.scanAndRedact(content);

    if (command === "scan") {
      if (isJson) {
        console.log(JSON.stringify(result, null, 2));
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
      const result = engine.scanAndRedact(buffer);
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
  } else if (command === "exec") {
    // Intercept agent command execution
    const rawCmd = args.slice(1).join(" ");
    if (!rawCmd) {
      console.error(
        "❌ Error: No command provided to sandbox. Usage: npx agentshield exec <command>",
      );
      process.exit(1);
    }

    const { AgentCommandSandbox } = await import("./sandbox.js");
    const sandbox = new AgentCommandSandbox();
    const check = sandbox.inspectCommand(rawCmd);

    if (check.isBlocked) {
      console.error(`\n🚨 [AgentShield Sandbox Block] ${check.reason}\n   Command: '${rawCmd}'\n`);
      process.exit(1);
    }

    // Command is safe to execute
    const { execSync } = await import("node:child_process");
    try {
      execSync(rawCmd, { stdio: "inherit" });
    } catch (err: unknown) {
      const exitCode =
        err && typeof err === "object" && "status" in err && typeof err.status === "number"
          ? err.status
          : 1;
      process.exit(exitCode);
    }
  } else {
    console.error(`❌ Unknown command '${command}'. Run 'agentshield --help' for usage.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal Error:", err);
  process.exit(1);
});
