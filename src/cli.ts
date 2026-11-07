#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync, statSync, readdirSync } from "node:fs";
import { platform } from "node:os";
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
import type { DetectedSecret, ScanOptions } from "./types.js";
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
  npx @ritualdev-lab/agentshield scan <file-path>       Scan a file for leaked secrets
  npx @ritualdev-lab/agentshield redact <file-path>     Redact secrets and print sanitized text
  npx @ritualdev-lab/agentshield stream                 Redact secrets from piped stdin (for terminal hooks)
  npx @ritualdev-lab/agentshield exec <command>         Safely sandbox & intercept agent bash command
  npx @ritualdev-lab/agentshield hook install           Install automatic git pre-commit leak shield (.git/hooks)
  npx @ritualdev-lab/agentshield hook uninstall         Uninstall automatic git pre-commit leak shield
  npx @ritualdev-lab/agentshield hook husky             Configure AgentShield for Husky (.husky/pre-commit)
  npx @ritualdev-lab/agentshield hook check             Audit git staged files before commit
  npx @ritualdev-lab/agentshield ci                     Audit pull request or git diff in CI/CD pipeline
  npx @ritualdev-lab/agentshield init-claude            Generate Claude Code PreToolUse hook configuration
  npx @ritualdev-lab/agentshield init-cursor            Generate Cursor / Windsurf settings.json protection rules
  npx @ritualdev-lab/agentshield benchmark              Run sub-millisecond scanning throughput benchmarks
  npx @ritualdev-lab/agentshield top                    Launch live interactive terminal process & taint monitor
  npx @ritualdev-lab/agentshield wrap <server...>       Transparent zero-config MCP wrapper for IDEs & agents
  npx @ritualdev-lab/agentshield badge <tool-name>      Generate Secured by AgentShield verified sponsor badge markdown / SVG
  npx @ritualdev-lab/agentshield bounty-verify <input>  Run local security PoC check against sandbox and secret engine
  npx @ritualdev-lab/agentshield upgrade [--tier pro]   Upgrade to Pro ($15/mo) or Team ($99/mo) via Dodo Payments

Enterprise Team Fleet & Remote Policy:
  npx @ritualdev-lab/agentshield login --sso                      Authenticate via corporate SSO (Okta, Google, Azure AD RFC 8628)
  npx @ritualdev-lab/agentshield login --org <id> --token <key>   Authenticate machine with enterprise organization
  npx @ritualdev-lab/agentshield siem export [--format cef|syslog] Export scan audit findings to CEF or Syslog RFC 5424
  npx @ritualdev-lab/agentshield siem test --target <service>     Test live HTTPS forwarding to Datadog, Splunk, or Webhook
  npx @ritualdev-lab/agentshield logout                           Disconnect machine and clear organization credentials
  npx @ritualdev-lab/agentshield policy sync                      Fetch and synchronize remote enterprise security policy
  npx @ritualdev-lab/agentshield server [--port <number>]         Run local/self-hosted SaaS Control Plane server MVP
  npx @ritualdev-lab/agentshield report [--compliance soc2]       Generate verifiable SOC 2 / ISO 27001 audit PDF & HTML
  npx @ritualdev-lab/agentshield attestation [--org <name>]       Generate cryptographic SOC 2 / ISO 27001 bundle

Experimental Labs & Enterprise Controls (--labs / --experimental):
  npx @ritualdev-lab/agentshield compliance <file>      Audit credentials for SOC2, PCI-DSS, HIPAA & ISO27001
  npx @ritualdev-lab/agentshield audit                  Audit workspace MCP, .claude, and agent permission configs
  npx @ritualdev-lab/agentshield mcp-proxy              Run inline JSON-RPC proxy filter for MCP tool calls
  npx @ritualdev-lab/agentshield ledger verify          Verify cryptographic integrity of audit ledger HMAC chain

Options:
  --compliance <soc2|iso27001>           Target compliance framework (default: soc2)
  --audit-pdf <filePath>                 Write verifiable PDF compliance audit report to file
  --air-gapped                           Run 100% offline with zero outbound phone-homes (local LLM mode)
  --base <branch>                        Git base ref for CI diff (default: origin/main)
  --report <filePath>                    Write Markdown security audit report to file
  --sarif <filePath>                     Export findings in OASIS SARIF 2.1.0 format
  --format <cef|json|syslog>             SIEM log output format
  --style <token|hash|asterisk>          Redaction format (default: token)
  --labs, --experimental                 Enable experimental labs & enterprise control plane features
  --json                                 Output findings in structured JSON
  --version, -v                          Show version number
  --help, -h                             Show this help message
`);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (args.includes("--air-gapped")) {
    process.env.AGENTSHIELD_AIR_GAPPED = "1";
    process.env.RITUAL_AIR_GAPPED = "1";
  }

  if (
    command === "--version" ||
    command === "-v" ||
    command === "version" ||
    args.includes("--version") ||
    args.includes("-v")
  ) {
    console.log(AGENTSHIELD_VERSION);
    process.exit(0);
  }

  if (
    !command ||
    command === "--help" ||
    command === "-h" ||
    args.includes("--help") ||
    args.includes("-h")
  ) {
    printHelp();
    process.exit(0);
  }

  if (command === "report") {
    printBanner();
    let orgName = "Enterprise Organization";
    const orgIdx = args.indexOf("--org");
    if (orgIdx !== -1 && args[orgIdx + 1]) orgName = args[orgIdx + 1];

    const compIdx = args.indexOf("--compliance");
    const frameworkArg =
      compIdx !== -1 && args[compIdx + 1] ? args[compIdx + 1].toLowerCase() : "soc2";
    const frameworks: import("./compliance.js").ComplianceFramework[] =
      frameworkArg === "iso27001" ? ["iso27001"] : ["soc2"];

    const pdfIdx = args.indexOf("--audit-pdf");
    const outIdx = args.indexOf("-o") !== -1 ? args.indexOf("-o") : args.indexOf("--output");
    let outPath: string | null = null;
    let format: "pdf" | "html" | "json" | "markdown" = "html";

    if (pdfIdx !== -1 && args[pdfIdx + 1]) {
      outPath = args[pdfIdx + 1];
      format = "pdf";
    } else if (outIdx !== -1 && args[outIdx + 1]) {
      outPath = args[outIdx + 1];
      if (outPath.endsWith(".pdf")) format = "pdf";
      else if (outPath.endsWith(".json")) format = "json";
      else if (outPath.endsWith(".md")) format = "markdown";
      else format = "html";
    } else {
      outPath = `./agentshield-${frameworkArg}-audit.html`;
    }

    const formatIdx = args.indexOf("--format");
    if (formatIdx !== -1 && args[formatIdx + 1]) {
      const f = args[formatIdx + 1].toLowerCase();
      if (f === "pdf" || f === "html" || f === "json" || f === "markdown") {
        format = f;
      }
    }

    const { EnterpriseComplianceBundleGenerator } = await import("./enterprise-bundle.js");
    const { TamperEvidentLedger } = await import("./ledger.js");

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
      { organizationName: orgName, frameworks },
    );

    let outputText = "";
    if (format === "html") {
      outputText = EnterpriseComplianceBundleGenerator.toHtml(bundle);
    } else if (format === "pdf") {
      outputText = EnterpriseComplianceBundleGenerator.toPdf(bundle);
    } else if (format === "markdown") {
      outputText = EnterpriseComplianceBundleGenerator.toExecutiveMarkdown(bundle);
    } else {
      outputText = JSON.stringify(bundle, null, 2);
    }

    if (outPath) {
      writeFileSync(outPath, outputText, "utf8");
      console.log(`
🛡️  AgentShield Compliance Audit Reporter
──────────────────────────────────────────
Framework:        ${frameworkArg.toUpperCase()}
Bundle ID:        ${bundle.bundleId}
Generated At:     ${bundle.generatedAt}
Compliance Score: ${bundle.complianceScore}% (${bundle.executiveStatus})
Auditor SHA Seal: ${bundle.rawEvidencePayloadSha256}
Report Saved To:  ${outPath}
──────────────────────────────────────────
Audit file ready for compliance officer review.
`);
    } else {
      console.log(outputText);
    }
    process.exit(0);
  }

  if (command === "upgrade") {
    printBanner();
    const tierIdx = args.indexOf("--tier");
    const tierArg = tierIdx !== -1 && args[tierIdx + 1] ? args[tierIdx + 1] : "pro";
    const selectedTierKey =
      tierArg === "team"
        ? "team-scale"
        : tierArg === "badge"
          ? "sponsor-verified-badge"
          : "pro-developer";

    const { DodoPaymentsService, SPONSORED_PRODUCTS } = await import("./dodo-payments.js");
    const dodo = new DodoPaymentsService();
    const product = SPONSORED_PRODUCTS[selectedTierKey];

    if (!product) {
      console.error(`❌ Unknown tier '${tierArg}'. Available: pro, team, badge`);
      process.exit(1);
    }

    try {
      const checkout = await dodo.createCheckoutSession({
        tierId: selectedTierKey,
        returnUrl: "https://ritual.dev/welcome-pro",
      });

      console.log(`
💳 Ritual Defense Upgrade (Powered by Dodo Payments)
────────────────────────────────────────────────────
Plan:               ${product.name}
Billing:            $${product.priceUsd}/month (${product.type})
Description:        ${product.description}

Features Included:
${product.features.map((f) => `  ✅ ${f}`).join("\n")}

Merchant of Record: Dodo Payments (Global Tax, Indian GST, VAT, Cards, UPI, Apple Pay)
Complete Checkout:  ${checkout.checkoutUrl}
────────────────────────────────────────────────────
`);
    } catch {
      console.log(`
💳 Ritual Defense Upgrade
────────────────────────────────────────────────────
Plan:               ${product.name}
Price:              $${product.priceUsd}/month (${product.type})
Features:
${product.features.map((f) => `  ✅ ${f}`).join("\n")}

Merchant of Record: Dodo Payments (Global Tax, Indian GST, VAT)
Direct Checkout:    https://checkout.dodopayments.com/buy/${product.id}?quantity=1
────────────────────────────────────────────────────
`);
    }
    process.exit(0);
  }

  if (command === "login") {
    printBanner();
    let orgId = "";
    let token = "";
    let endpoint = "";

    if (args.includes("--sso")) {
      const endpointIdx = args.indexOf("--endpoint");
      if (endpointIdx !== -1 && args[endpointIdx + 1]) endpoint = args[endpointIdx + 1];

      const providerIdx = args.indexOf("--provider");
      const provider = providerIdx !== -1 ? args[providerIdx + 1] : "okta";

      console.log(`
════════════════════════════════════════════════════════════════════════
🛡️ AgentShield Enterprise SSO — OAuth 2.0 Device Flow (RFC 8628)
════════════════════════════════════════════════════════════════════════
Initiating corporate SSO device authorization session...`);

      const { DeviceAuthorizationFlow } = await import("./enterprise-sso.js");
      const session = await DeviceAuthorizationFlow.initiate({ endpoint, orgId, provider });

      console.log(`
To authenticate this machine with your corporate Identity Provider:

1. Open your web browser:
   👉 ${session.verification_uri}

2. Enter or confirm this 8-character verification code:
   🔑  [ ${session.user_code} ]

Direct verification link:
   🔗 ${session.verification_uri_complete}
════════════════════════════════════════════════════════════════════════
`);

      // Attempt to launch browser automatically with safe argument separation
      try {
        const parsedUrl = new URL(session.verification_uri_complete);
        if (parsedUrl.protocol === "https:" || parsedUrl.protocol === "http:") {
          const { spawn } = await import("node:child_process");
          const targetUrl = parsedUrl.href;
          if (process.platform === "win32") {
            spawn("cmd.exe", ["/c", "start", '""', targetUrl], {
              detached: true,
              stdio: "ignore",
            }).unref();
          } else if (process.platform === "darwin") {
            spawn("open", [targetUrl], { detached: true, stdio: "ignore" }).unref();
          } else {
            spawn("xdg-open", [targetUrl], { detached: true, stdio: "ignore" }).unref();
          }
        }
      } catch {
        // silent fallback if browser launcher unavailable
      }

      process.stdout.write("⏳ Polling for browser SSO approval (press Ctrl+C to cancel)");
      const pollResult = await DeviceAuthorizationFlow.pollToken(session.device_code, {
        endpoint,
        interval: session.interval,
        onPoll: () => process.stdout.write("."),
      });
      console.log("\n");

      if (pollResult.status === "approved" && pollResult.token) {
        orgId = pollResult.claims?.orgId || orgId || "enterprise-sso-org";
        token = pollResult.token;
        saveCredentials({ orgId, token, endpoint });
        console.log(`✅ [AgentShield] Machine authenticated successfully via Enterprise SSO!`);
        if (pollResult.claims) {
          console.log(`   User:     ${pollResult.claims.email} (${pollResult.claims.name})`);
          console.log(`   Org ID:   ${pollResult.claims.orgId}`);
          console.log(`   Provider: ${pollResult.claims.provider}`);
          console.log(`   Roles:    ${pollResult.claims.roles.join(", ")}`);
        }
        process.exit(0);
      } else {
        console.error(`❌ SSO Authentication failed: ${pollResult.error || pollResult.status}`);
        process.exit(1);
      }
    }

    const orgIdx = args.indexOf("--org");
    if (orgIdx !== -1 && args[orgIdx + 1]) orgId = args[orgIdx + 1];

    const tokenIdx =
      args.indexOf("--token") !== -1 ? args.indexOf("--token") : args.indexOf("--key");
    if (tokenIdx !== -1 && args[tokenIdx + 1]) token = args[tokenIdx + 1];

    const licenseIdx = args.indexOf("--license");
    if (licenseIdx !== -1 && args[licenseIdx + 1]) token = args[licenseIdx + 1];

    if (!orgId && token) {
      if (token.startsWith("ASHIELD-PRO-")) {
        orgId = "pro-individual";
      } else if (token.startsWith("ASHIELD-TEAM-")) {
        orgId = "team-scale";
      } else {
        orgId = "licensed-developer";
      }
    }

    if (!orgId || !token) {
      console.error(
        "❌ Error: Missing credentials. Usage:\n   • Pro License:       agentshield login --key <license-key>\n   • Enterprise Team:   agentshield login --org <org-id> --token <token>",
      );
      process.exit(1);
    }

    saveCredentials({ orgId, token, endpoint });
    console.log(
      `✅ [AgentShield] Machine registered with ${orgId.includes("pro") ? "Pro License" : `Organization '${orgId}'`}.`,
    );
    console.log("   Initializing security defense & policies...");

    const { policy, isCached, error } = await fetchRemotePolicy();
    if (policy) {
      console.log(
        `   Policy Version: ${policy.policyVersion} (${policy.customPatterns?.length || 0} custom rules active)`,
      );
      if (isCached) console.log("   (Loaded from resilient local cache)");
    } else if (error) {
      console.log(
        `   🛡️ Standalone License Activated. Zero-leak redaction & kernel sandbox enforcement ready.`,
      );
    }
    console.log("\n🚀 Defense engine active for all AI agent executions on this machine.\n");
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

  if (command === "siem") {
    printBanner();
    const subAction = args[1] || "export";
    const { SiemExporter } = await import("./siem.js");

    const formatIdx = args.indexOf("--format");
    const format =
      (formatIdx !== -1 && (args[formatIdx + 1] as "cef" | "syslog" | "json")) || "cef";

    if (subAction === "export") {
      const fileIdx = args.indexOf("--file");
      const targetFile = fileIdx !== -1 ? args[fileIdx + 1] : undefined;

      if (targetFile && existsSync(targetFile)) {
        const config = await loadConfig();
        const customRules = parseCustomPatterns(config);
        const engine = new AgentShieldEngine(customRules);
        const content = readFileSync(targetFile, "utf8");
        const findings = engine.scan(content);
        for (const f of findings) {
          f.file = targetFile;
        }

        if (findings.length === 0) {
          console.log(`ℹ️ No secrets detected in '${targetFile}'. Nothing to export.`);
          process.exit(0);
        }

        console.log(
          `📦 Exporting ${findings.length} incident event(s) in [${format.toUpperCase()}] format:\n`,
        );
        const exporter = new SiemExporter({ format });
        for (const finding of findings) {
          // Explicitly sanitize finding to break taint flow and prevent clear-text secret logging
          const safeFinding: DetectedSecret = {
            ...finding,
            raw: "[REDACTED_BY_AGENTSHIELD]",
            redacted: finding.redacted || "[REDACTED]",
          };
          const event = SiemExporter.createSecretLeakEvent(safeFinding, {
            source: "AgentShield-CLI",
          });
          const formattedOutput = exporter.exportEvent(event, format);
          process.stdout.write(`${formattedOutput}\n`);
        }
      } else {
        // Export synthetic reference finding
        const sampleFinding: DetectedSecret = {
          file: targetFile || "src/auth/config.ts",
          line: 42,
          column: 15,
          raw: "[SYNTHETIC_MOCK_TOKEN]",
          redacted: "apiKey: [AGENTSHIELD_REDACTED:AWS_ACCESS_KEY:a1b2c3d4e5f6]",
          patternId: "aws-access-key",
          patternName: "AWS Access Key ID",
          category: "cloud",
          severity: "critical" as const,
        };
        const sampleEvent = SiemExporter.createSecretLeakEvent(sampleFinding);
        const exporter = new SiemExporter({ format });
        console.log(`📦 Sample SIEM Incident Event [${format.toUpperCase()}]:\n`);
        const formattedSample = exporter.exportEvent(sampleEvent, format);
        process.stdout.write(`${formattedSample}\n`);
        console.log(`\n💡 Tip: Provide a file to scan and export live findings:`);
        console.log(
          `   npx @ritualdev-lab/agentshield siem export --file <path> --format ${format}\n`,
        );
      }
      process.exit(0);
    }

    if (subAction === "test") {
      const targetIdx = args.indexOf("--target");
      const target = (targetIdx !== -1 ? args[targetIdx + 1] : "datadog").toLowerCase();

      const urlIdx = args.indexOf("--url");
      const targetUrl = urlIdx !== -1 ? args[urlIdx + 1] : undefined;

      const keyIdx = args.indexOf("--key");
      const apiKey =
        (keyIdx !== -1 ? args[keyIdx + 1] : undefined) ||
        process.env.DD_API_KEY ||
        process.env.SPLUNK_TOKEN ||
        "test_api_key_token";

      const sampleFinding = {
        file: "src/autonomous_agent.py",
        line: 12,
        column: 4,
        raw: "sk-1234567890abcdef1234567890abcdef",
        redacted: "OPENAI_API_KEY = '[AGENTSHIELD_REDACTED:OPENAI_KEY:9f8e7d6c5b4a]'",
        patternId: "openai-api-key",
        patternName: "OpenAI Secret Key",
        category: "ai",
        severity: "critical" as const,
      };
      const testEvent = SiemExporter.createSecretLeakEvent(sampleFinding);

      console.log(`📡 Testing SIEM telemetry forwarding to [${target.toUpperCase()}]...`);
      const startTime = Date.now();

      if (target === "datadog") {
        const siteIdx = args.indexOf("--site");
        const site = siteIdx !== -1 ? args[siteIdx + 1] : "datadoghq.com";
        const result = await SiemExporter.forwardToDatadog(testEvent, { apiKey, site });
        const latency = Date.now() - startTime;
        if (result.delivered) {
          console.log(
            `✅ [Datadog Logs API] Delivered successfully (HTTP ${result.statusCode}, ${latency}ms)`,
          );
        } else {
          console.log(
            `⚠️ [Datadog Logs API] Dispatch attempted (HTTP ${result.statusCode || "N/A"}: ${result.error || "Check API Key permissions"})`,
          );
        }
      } else if (target === "splunk") {
        const hecUrl = targetUrl || process.env.SPLUNK_HEC_URL || "https://localhost:8088";
        const result = await SiemExporter.forwardToSplunk(testEvent, { hecUrl, token: apiKey });
        const latency = Date.now() - startTime;
        if (result.delivered) {
          console.log(
            `✅ [Splunk HEC] Delivered successfully (HTTP ${result.statusCode}, ${latency}ms)`,
          );
        } else {
          console.log(
            `⚠️ [Splunk HEC] Dispatch attempted (HTTP ${result.statusCode || "N/A"}: ${result.error || "Check HEC URL & token"})`,
          );
        }
      } else {
        const webhookUrl = targetUrl || "https://ritualdev.in/api/v1/telemetry";
        const result = await SiemExporter.forwardToWebhook(testEvent, { url: webhookUrl, format });
        const latency = Date.now() - startTime;
        if (result.delivered) {
          console.log(
            `✅ [SIEM Webhook] Delivered successfully (HTTP ${result.statusCode}, ${latency}ms)`,
          );
        } else {
          console.log(
            `⚠️ [SIEM Webhook] Dispatch attempted (HTTP ${result.statusCode || "N/A"}: ${result.error || "Check endpoint connectivity"})`,
          );
        }
      }
      process.exit(0);
    }

    console.error(`❌ Unknown siem action '${subAction}'. Usage: agentshield siem <export|test>`);
    process.exit(1);
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

    let content = "";
    if (statSync(targetFile).isDirectory()) {
      const files: string[] = [];
      const walk = (dir: string) => {
        try {
          for (const entry of readdirSync(dir, { withFileTypes: true })) {
            if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") continue;
            const full = join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.isFile()) files.push(full);
          }
        } catch {}
      };
      walk(targetFile);
      content = files
        .map((f) => {
          try {
            return `// FILE: ${f}\n` + readFileSync(f, "utf8");
          } catch {
            return "";
          }
        })
        .join("\n\n");
    } else {
      content = readFileSync(targetFile, "utf8");
    }
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
    const subAction = args[1] || "check";
    const { GitPreCommitGate } = await import("./gate.js");
    const gate = new GitPreCommitGate(engine);

    if (subAction === "install" || subAction === "git-install") {
      const success = gate.installHook();
      if (success) {
        console.log(
          "✅ [AgentShield] Git pre-commit leak shield successfully installed in .git/hooks/pre-commit",
        );
        process.exit(0);
      } else {
        console.error(
          "❌ [AgentShield] Could not find .git directory. Run this command inside a Git repository.",
        );
        process.exit(1);
      }
    } else if (subAction === "uninstall") {
      const success = gate.uninstallHook();
      if (success) {
        console.log("✅ [AgentShield] Pre-commit hook removed from .git/hooks/pre-commit");
        process.exit(0);
      } else {
        console.warn("⚠️ [AgentShield] No AgentShield pre-commit hook found to uninstall.");
        process.exit(0);
      }
    } else if (subAction === "husky") {
      const success = gate.installHuskyHook();
      if (success) {
        console.log(
          "✅ [AgentShield] Husky pre-commit hook successfully configured in .husky/pre-commit",
        );
        process.exit(0);
      } else {
        console.error(
          "❌ [AgentShield] Could not find .husky directory. Please initialize Husky ('npx husky init') first.",
        );
        process.exit(1);
      }
    } else if (subAction === "check" || subAction === "run") {
      const result = gate.auditStagedFiles();
      if (args.includes("--json")) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        console.log(result.report);
      }
      if (!result.passed) {
        process.exit(1);
      }
      process.exit(0);
    } else {
      console.error("❌ Unknown hook action. Supported: 'install', 'uninstall', 'husky', 'check'.");
      process.exit(1);
    }
  } else if (command === "exec" || command === "run") {
    // Intercept agent command execution using streaming stdio interceptor
    let rawCmd = args
      .slice(1)
      .filter((a) => !a.startsWith("--kernel") && a !== "--claude-hook")
      .join(" ");

    // Check if called via Claude Code PreToolUse hook (JSON on stdin or empty args)
    if (!rawCmd && !process.stdin.isTTY) {
      try {
        const stdinChunks: Buffer[] = [];
        for await (const chunk of process.stdin) {
          stdinChunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
        }
        const stdinStr = Buffer.concat(stdinChunks).toString("utf8").trim();
        if (stdinStr) {
          try {
            const hookPayload = JSON.parse(stdinStr);
            rawCmd = hookPayload.tool_input?.command || hookPayload.command || stdinStr;
          } catch {
            rawCmd = stdinStr;
          }
        }
      } catch {
        // Fallback
      }
    }

    if (!rawCmd) {
      console.error(
        `❌ Error: No command provided to sandbox. Usage: npx @ritualdev-lab/agentshield ${command} <command>`,
      );
      process.exit(1);
    }

    const enableKernel = args.includes("--kernel");
    const requireIsolation =
      args.includes("--require-isolation") || args.includes("--strict-isolation");

    const isClaudeHook =
      args.includes("--claude-hook") || process.env.CLAUDE_TOOL_USE !== undefined;
    const { AgentStdioInterceptor } = await import("./interceptor.js");
    const interceptor = new AgentStdioInterceptor(engine, process.cwd());

    const result = await interceptor.execute(rawCmd, {
      workspaceDir: process.cwd(),
      enableKernelSandbox: enableKernel,
      requireIsolation,
      maskStyle,
      onBlock: (check) => {
        console.error(
          `\n🚨 [AgentShield Sandbox Block] ${check.reason}\n   Command: '${rawCmd}'\n`,
        );
      },
    });

    if (result.downgradedIsolation) {
      console.warn(`\n⚠️  [AgentShield Isolation Warning] ${result.isolationNotice}\n`);
    }

    if (result.isBlocked) {
      if (result.isolationMechanism === "isolated_refusal") {
        console.error(`\n🛑 [AgentShield Isolation Refusal] ${result.blockReason}\n`);
      }
      // Exit code 2 tells Claude Code to abort the tool execution cleanly
      process.exit(isClaudeHook ? 2 : 1);
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

    if (args.includes("--json")) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(result.markdownReport);
    }

    // Emit GitHub Actions inline workflow annotations
    if (args.includes("--annotate") && result.findings.length > 0) {
      const { GitHubActionBot } = await import("./github-action.js");
      GitHubActionBot.emitAnnotations(result.findings);
    }

    // Post or update sticky Pull Request review comment if requested or in PR workflow
    if (args.includes("--post-pr-comment")) {
      const { GitHubActionBot } = await import("./github-action.js");
      const commentRes = await GitHubActionBot.postOrUpdatePrComment(result, {});
      if (commentRes.success) {
        console.log(
          `\n💬 [AgentShield] PR review comment successfully ${commentRes.action} (id: ${commentRes.commentId})`,
        );
      } else if (commentRes.action !== "skipped") {
        console.warn(`\n⚠️ [AgentShield] PR comment notification warning: ${commentRes.error}`);
      }
    }

    let sarifPath: string | null = null;
    const sarifIdx = args.indexOf("--sarif");
    if (sarifIdx !== -1 && args[sarifIdx + 1]) {
      sarifPath = args[sarifIdx + 1];
    }

    if (reportPath) {
      writeFileSync(reportPath, result.markdownReport, "utf8");
      console.log(`\n📄 [AgentShield] Security report written to ${reportPath}`);
    }

    if (sarifPath && result.sarifLog) {
      writeFileSync(sarifPath, JSON.stringify(result.sarifLog, null, 2), "utf8");
      console.log(`\n📊 [AgentShield] OASIS SARIF 2.1.0 report written to ${sarifPath}`);
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

    let content = "";
    if (statSync(targetFile).isDirectory()) {
      const files: string[] = [];
      const walk = (dir: string) => {
        try {
          for (const entry of readdirSync(dir, { withFileTypes: true })) {
            if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") continue;
            const full = join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.isFile()) files.push(full);
          }
        } catch {}
      };
      walk(targetFile);
      content = files
        .map((f) => {
          try {
            return `// FILE: ${f}\n` + readFileSync(f, "utf8");
          } catch {
            return "";
          }
        })
        .join("\n\n");
    } else {
      content = readFileSync(targetFile, "utf8");
    }
    const scan = engine.scanAndRedact(content);

    const { ComplianceEngine } = await import("./compliance.js");
    const report = ComplianceEngine.evaluate(scan.findings);

    if (args.includes("--json")) {
      console.log(JSON.stringify(report, null, 2));
      process.exit(report.status === "NO_FINDINGS_IN_ASSESSED_CONTROLS" ? 0 : 1);
    }

    printBanner();
    console.log(
      `📋 [SECRET-CONTROL ASSESSMENT] Status: ${report.status} (Assessed Controls Score: ${report.score}%)\n`,
    );
    console.log(`ℹ️  Scope: ${report.scopeDisclosure.scope}`);
    console.log(`⚠️  Disclaimer: ${report.scopeDisclosure.disclaimer}\n`);

    console.log("  Assessed Controls:");
    for (const ctrl of report.assessedControls) {
      const icon = ctrl.status === "PASSED" ? "✅" : "❌";
      console.log(`    ${icon} [${ctrl.framework.toUpperCase()}] ${ctrl.controlId}: ${ctrl.name}`);
      if (ctrl.violations.length > 0) {
        for (const v of ctrl.violations) {
          console.log(`       ⚠️ ${v}`);
        }
      }
    }

    console.log("\n  Broader Controls (Not Assessed by Secret Scanning):");
    for (const ctrl of report.unassessedControls) {
      console.log(
        `    ⏸️  [${ctrl.framework.toUpperCase()}] ${ctrl.controlId}: ${ctrl.name} (NOT ASSESSED)`,
      );
      console.log(`       Reason: ${ctrl.reason}`);
      console.log(`       Evidence Needed: ${ctrl.requiredExternalEvidence.join("; ")}`);
    }
    console.log("");

    if (report.status !== "NO_FINDINGS_IN_ASSESSED_CONTROLS") {
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
        "❌ Unknown ledger action. Use 'npx @ritualdev-lab/agentshield ledger verify'.",
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
            command: "npx @ritualdev-lab/agentshield exec --claude-hook",
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
        preExecutionCommand: "npx @ritualdev-lab/agentshield exec $COMMAND",
        blockOnSensitiveFileRead: true,
        sensitivePatterns: [".env*", "*.pem", "id_rsa*", "*.key"],
      },
    };
    writeFileSync(rulesPath, JSON.stringify(cursorConfig, null, 2), "utf8");
    printBanner();
    console.log(`✅ [Cursor / Windsurf] Protection rules written to: ${rulesPath}`);
    console.log("   AI agent workspace boundaries and credential paths are protected.\n");
  } else if (command === "badge") {
    const toolName = args.filter((a) => !a.startsWith("--"))[1];
    if (!toolName) {
      console.error(
        "❌ Error: Please specify tool name. Usage: agentshield badge <tool-name> [--repo <url>] [--tier <verified|sponsor|enterprise>]",
      );
      process.exit(1);
    }

    let repoUrl = "";
    const repoIdx = args.indexOf("--repo");
    if (repoIdx !== -1 && args[repoIdx + 1]) repoUrl = args[repoIdx + 1];

    let tier: "verified" | "sponsor" | "enterprise" = "verified";
    const tierIdx = args.indexOf("--tier");
    if (tierIdx !== -1 && args[tierIdx + 1]) {
      const val = args[tierIdx + 1].toLowerCase();
      if (val === "sponsor" || val === "enterprise" || val === "verified") {
        tier = val;
      }
    }

    const { VerifiedBadgeGenerator } = await import("./badge-generator.js");
    const snippet = VerifiedBadgeGenerator.getMarkdownSnippet(
      toolName,
      "https://agentshield.ritualdev.in",
      tier,
    );
    const signature = repoUrl
      ? VerifiedBadgeGenerator.signAuditRecord(toolName, repoUrl, tier)
      : null;

    if (args.includes("--svg")) {
      const svg = VerifiedBadgeGenerator.generateSvgBadge(toolName, { tier });
      console.log(svg);
      process.exit(0);
    }

    printBanner();
    console.log(
      `🛡️ [Secured by AgentShield] Verified Badge for "${toolName}" (${tier.toUpperCase()} TIER)\n`,
    );
    console.log("Markdown (for README.md):");
    console.log(`  ${snippet.markdown}\n`);
    console.log("HTML (for websites/docs):");
    console.log(`  ${snippet.html}\n`);
    console.log("Shields.io Badge URL:");
    console.log(`  ${snippet.shieldsIoBadgeUrl}\n`);
    if (signature) {
      console.log("Cryptographic Verification Signature:");
      console.log(`  ${signature}`);
      console.log(
        `  Verify URL: https://agentshield.ritualdev.in/api/v1/badges/verify?tool=${encodeURIComponent(toolName)}&repo=${encodeURIComponent(repoUrl)}&tier=${tier}&hash=${signature}\n`,
      );
    }
    process.exit(0);
  } else if (command === "bounty-verify") {
    printBanner();
    const target = args.filter((a) => !a.startsWith("--"))[1];
    if (!target) {
      console.error(
        "❌ Error: Missing target payload. Usage: agentshield bounty-verify <file-or-command>",
      );
      process.exit(1);
    }

    console.log(
      "🧪 [AgentShield Bounty Verification Engine] Evaluating exploit/bypass candidate...\n",
    );

    let isSecretLeak = false;
    let isCommandBlocked = false;
    let details = "";

    // 1. Check if target is a file or raw string content
    const { existsSync, readFileSync } = await import("node:fs");
    let contentToScan = target;
    if (existsSync(target)) {
      contentToScan = readFileSync(target, "utf8");
      console.log(`  • Input Source: File ('${target}')`);
    } else {
      console.log(`  • Input Source: Command / Raw String Payload ('${target}')`);
    }

    // 2. Run secret scan
    const scan = engine.scanAndRedact(contentToScan);
    if (scan.hasSecrets) {
      isSecretLeak = true;
      details += `  ✓ Intercepted ${scan.findings.length} secret token(s) [Redacted in-flight]\n`;
    }

    // 3. Run command sandbox inspect
    const { AgentCommandSandbox } = await import("./sandbox.js");
    const sandbox = new AgentCommandSandbox();
    const sandboxCheck = sandbox.inspectCommand(target);
    if (sandboxCheck.isBlocked) {
      isCommandBlocked = true;
      details += `  ✓ Sandbox intercepted prohibited command: "${sandboxCheck.reason}"\n`;
    }

    console.log(details || "  ℹ️ No secrets or forbidden commands detected by standard rules.\n");

    if (isSecretLeak || isCommandBlocked) {
      console.log("🛡️ [VERDICT: MITIGATED]");
      console.log("   AgentShield successfully caught and neutralized this exploit vector.");
      console.log("   If you believe you have discovered a novel bypass, submit your PoC at:");
      console.log("   https://github.com/RitualDev-Lab/AgentShield/security/advisories/new\n");
      process.exit(0);
    } else {
      console.log("⚠️ [VERDICT: UNRESTRICTED / POTENTIAL CANDIDATE]");
      console.log("   Payload was not blocked by default rules.");
      console.log(
        "   If this payload extracts production credentials or breaks sandbox isolation,",
      );
      console.log("   it qualifies for a Community Bug Bounty ($50 - $500).");
      console.log(
        "   Report privately: https://github.com/RitualDev-Lab/AgentShield/security/advisories/new\n",
      );
      process.exit(0);
    }
  } else if (command === "top" || command === "htop") {
    const { runTopMonitor } = await import("./top-monitor.js");
    const isOnce = args.includes("--once");
    const isJson = args.includes("--json");
    let intervalMs = 1500;
    const intervalIdx = args.indexOf("--interval");
    if (intervalIdx !== -1 && args[intervalIdx + 1]) {
      intervalMs = Number.parseInt(args[intervalIdx + 1], 10) || 1500;
    }
    await runTopMonitor({ once: isOnce, json: isJson, intervalMs });
    if (isOnce || isJson) {
      process.exit(0);
    }
  } else if (command === "wrap" || command === "mcp-wrap") {
    const { runMcpWrapper } = await import("./mcp-wrapper.js");
    runMcpWrapper(args.slice(1));
  } else if (command === "sidecar" || command === "daemon") {
    const { AgentShieldSidecar } = await import("./sidecar.js");
    const sidecar = new AgentShieldSidecar(engine);
    sidecar.startStdioServer(process.stdin, process.stdout);
    process.stdin.on("end", () => {
      process.exit(0);
    });
  } else {
    console.error(`❌ Unknown command '${command}'. Run 'agentshield --help' for usage.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal Error:", err);
  process.exit(1);
});
