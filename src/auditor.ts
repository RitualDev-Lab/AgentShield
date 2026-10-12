import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { AgentConfigAuditIssue, AgentConfigAuditReport } from "./taxonomy.js";

/**
 * Static Agent Environment & Configuration Auditor
 * Scans .claude/, .cursor/, .windsurf/, claude_desktop_config.json, and mcpServers
 * for excessive permissions, blanket filesystem access, and credential leakage.
 */
export class AgentConfigAuditor {
  private rootDir: string;

  constructor(rootDir: string = process.cwd()) {
    this.rootDir = rootDir;
  }

  public auditWorkspace(): AgentConfigAuditReport {
    const issues: AgentConfigAuditIssue[] = [];
    let filesAudited = 0;

    // 1. Audit MCP configurations (claude_desktop_config.json, mcpServers)
    const mcpFiles = [
      join(this.rootDir, "claude_desktop_config.json"),
      join(this.rootDir, ".mcp.json"),
      join(this.rootDir, "mcp.json"),
      join(this.rootDir, ".cursor", "mcp.json"),
      join(this.rootDir, ".claude", "mcp.json"),
    ];

    for (const file of mcpFiles) {
      if (existsSync(file)) {
        filesAudited++;
        this.auditMcpConfigFile(file, issues);
      }
    }

    // 2. Audit .claude / .cursor / .windsurf configurations
    const agentDirs = [
      join(this.rootDir, ".claude"),
      join(this.rootDir, ".cursor"),
      join(this.rootDir, ".windsurf"),
    ];

    for (const dir of agentDirs) {
      if (existsSync(dir) && statSync(dir).isDirectory()) {
        const files = this.collectJsonYamlFiles(dir);
        for (const file of files) {
          filesAudited++;
          this.auditAgentSettingsFile(file, issues);
        }
      }
    }

    // 3. Audit root environment files (.env, .env.local) permissions
    const envFiles = [join(this.rootDir, ".env"), join(this.rootDir, ".env.local")];
    for (const envFile of envFiles) {
      if (existsSync(envFile)) {
        filesAudited++;
        issues.push({
          id: "AS-CONFIG-001",
          file: envFile,
          severity: "high",
          category: "credential_exposure",
          title: "Unprotected Root Environment Secret File",
          description:
            "Cleartext .env file present in workspace root. Accessible to autonomous agents running file search tools.",
          recommendation:
            "Move sensitive variables to an encrypted vault or use AgentShield virtual surrogate tokens.",
          owaspLlm: "LLM06",
          mitreAtlas: "AML.T0024",
        });
      }
    }

    return {
      timestamp: new Date().toISOString(),
      totalFilesAudited: filesAudited,
      issues,
      passed: issues.filter((i) => i.severity === "critical").length === 0,
    };
  }

  private auditMcpConfigFile(filePath: string, issues: AgentConfigAuditIssue[]): void {
    try {
      const raw = readFileSync(filePath, "utf8");
      const config = JSON.parse(raw);
      const servers = config.mcpServers || config.servers || {};

      interface McpServerEntry {
        args?: string[];
        env?: Record<string, string>;
      }

      for (const [serverName, serverCfg] of Object.entries<McpServerEntry>(servers)) {
        const args: string[] = serverCfg.args || [];
        const env: Record<string, string> = serverCfg.env || {};

        // Check for blanket filesystem permissions
        if (args.some((arg) => arg === "/" || arg === "~" || arg === "$HOME" || arg === "C:\\")) {
          issues.push({
            id: "AS-MCP-001",
            file: filePath,
            severity: "critical",
            category: "excessive_permissions",
            title: `Blanket Root Filesystem Access in MCP Server '${serverName}'`,
            description: `Server '${serverName}' is granted root/home directory access. An agent can read ~/.ssh, ~/.aws, or system stores.`,
            recommendation:
              "Constrain MCP server root directory arguments strictly to active project workspace.",
            owaspLlm: "LLM06",
            mitreAtlas: "AML.T0054",
          });
        }

        // Check for cleartext credentials in MCP server environment configs
        for (const [envKey, envVal] of Object.entries(env)) {
          if (
            typeof envVal === "string" &&
            (envVal.startsWith("sk-") || envVal.startsWith("AKIA") || envVal.startsWith("ghp_"))
          ) {
            issues.push({
              id: "AS-MCP-002",
              file: filePath,
              severity: "critical",
              category: "credential_exposure",
              title: `Hardcoded API Secret in MCP Server '${serverName}' Env: '${envKey}'`,
              description: `Plaintext credential hardcoded inside MCP config file under '${envKey}'.`,
              recommendation:
                "Reference system environment variables instead of hardcoding credentials.",
              owaspLlm: "LLM06",
              mitreAtlas: "AML.T0024",
            });
          }
        }
      }
    } catch {
      // Ignore unparseable or binary files
    }
  }

  private auditAgentSettingsFile(filePath: string, issues: AgentConfigAuditIssue[]): void {
    try {
      const content = readFileSync(filePath, "utf8");
      if (
        content.includes("allowDangerousCommands: true") ||
        content.includes('"allowDangerousCommands": true')
      ) {
        issues.push({
          id: "AS-AGENT-001",
          file: filePath,
          severity: "high",
          category: "excessive_permissions",
          title: "Dangerous Unrestricted Commands Allowed in Agent Settings",
          description:
            "Agent config allows arbitrary dangerous command execution without human-in-the-loop confirmation.",
          recommendation:
            "Disable allowDangerousCommands and enforce AgentShield shell sandbox wrapper.",
          owaspLlm: "LLM02",
          mitreAtlas: "AML.T0054",
        });
      }
    } catch {
      // Skip
    }
  }

  private collectJsonYamlFiles(dir: string): string[] {
    const results: string[] = [];
    try {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        const full = join(dir, entry.name);
        if (
          entry.isFile() &&
          (entry.name.endsWith(".json") ||
            entry.name.endsWith(".yaml") ||
            entry.name.endsWith(".yml"))
        ) {
          results.push(full);
        }
      }
    } catch {
      // Skip inaccessible dirs
    }
    return results;
  }
}
