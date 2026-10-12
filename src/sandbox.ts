export interface CommandInspectionResult {
  isBlocked: boolean;
  reason?: string;
  sanitizedCommand?: string;
  category?: "env_dump" | "secret_echo" | "credential_exfiltration" | "dangerous_mutation";
}

/**
 * Commands that dump raw environment secrets or read private credential stores directly.
 */
const DANGEROUS_COMMAND_PATTERNS = [
  // 1. Reading .env or credential stores directly
  {
    regex:
      /\b(cat|more|less|tail|head|type|Get-Content|gc)\s+(?:.*?\/)?(?:\.env|\.env\.[a-zA-Z0-9_\-]+|id_rsa|id_ed25519|\.aws\/credentials|\.aws\/config|\.npmrc|\.netrc)\b/i,
    reason:
      "Blocked attempt to read raw .env or private credential file directly into agent terminal context.",
    category: "env_dump" as const,
  },
  // 2. Dumping all environment variables
  {
    regex: /^\s*(printenv|env|export|set|Get-ChildItem\s+Env:)\s*$/i,
    reason: "Blocked attempt to dump full environment variables into agent context.",
    category: "env_dump" as const,
  },
  // 3. Exfiltrating secrets via curl/wget POST or raw piping
  {
    regex:
      /\b(curl|wget|invoke-webrequest|irm|iwr)\b.*?(?:\$API_KEY|\$SECRET|\$AWS_|\$OPENAI_|\$TOKEN|\.env)/i,
    reason: "Blocked potential secret exfiltration via external HTTP request.",
    category: "credential_exfiltration" as const,
  },
];

export class AgentCommandSandbox {
  /**
   * Inspects a command before execution by an AI coding agent.
   */
  public inspectCommand(command: string): CommandInspectionResult {
    const trimmed = command.trim();

    for (const pattern of DANGEROUS_COMMAND_PATTERNS) {
      if (pattern.regex.test(trimmed)) {
        return {
          isBlocked: true,
          reason: pattern.reason,
          category: pattern.category,
        };
      }
    }

    return {
      isBlocked: false,
    };
  }
}
