export interface CommandInspectionResult {
  isBlocked: boolean;
  reason?: string;
  sanitizedCommand?: string;
  category?: "env_dump" | "secret_echo" | "credential_exfiltration" | "dangerous_mutation";
}

/**
 * File basenames or target extensions that contain high-risk secrets.
 */
const SENSITIVE_TARGET_FILES =
  /(?:^|[\s'"\/\\=])(?:\.env(?:\.[a-zA-Z0-9_\-]+)?|id_rsa|id_ed25519|id_ecdsa|\.aws[\/\\](?:credentials|config)|\.npmrc|\.netrc|\.gnupg[\/\\][a-zA-Z0-9_\-]+)(?:$|['"\s|;&><])/i;

/**
 * Direct file-reading utilities or shell builtins.
 */
const FILE_READER_BINARIES =
  /\b(cat|more|less|tail|head|type|Get-Content|gc|grep|egrep|awk|sed|dd|xargs|nl|fold|paste|tac|strings)\b/i;

/**
 * Commands that dump raw environment secrets or read private credential stores directly.
 */
const DANGEROUS_COMMAND_PATTERNS = [
  // 1. Reading .env or credential stores directly via reader commands
  {
    test: (cmd: string) => FILE_READER_BINARIES.test(cmd) && SENSITIVE_TARGET_FILES.test(cmd),
    reason:
      "Blocked attempt to read raw .env or private credential file directly into agent terminal context.",
    category: "env_dump" as const,
  },
  // 2. Reading .env via shell redirection: `< .env` or `while read ... < .env`
  {
    test: (cmd: string) =>
      /<\s*(?:[^\s|;&]*[\/\\])?(?:\.env|\.aws[\/\\]credentials|id_rsa)/i.test(cmd),
    reason: "Blocked attempt to read sensitive file via input redirection into agent context.",
    category: "env_dump" as const,
  },
  // 3. Inline scripts reading sensitive files: python -c "open('.env')", node -e "fs.readFileSync('.env')"
  {
    test: (cmd: string) =>
      /\b(python|python3|node|perl|ruby|php|bash|sh|zsh)\b/i.test(cmd) &&
      SENSITIVE_TARGET_FILES.test(cmd),
    reason: "Blocked inline script targeting sensitive credential files.",
    category: "env_dump" as const,
  },
  // 4. Dumping all environment variables (standalone or piped: env | sort, printenv, export)
  {
    test: (cmd: string) =>
      /(?:^|[|;&]\s*)(?:printenv|env|export|set|Get-ChildItem\s+Env:)\b(?!\s*[-_a-zA-Z0-9]+=)/i.test(
        cmd,
      ),
    reason: "Blocked attempt to dump full environment variables into agent context.",
    category: "env_dump" as const,
  },
  // 5. Exfiltrating secrets via curl/wget/POST/webhook or external network call with env variables
  {
    test: (cmd: string) =>
      /\b(curl|wget|invoke-webrequest|irm|iwr|nc|ncat|netcat|socat)\b/i.test(cmd) &&
      /(?:\$[A-Z0-9_]{3,}|\.env|id_rsa|\.aws)/i.test(cmd),
    reason: "Blocked potential secret exfiltration via external network transfer.",
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
      if (pattern.test(trimmed)) {
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
