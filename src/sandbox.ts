export interface CommandInspectionResult {
  isBlocked: boolean;
  reason?: string;
  sanitizedCommand?: string;
  category?: "env_dump" | "secret_echo" | "credential_exfiltration" | "dangerous_mutation";
}

/**
 * File basenames or target patterns that contain high-risk secrets.
 */
const SENSITIVE_TARGET_FILES =
  /(?:^|[\s'"\/\\=])(?:\.env(?:\.[a-zA-Z0-9_\-]+)?|id_rsa|id_ed25519|id_ecdsa|\.aws[\/\\](?:credentials|config)|\.npmrc|\.netrc|\.gnupg[\/\\][a-zA-Z0-9_\-]+)(?:$|['"\s|;&><])/i;

/**
 * Direct file-reading utilities or shell builtins.
 */
const FILE_READER_BINARIES =
  /\b(cat|more|less|tail|head|type|Get-Content|gc|grep|egrep|awk|sed|dd|xargs|nl|fold|paste|tac|strings)\b/i;

/**
 * Normalizes shell command strings by stripping common evasion wrappers
 * (such as `sh -c "..."`, `bash -c '...'`, `$'\t'` escapes, and redundant quotes).
 */
export function normalizeShellCommand(cmd: string): string[] {
  let normalized = cmd.trim();

  // 1. Resolve bash ANSI-C quoting: $'\x20' or $'\t'
  normalized = normalized.replace(/\$'([^']*)'/g, (_, content: string) => {
    return content
      .replace(/\\t/g, " ")
      .replace(/\\n/g, " ")
      .replace(/\\r/g, " ")
      .replace(/\\x([0-9a-fA-F]{2})/g, (__, hex: string) =>
        String.fromCharCode(Number.parseInt(hex, 16)),
      );
  });

  // 2. Unpack subshell wrappers: sh -c "...", bash -c '...'
  const subshellMatch = normalized.match(
    /(?:^|[|;&]\s*)(?:sh|bash|zsh)\s+-c\s+(['"])(.*?)\1(?:\s*(?:[|;&]|$))/i,
  );
  if (subshellMatch?.[2]) {
    return [normalized, subshellMatch[2]];
  }

  return [normalized];
}

/**
 * Tokenizes a shell command line respecting quotes and pipes.
 */
export function tokenizeCommand(cmd: string): string[] {
  const tokens: string[] = [];
  const regex = /[^\s"']+|"([^"]*)"|'([^']*)'/g;
  let match = regex.exec(cmd);
  while (match !== null) {
    tokens.push(match[1] ?? match[2] ?? match[0]);
    match = regex.exec(cmd);
  }
  return tokens;
}

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
    const candidates = normalizeShellCommand(command);

    for (const cmdVariant of candidates) {
      const trimmed = cmdVariant.trim();

      for (const pattern of DANGEROUS_COMMAND_PATTERNS) {
        if (pattern.test(trimmed)) {
          return {
            isBlocked: true,
            reason: pattern.reason,
            category: pattern.category,
          };
        }
      }
    }

    return {
      isBlocked: false,
    };
  }
}
