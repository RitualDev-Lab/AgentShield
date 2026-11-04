import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { AgentCommandSandbox } from "../src/sandbox.js";
import { sanitizeProcessEnvironment } from "../src/interceptor.js";
import { UNIGNORABLE_FILES_PATTERN } from "../src/ci.js";
import { validateReDoSSafety, parseCustomPatterns } from "../src/config.js";

describe("GHSA Vulnerability Patches Suite", () => {
  describe("GHSA-92f2-4677-rmvh: Environment Secrets & /proc/self/environ Defense", () => {
    const sandbox = new AgentCommandSandbox();

    it("should intercept reading /proc/self/environ and /proc/$$/environ", () => {
      const commands = [
        "cat /proc/self/environ",
        "strings /proc/self/environ",
        "cat /proc/$$/environ",
        "more /proc/thread-self/environ",
        "grep SECRET /proc/1/environ",
        "dd if=/proc/self/environ of=out.txt",
      ];

      for (const cmd of commands) {
        const result = sandbox.inspectCommand(cmd);
        assert.equal(result.isBlocked, true, `Command should be blocked: ${cmd}`);
        assert.equal(result.category, "env_dump");
      }
    });

    it("should intercept echo and printf reflecting sensitive environment variables", () => {
      const commands = [
        "echo $AWS_SECRET_ACCESS_KEY",
        "echo ${GITHUB_TOKEN}",
        "printf '%s\\n' \"$ANTHROPIC_API_KEY\"",
        "printf %s $OPENAI_API_KEY",
        "echo $DATABASE_URL",
        "echo $SLACK_BOT_TOKEN",
        "write-host $Env:PRIVATE_KEY",
      ];

      for (const cmd of commands) {
        const result = sandbox.inspectCommand(cmd);
        assert.equal(result.isBlocked, true, `Command should be blocked: ${cmd}`);
        assert.equal(result.category, "secret_echo");
      }
    });

    it("should allow safe echo and printf commands with normal variables", () => {
      const safeCommands = [
        "echo 'Hello World'",
        "echo $USER",
        "echo $HOME",
        "echo $PATH",
        "printf '%s\\n' 'Build succeeded'",
        "echo $NODE_ENV",
      ];

      for (const cmd of safeCommands) {
        const result = sandbox.inspectCommand(cmd);
        assert.equal(result.isBlocked, false, `Safe command should be allowed: ${cmd}`);
      }
    });

    it("should sanitize process environment by redacting sensitive keys for child processes", () => {
      const testEnv = {
        PATH: "/usr/bin:/bin",
        HOME: "/home/user",
        USER: "developer",
        AWS_SECRET_ACCESS_KEY: "super_secret_aws_key_123",
        GITHUB_TOKEN: "ghp_live_secret_token_456",
        ANTHROPIC_API_KEY: "sk-ant-live-secret-789",
        MY_APP_NAME: "test-app",
      };

      const sanitized = sanitizeProcessEnvironment(testEnv);

      // Safe variables preserved
      assert.equal(sanitized.PATH, "/usr/bin:/bin");
      assert.equal(sanitized.HOME, "/home/user");
      assert.equal(sanitized.USER, "developer");
      assert.equal(sanitized.MY_APP_NAME, "test-app");

      // Sensitive credentials redacted
      assert.equal(sanitized.AWS_SECRET_ACCESS_KEY, "[REDACTED_BY_AGENTSHIELD_ENV_GATE]");
      assert.equal(sanitized.GITHUB_TOKEN, "[REDACTED_BY_AGENTSHIELD_ENV_GATE]");
      assert.equal(sanitized.ANTHROPIC_API_KEY, "[REDACTED_BY_AGENTSHIELD_ENV_GATE]");
    });
  });

  describe("GHSA-p3v4-5qw2-92rg: CI Secret Gate Self-Neutering Defense", () => {
    it("should classify .env, keys, and credentials as unignorable files", () => {
      const criticalFiles = [
        ".env",
        ".env.local",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        ".aws/credentials",
        ".aws/config",
        "service-account.json",
        "cert.pem",
        "server.key",
      ];

      for (const file of criticalFiles) {
        assert.equal(
          UNIGNORABLE_FILES_PATTERN.test(file),
          true,
          `File should be unignorable: ${file}`,
        );
      }
    });

    it("should allow legitimate example templates to be ignored", () => {
      assert.equal(
        UNIGNORABLE_FILES_PATTERN.test(".env.example"),
        false,
        ".env.example should be allowable",
      );
    });
  });

  describe("GHSA-g5mq-fjr3-39qp: ReDoS Catastrophic Backtracking Guard", () => {
    it("should detect and reject nested quantifier patterns with exponential backtracking", () => {
      const vulnerablePatterns = [
        "(a+)+$",
        "(a*)*",
        "(?:[a-z]+)+",
        "(a|a+)+$",
        "(a+|b)+$",
        "(a{1,}){2,}",
      ];

      for (const pattern of vulnerablePatterns) {
        const check = validateReDoSSafety(pattern);
        assert.equal(check.safe, false, `Pattern should be rejected as ReDoS: ${pattern}`);
        assert.match(check.reason || "", /Catastrophic backtracking risk/);
      }
    });

    it("should accept safe, non-backtracking regular expressions", () => {
      const safePatterns = [
        "AKIA[0-9A-Z]{16}",
        "ghp_[a-zA-Z0-9]{36}",
        "(?:bearer\\s+)?[a-zA-Z0-9_\\-\\.]{20,}",
        "sk-[a-zA-Z0-9]{48}",
        "^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
      ];

      for (const pattern of safePatterns) {
        const check = validateReDoSSafety(pattern);
        assert.equal(check.safe, true, `Pattern should be safe: ${pattern}`);
      }
    });

    it("parseCustomPatterns should discard vulnerable ReDoS patterns without crashing", () => {
      const config = {
        customPatterns: [
          {
            id: "safe-rule",
            name: "Safe Rule",
            regex: "SAFE_TOKEN_[0-9]{10}",
            severity: "high" as const,
          },
          {
            id: "malicious-redos",
            name: "ReDoS Attack Rule",
            regex: "(a+)+$",
            severity: "high" as const,
          },
        ],
      };

      const parsed = parseCustomPatterns(config);
      assert.equal(parsed.length, 1);
      assert.equal(parsed[0].id, "safe-rule");
    });
  });
});
