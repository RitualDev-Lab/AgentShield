import type { SecretPattern } from "./types.js";

export const BUILTIN_PATTERNS: SecretPattern[] = [
  // 1. AI & LLM Providers
  {
    id: "anthropic-api-key",
    name: "Anthropic Claude Key",
    category: "ai",
    severity: "critical",
    regex: /\b(sk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{40,120})\b/g,
    description: "Anthropic Claude API Key",
  },
  {
    id: "openai-api-key",
    name: "OpenAI Secret Key",
    category: "ai",
    severity: "critical",
    regex: /\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,120})\b/g,
    description: "OpenAI API Secret Key or Service Account Key",
  },
  {
    id: "google-gemini-key",
    name: "Google Gemini / AI Studio Key",
    category: "ai",
    severity: "critical",
    regex: /\b(AIzaSy[A-Za-z0-9_-]{33})\b/g,
    description: "Google Cloud / Gemini AI Studio API Key",
  },
  {
    id: "huggingface-token",
    name: "Hugging Face User Access Token",
    category: "ai",
    severity: "critical",
    regex: /\b(hf_[A-Za-z0-9]{34,60})\b/g,
    description: "Hugging Face API / Inference Token",
  },

  // 2. Cloud Providers
  {
    id: "aws-access-key-id",
    name: "AWS Access Key ID",
    category: "cloud",
    severity: "critical",
    regex: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
    description: "Amazon Web Services Access Key ID",
  },
  {
    id: "aws-secret-access-key",
    name: "AWS Secret Access Key",
    category: "cloud",
    severity: "critical",
    regex:
      /(?:aws_secret_access_key|aws_secret|secret_key|secret_access_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    description: "Amazon Web Services Secret Key",
  },

  // 3. SaaS, Payments & Auth
  {
    id: "stripe-secret-key",
    name: "Stripe Secret / Restricted Key",
    category: "saas",
    severity: "critical",
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,100})\b/g,
    description: "Stripe Payment Secret or Restricted API Key",
  },
  {
    id: "github-pat",
    name: "GitHub Personal Access Token",
    category: "vcs",
    severity: "critical",
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b/g,
    description: "GitHub Fine-Grained or Classic Personal Access Token",
  },
  {
    id: "slack-webhook",
    name: "Slack Incoming Webhook",
    category: "saas",
    severity: "high",
    regex:
      /https:\/\/hooks\.slack\.com\/services\/(T[A-Z0-9]{8,12}\/B[A-Z0-9]{8,12}\/[A-Za-z0-9]{24})/g,
    description: "Slack Incoming Webhook URL",
  },
  {
    id: "jwt-token",
    name: "JSON Web Token (JWT)",
    category: "generic",
    severity: "medium",
    regex: /\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    description: "Cryptographically signed JWT bearer token",
  },

  // 4. Cryptographic Private Keys
  {
    id: "private-key-block",
    name: "Private Cryptographic Key",
    category: "crypto",
    severity: "critical",
    regex:
      /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY-----[\s\S]+?-----END (?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY-----/g,
    description: "PEM-encoded RSA, OpenSSH, or private TLS key block",
  },

  // 5. Generic Sensitive Assignments (ENV files)
  {
    id: "generic-secret-assignment",
    name: "Generic Secret Assignment",
    category: "generic",
    severity: "high",
    regex:
      /(?:API_KEY|SECRET_KEY|AUTH_TOKEN|ACCESS_TOKEN|PRIVATE_KEY|DB_PASSWORD|DATABASE_PASSWORD)\s*=\s*["']?([A-Za-z0-9_!@#$%^&*()\-+=]{12,120})["']?/gi,
    description: "Standard environment variable secret assignment",
  },
];
