import type { SigmaRule } from "./taxonomy.js";

/**
 * Standardized Sigma-AI Rule Corpus
 * Mapped to OWASP Top 10 for LLMs & MITRE ATLAS/ATT&CK
 */
export const STANDARD_SIGMA_RULES: SigmaRule[] = [
  {
    meta: {
      id: "AS-SIGMA-001",
      title: "OpenAI Secret API Key Exposure",
      status: "stable",
      description:
        "Detects exposed OpenAI secret API keys starting with sk-proj- or legacy sk- tokens.",
      tags: {
        mitreAttack: ["T1552.001"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "sk-(?:proj-)?[A-Za-z0-9_-]{32,}",
      category: "ai",
      prefix: "sk-",
    },
  },
  {
    meta: {
      id: "AS-SIGMA-002",
      title: "Anthropic Claude API Key Exposure",
      status: "stable",
      description: "Detects exposed Anthropic Claude secret API keys starting with sk-ant-.",
      tags: {
        mitreAttack: ["T1552.001"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "sk-ant-[A-Za-z0-9_-]{32,}",
      category: "ai",
      prefix: "sk-ant-",
    },
  },
  {
    meta: {
      id: "AS-SIGMA-003",
      title: "AWS Access Key ID Exposure",
      status: "stable",
      description: "Detects exposed Amazon Web Services (AWS) 20-character Access Key IDs.",
      tags: {
        mitreAttack: ["T1552.001", "T1078.004"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
      category: "cloud",
    },
  },
  {
    meta: {
      id: "AS-SIGMA-004",
      title: "GitHub Personal Access Token Exposure",
      status: "stable",
      description: "Detects exposed classic or fine-grained GitHub Personal Access Tokens.",
      tags: {
        mitreAttack: ["T1552.001"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,}",
      category: "vcs",
    },
  },
  {
    meta: {
      id: "AS-SIGMA-005",
      title: "Google Gemini API Key Exposure",
      status: "stable",
      description: "Detects exposed Google AI Studio / Gemini API tokens.",
      tags: {
        mitreAttack: ["T1552.001"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "AIzaSy[A-Za-z0-9_-]{33}",
      category: "ai",
      prefix: "AIzaSy",
    },
  },
  {
    meta: {
      id: "AS-SIGMA-006",
      title: "Stripe Live Secret Key Exposure",
      status: "stable",
      description: "Detects live production payment tokens from Stripe.",
      tags: {
        mitreAttack: ["T1552.001"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "sk_live_[0-9a-zA-Z]{24,}",
      category: "saas",
      prefix: "sk_live_",
    },
  },
  {
    meta: {
      id: "AS-SIGMA-007",
      title: "Private Cryptographic Key Block Exposure",
      status: "stable",
      description: "Detects exposed RSA, DSA, EC, or OpenSSH private key PEM headers.",
      tags: {
        mitreAttack: ["T1552.004"],
        mitreAtlas: ["AML.T0024"],
        owaspLlm: ["LLM06"],
      },
      severity: "critical",
    },
    detection: {
      regex: "-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
      category: "crypto",
    },
  },
];
