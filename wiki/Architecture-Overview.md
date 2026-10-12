# Architecture Overview ⚙️

AgentShield enforces a **multi-stage defense-in-depth model** operating locally on the developer machine or CI runner.

```mermaid
flowchart TD
    A[Agent Input / Shell Action] --> B[AST Command Normalizer]
    B -->|Check Prohibited Targets| C{Threat Detected?}
    C -->|Yes (.env, printenv, curl)| D[Hard Process Termination Exit 1]
    C -->|No| E[Regex Automata + Shannon Entropy Scanner]
    E --> F[SHA-256 Surrogate Redactor]
    F --> G[Execution via Local Sandboxed Runtime]
    G --> H[Chained HMAC Audit Ledger]
```

## 1. High-Performance Automata
- **Aho-Corasick Multipattern Matching**: Evaluates 100+ cloud secret patterns simultaneously in sub-millisecond latency.
- **Shannon Entropy Engine ($H \ge 4.5\text{ bits/char}$)**: Catches high-entropy secret tokens even if their prefix or formatting is previously unrecognized.

## 2. Zero-Collision Surrogate Replacement
- Secrets are mapped deterministically:
  `[AGENT_SHIELD:OPENAI_API_KEY:4a7f9b8c1d2e3f40]`
- Rehydration is local, exact, and guarantees that credentials are never transmitted into external LLM prompts.
