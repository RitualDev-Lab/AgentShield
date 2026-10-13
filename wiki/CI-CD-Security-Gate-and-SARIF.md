# CI/CD Security Gate & SARIF 2.1.0 🛡️

AgentShield integrates into continuous integration pipelines to prevent hardcoded secrets and high-entropy tokens from merging into protected branches.

---

## ⚡ GitHub Actions Workflow Example

Add this workflow to your repository at `.github/workflows/agentshield-gate.yml`:

```yaml
name: AgentShield Security Gate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-audit:
    name: Audit Pull Request for Leaked Secrets
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Run AgentShield Gate
        run: npx @ritualdev_lab/agentshield ci --base origin/main --format sarif --out agentshield.sarif

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentshield.sarif
```

---

## 📊 SARIF 2.1.0 Standardization

AgentShield outputs SARIF (Static Analysis Results Interchange Format) compliant with the OASIS Standard, enabling direct native integration with GitHub Code Scanning, SonarQube, and enterprise SIEM platforms.
