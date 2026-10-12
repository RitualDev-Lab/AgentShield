# Contributing to AgentShield

Thank you for your interest in contributing to **AgentShield**! We welcome contributions from developers, security engineers, and AI practitioners.

---

## 🛠️ Development Setup

AgentShield is built with Node.js 20+, TypeScript, ESM, and pnpm.

```bash
# 1. Clone your fork
git clone https://github.com/<your-username>/AgentShield.git
cd AgentShield

# 2. Install dependencies
pnpm install

# 3. Build project
pnpm run build

# 4. Run full test suite
pnpm test
```

---

## 📐 Guidelines

### 1. Code Standards & Tooling
- We use [Biome](https://biomejs.dev/) for ultra-fast linting and code formatting:
  ```bash
  pnpm run lint
  pnpm run format
  ```
- All code must pass Biome checks with 0 errors and 0 warnings before opening a PR.

### 2. Never Hardcode Real or Synthetic Secrets in Tests
> [!IMPORTANT]
> GitHub Secret Scanning Push Protection will immediately block git pushes if you include realistic token formats (such as literal `sk-proj-...` or `AKIA...`).
> **Always construct test tokens dynamically** using arrays: `["sk-proj-", "123..."].join("")` or synthetic non-production strings.

### 3. Adding New Secret Detection Patterns
To add a new credential pattern:
1. Edit [`src/patterns.ts`](file:///src/patterns.ts).
2. Add a unique `id`, human-readable `name`, `category`, and `severity`.
3. Provide a test case in [`tests/engine.test.ts`](file:///tests/engine.test.ts).

### 4. Pull Request Process
1. Create a feature branch: `git checkout -b feat/my-new-feature`.
2. Ensure all existing tests and new unit tests pass (`pnpm test`).
3. Commit with semantic commit messages:
   - `feat(...)`: New feature or pattern
   - `fix(...)`: Bug fix or false positive tuning
   - `docs(...)`: Documentation updates
   - `test(...)`: Test additions
4. Push and open a Pull Request against `RitualDev-Lab/AgentShield:main`.
