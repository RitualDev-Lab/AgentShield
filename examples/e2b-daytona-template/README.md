# AgentShield + DBShield Inside E2B / Daytona Cloud Sandboxes

Official production template for running autonomous AI coding agents inside **E2B microVMs** or **Daytona DevContainers** with zero-leak credential redaction (**AgentShield**), PostgreSQL wire-protocol SQL guardrails (**DBShield**), and air-gapped defaults (`RITUAL_AIR_GAPPED=1`).

## Files

- `e2b.Dockerfile` — Non-root (`UID 10001`) hardened container image bundling `@ritualdev-lab/agentshield>=0.2.2`, `@ritualdev-lab/dbshield>=0.2.1`, and `bubblewrap`.
- `daytona-devcontainer.json` — DevContainer / Daytona workspace manifest enforcing `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only` rootfs, and the canonical `ritualdev-lab.agentshield-defense` IDE extension.
- `entrypoint.sh` — Runs `agentshield doctor` preflight and supports `--exec-guarded <command>` wrapped command execution.

## E2B MicroVM Quickstart

```bash
cd examples/e2b-daytona-template
e2b template build --name ritual-agentshield-sandbox --dockerfile e2b.Dockerfile
```

## Daytona Workspace Quickstart

```bash
daytona create https://github.com/RitualDev-Lab/AgentShield \
  --devcontainer-path examples/e2b-daytona-template/daytona-devcontainer.json
```

## Unified 3-Layer Policy Boot

Inside the microVM or Daytona workspace, validate or boot the full stack via `ritual.policy.yaml`:

```bash
agentshield up --config ../ritual.policy.yaml --dry-run
```
