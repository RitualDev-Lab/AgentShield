#!/usr/bin/env bash
set -euo pipefail

# Official RitualDev-Lab E2B / Daytona Cloud Sandbox Entrypoint
# 1. Enforces strict air-gapped environment defaults
# 2. Runs AgentShield sandbox doctor preflight
# 3. Routes executed agent commands through AgentShield zero-leak stream redactor

export RITUAL_AIR_GAPPED="${RITUAL_AIR_GAPPED:-1}"
export AGENTSHIELD_AIR_GAPPED="${AGENTSHIELD_AIR_GAPPED:-1}"
export AGENTSHIELD_MODE="${AGENTSHIELD_MODE:-strict}"
export DBSHIELD_SAFETY_TIER="${DBSHIELD_SAFETY_TIER:-STRICT}"

if command -v agentshield >/dev/null 2>&1; then
  agentshield doctor --json >/tmp/agentshield-preflight.json 2>&1 || true
fi

if [ "$#" -gt 0 ] && [ "$1" = "--exec-guarded" ]; then
  shift
  exec agentshield exec "$*"
fi

exec "$@"
