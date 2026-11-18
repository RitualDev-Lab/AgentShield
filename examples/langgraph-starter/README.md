# LangGraph + AgentShield Starter Example

Consolidated canonical example (migrated from `RitualDev-Lab/langgraph-agentshield-template`).

Demonstrates:
- `@shield.protect` tool-call zero-leak secret redaction
- `AgentShieldCallbackHandler` for LangGraph / LangChain state graphs
- Subprocess & `/proc/self/environ` syscall guardrails

## Quick Start

```bash
pip install -r requirements.txt
python agent.py
```

Or boot the full 3-layer defense stack (AgentShield + DBShield + SkillPrism):

```bash
npx @ritualdev-lab/agentshield up --config ../ritual.policy.yaml --dry-run
```
