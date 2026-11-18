# Claude Code + AgentShield Starter Example

Consolidated canonical example (migrated from `RitualDev-Lab/claude-code-agentshield-starter`).

Pre-configured with:
- `.claude/config.json` `PreToolUse` hook routing commands through `@ritualdev-lab/agentshield>=0.2.2`
- `.agentshield.json` strict zero-leak policy
- `demo-tool.js` demonstrating live runtime redaction of leaked tokens

## Quick Start

```bash
node demo-tool.js "SELECT * FROM users LIMIT 1" | npx @ritualdev-lab/agentshield stream
```

Or boot the full 3-layer defense stack (AgentShield + DBShield + SkillPrism):

```bash
npx @ritualdev-lab/agentshield up --config ../ritual.policy.yaml --dry-run
```
