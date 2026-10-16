# 🐍 AgentShield Python SDK

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Official Python SDK for **[AgentShield](https://github.com/RitualDev-Lab/AgentShield)**: Zero-leak secret defense, in-memory surrogate token rehydration, and shell command sandboxing for Python AI agents.

Works seamlessly with **LangChain**, **LangGraph**, **LlamaIndex**, **CrewAI**, **AutoGen**, and raw LLM clients (OpenAI, Anthropic, Gemini).

---

## 📦 Installation

```bash
pip install agentshield
```

AgentShield operates in two high-performance modes:
1. **Pure Python In-Process Engine**: Zero external dependencies, pure standard library.
2. **Subprocess Sidecar Engine**: Communicates with the AgentShield Node.js daemon over JSON-RPC 2.0 stdio pipes for sub-millisecond multi-engine scanning and full ecosystem parity.

---

## 🚀 Quick Start

### 1. In-Process Prompt Redaction & Rehydration

```python
from agentshield import AgentShieldEngine

shield = AgentShieldEngine()

# Scan and redact secrets before dispatching to LLM
user_prompt = "Connect to database with sk-proj-placeholder-token-here"
result = shield.scan_and_redact(user_prompt)

print(result["hasSecrets"])      # True
print(result["sanitizedText"])   # "Connect to database with [AGENT_SHIELD:AI:7b3a4f1c]"

# When the LLM responds, rehydrate tokens back locally
llm_reply = "I used [AGENT_SHIELD:AI:7b3a4f1c] to query your database."
original = shield.rehydrate(llm_reply)
print(original)  # Restored with original credential!
```

### 2. Pre-Flight Command Sandbox Firewall

```python
from agentshield import AgentCommandSandbox

sandbox = AgentCommandSandbox()

# Intercept adversarial agent actions
check = sandbox.inspect_command("cat .env")
if check["isBlocked"]:
    print(f"🚨 Blocked: {check['reason']}")
    # 🚨 Blocked: Blocked attempt to read raw .env file
```

### 3. LangChain & LangGraph Integration

```python
from langchain_openai import ChatOpenAI
from agentshield import AgentShieldCallbackHandler

# Attach handler to automatically scrub secrets from prompt inputs
llm = ChatOpenAI(
    callbacks=[AgentShieldCallbackHandler()]
)

# Any prompt containing keys will be sanitized before egress to OpenAI!
```

### 4. Sidecar Daemon Client

```python
from agentshield import AgentShieldClient

with AgentShieldClient() as client:
    res = client.scan_and_redact("My key is sk-proj-placeholder-token")
    print(res["sanitizedText"])
```

---

## 🛡️ License

MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
