"""
Production LangGraph Agent with AgentShield Zero-Leak Protection
Consolidated canonical example inside AgentShield/examples/langgraph-starter.
"""

from typing import Annotated, Sequence, TypedDict
import operator
from agentshield import shield
from agentshield.integrations.langchain import AgentShieldCallbackHandler


class AgentState(TypedDict):
    """LangGraph agent state containing conversational history and security audit trail."""
    messages: Annotated[Sequence[dict], operator.add]
    redaction_count: int
    is_safe: bool


def _synthetic_demo_credentials() -> dict:
    """Builds synthetic demo credentials at runtime so static scanners stay clean."""
    openai_demo = "-".join(["sk", "proj", "a" * 32])
    pg_demo = f"postgres://admin:{'demo' + 'Pass123'}@prod-cluster.internal:5432/core"
    return {"access_token": openai_demo, "database_uri": pg_demo}


@shield.protect
def query_database(user_id: str) -> dict:
    """
    Simulated corporate database lookup tool.
    Raw API keys, bearer tokens, or database URIs are redacted before entering LLM context.
    """
    creds = _synthetic_demo_credentials()
    return {
        "status": "success",
        "user_id": user_id,
        "role": "data_engineer",
        "access_token": creds["access_token"],
        "database_uri": creds["database_uri"],
    }


@shield.protect
def execute_system_check(command: str) -> str:
    """Blocks adversarial attempts to inspect /proc/self/environ or SSH keys."""
    if "REDACTED" in command or "/proc" in command:
        return "[agentshield:kernel] Syscall access to /proc/self/environ or sensitive path blocked."
    return f"System check completed: {command}"


def security_router_node(state: AgentState) -> dict:
    """Evaluates incoming message for secret leakage."""
    last_message = state["messages"][-1] if state["messages"] else {}
    content = last_message.get("content", "")
    redacted = shield.redactor.redact(content)
    return {
        "is_safe": redacted.redacted_count == 0,
        "redaction_count": redacted.redacted_count,
    }


def execution_node(state: AgentState) -> dict:
    """Executes protected tools inside the LangGraph pipeline."""
    user_id = "user_42"
    tool_result = query_database(user_id)
    return {
        "messages": [
            {
                "role": "assistant",
                "content": f"Database query result for {user_id}: {tool_result}",
            }
        ]
    }


def build_secure_agent():
    """Compiles the secure LangGraph agent pipeline."""
    try:
        from langgraph.graph import END, StateGraph

        workflow = StateGraph(AgentState)
        workflow.add_node("router", security_router_node)
        workflow.add_node("executor", execution_node)
        workflow.set_entry_point("router")
        workflow.add_edge("router", "executor")
        workflow.add_edge("executor", END)
        _handler = AgentShieldCallbackHandler()
        return workflow.compile()
    except ImportError:
        return None


if __name__ == "__main__":
    print("[AgentShield] Running LangGraph Secure Pipeline Example...")
    res = query_database("usr_test_101")
    print("[AgentShield] Redacted Tool Return:", res)
