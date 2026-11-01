"""
AgentShield LlamaIndex Integration:
Intercepts query submissions, retrieved context nodes, and tool executions
to redact sensitive credentials and enforce sandbox boundaries in LlamaIndex workflows.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from ..client import AgentShieldClient


class AgentShieldLlamaIndexCallbackHandler:
    """
    LlamaIndex callback handler that automatically redacts credentials from queries,
    retrieved documents, and LLM prompts, and blocks unauthorized sandbox commands.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_text(self, text: str) -> str:
        """Sanitizes text by replacing detected secrets with surrogate tokens."""
        if not text:
            return text
        res = self.client.scan_and_redact(text)
        return str(res.get("sanitizedText", text))

    def on_event_start(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Intercepts LlamaIndex events at trigger time."""
        if not payload:
            return event_id

        # 1. Sanitize user queries and prompt templates
        if "query_str" in payload and isinstance(payload["query_str"], str):
            payload["query_str"] = self.sanitize_text(payload["query_str"])

        if "messages" in payload and isinstance(payload["messages"], list):
            for msg in payload["messages"]:
                if isinstance(msg, dict) and "content" in msg and isinstance(msg["content"], str):
                    msg["content"] = self.sanitize_text(msg["content"])
                elif hasattr(msg, "content") and isinstance(msg.content, str):
                    msg.content = self.sanitize_text(msg.content)

        # 2. Intercept function calls / tool invocations
        if event_type in ("function_call", "tool") or "tool" in payload:
            tool_input = payload.get("tool_input") or payload.get("input") or ""
            if isinstance(tool_input, str) and tool_input.strip():
                inspection = self.client.inspect_command(tool_input)
                if inspection.get("isBlocked"):
                    reason = inspection.get("reason", "Tool execution blocked by AgentShield sandbox")
                    raise PermissionError(f"[AgentShield Sandbox Block] {reason}: '{tool_input}'")

        return event_id

    def on_event_end(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Inspects and scrubs secrets from output nodes or retrieved chunks."""
        if not payload:
            return

        if "nodes" in payload and isinstance(payload["nodes"], list):
            for node in payload["nodes"]:
                if hasattr(node, "text") and isinstance(node.text, str):
                    node.text = self.sanitize_text(node.text)
                elif isinstance(node, dict) and "text" in node and isinstance(node["text"], str):
                    node["text"] = self.sanitize_text(node["text"])

        if "response" in payload and isinstance(payload["response"], str):
            payload["response"] = self.sanitize_text(payload["response"])
