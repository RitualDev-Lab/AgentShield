"""
AgentShield LiteLLM Integration:
Pre-call and post-call proxy hooks that intercept prompt messages and tool calls
across 100+ LLM providers supported by LiteLLM.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from ..client import AgentShieldClient


class AgentShieldLiteLLMHandler:
    """
    LiteLLM input and output hook handler:
    - Pre-call: Redacts sensitive API keys, database credentials, and tokens from `messages`.
    - Post-call: Audits completion choices against credential leakage.
    - Tool-call: Blocks dangerous shell or terminal command arguments.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_text(self, text: str) -> str:
        """Sanitizes text, replacing secrets with deterministic surrogates."""
        if not text:
            return text
        res = self.client.scan_and_redact(text)
        return str(res.get("sanitizedText", text))

    def sanitize_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitizes an OpenAI-style list of messages."""
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = self.sanitize_text(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                        part["text"] = self.sanitize_text(part["text"])
        return messages

    def pre_call_hook(
        self,
        user_api_key_dict: Optional[Dict[str, Any]] = None,
        cache: Optional[Any] = None,
        messages: Optional[List[Dict[str, Any]]] = None,
        call_type: str = "completion",
        **kwargs: Any,
    ) -> Optional[List[Dict[str, Any]]]:
        """Pre-call hook for LiteLLM. Sanitize all message content in-place."""
        if messages and isinstance(messages, list):
            self.sanitize_messages(messages)
            return messages
        return None

    def post_call_hook(
        self,
        user_api_key_dict: Optional[Dict[str, Any]] = None,
        response: Optional[Any] = None,
        call_type: str = "completion",
        **kwargs: Any,
    ) -> Any:
        """Post-call hook auditing completions for leaked credentials."""
        if not response:
            return response

        # If response has choices with message content
        if hasattr(response, "choices"):
            for choice in response.choices:
                if hasattr(choice, "message") and hasattr(choice.message, "content"):
                    if isinstance(choice.message.content, str):
                        choice.message.content = self.sanitize_text(choice.message.content)

        return response

    def inspect_tool_call(self, tool_name: str, tool_args: str) -> None:
        """Inspects tool call arguments against the AgentShield sandbox."""
        inspection = self.client.inspect_command(tool_args)
        if inspection.get("isBlocked"):
            reason = inspection.get("reason", "Tool execution blocked by AgentShield sandbox")
            raise PermissionError(f"[AgentShield Sandbox Block] {reason}: '{tool_args}' in {tool_name}")
