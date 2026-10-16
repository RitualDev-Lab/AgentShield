"""
AgentShield LangChain & LangGraph Integration:
Intercepts prompt submissions and tool invocations to redact sensitive credentials
before they enter the LLM context window.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from ..client import AgentShieldClient


class AgentShieldCallbackHandler:
    """
    LangChain callback handler that automatically redacts secrets from prompts,
    tool inputs, and context variables before dispatching to LLMs.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_prompt(self, prompt: str) -> str:
        """Sanitizes an input prompt string, replacing secrets with surrogate tokens."""
        res = self.client.scan_and_redact(prompt)
        return str(res.get("sanitizedText", prompt))

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any
    ) -> None:
        """Inspects and redacts prompts in-place before inference."""
        for i, p in enumerate(prompts):
            prompts[i] = self.sanitize_prompt(p)

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        """Inspects tool execution commands against AgentShield sandbox firewall."""
        inspection = self.client.inspect_command(input_str)
        if inspection.get("isBlocked"):
            reason = inspection.get("reason", "Command blocked by security policy")
            raise PermissionError(f"[AgentShield Sandbox Block] {reason}: '{input_str}'")
