"""
AgentShield CrewAI Integration:
Intercepts multi-agent task execution, agent-to-agent delegation, and tool invocations
to redact secrets and block malicious or unauthorized shell commands.
"""

from __future__ import annotations
from typing import Any, Dict, Optional
from ..client import AgentShieldClient


class AgentShieldCrewAIHook:
    """
    CrewAI step and tool hook:
    - Pre-task: Sanitizes task description and expected output.
    - Tool invocation: Intercepts tool calls and blocks dangerous sandbox commands (e.g. cat .env).
    - Inter-agent delegation: Redacts secrets before passing messages between crew agents.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_text(self, text: str) -> str:
        """Sanitizes text by replacing detected secrets with surrogate tokens."""
        if not text:
            return text
        res = self.client.scan_and_redact(text)
        return str(res.get("sanitizedText", text))

    def on_task_start(self, task_description: str) -> str:
        """Sanitizes task description before agent execution."""
        return self.sanitize_text(task_description)

    def on_tool_start(self, tool_name: str, tool_input: Any) -> Any:
        """
        Validates tool execution command against AgentShield command sandbox.
        Raises PermissionError if a forbidden command or sensitive credential is used.
        """
        cmd_str = ""
        if isinstance(tool_input, str):
            cmd_str = tool_input
        elif isinstance(tool_input, dict):
            cmd_str = " ".join(str(v) for v in tool_input.values())
        else:
            cmd_str = str(tool_input)

        inspection = self.client.inspect_command(cmd_str)
        if inspection.get("isBlocked"):
            reason = inspection.get("reason", "Command blocked by security policy")
            raise PermissionError(f"[AgentShield CrewAI Sandbox Block] {reason}: '{cmd_str}' in {tool_name}")

        return tool_input

    def on_agent_output(self, output: str) -> str:
        """Sanitizes agent output or thoughts before handing to next agent in crew."""
        return self.sanitize_text(output)
