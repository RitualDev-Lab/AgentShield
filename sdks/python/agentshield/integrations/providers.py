"""
AgentShield Direct LLM Provider Interceptors:
Provides zero-leak prompt sanitization and sandbox tool interception
for direct SDK clients: Google Gemini, OpenAI, and Anthropic.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from ..client import AgentShieldClient


class GeminiInterceptor:
    """
    Direct interceptor for Google Gemini SDK (`google.genai` / `google.generativeai`).
    Sanitizes prompt contents before submission and audits function calls against sandbox.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_text(self, text: str) -> str:
        """Replaces detected secrets with surrogate tokens."""
        if not text:
            return text
        res = self.client.scan_and_redact(text)
        return str(res.get("sanitizedText", text))

    def sanitize_contents(self, contents: Any) -> Any:
        """Sanitizes Gemini contents (string, list of strings, or dict parts)."""
        if isinstance(contents, str):
            return self.sanitize_text(contents)
        if isinstance(contents, list):
            sanitized = []
            for item in contents:
                if isinstance(item, str):
                    sanitized.append(self.sanitize_text(item))
                elif isinstance(item, dict) and "text" in item:
                    item_copy = dict(item)
                    item_copy["text"] = self.sanitize_text(item["text"])
                    sanitized.append(item_copy)
                elif hasattr(item, "text") and isinstance(item.text, str):
                    item.text = self.sanitize_text(item.text)
                    sanitized.append(item)
                else:
                    sanitized.append(item)
            return sanitized
        return contents

    def inspect_function_call(self, function_name: str, args: Dict[str, Any]) -> None:
        """Inspects Gemini function call arguments against sandbox policy."""
        arg_str = " ".join(str(v) for v in args.values())
        inspection = self.client.inspect_command(arg_str)
        if inspection.get("isBlocked"):
            reason = inspection.get("reason", "Function call blocked by sandbox policy")
            raise PermissionError(f"[AgentShield Gemini Block] {reason}: '{function_name}({arg_str})'")

    def wrap_client(self, gemini_client: Any) -> Any:
        """Wraps a Gemini client's generate_content method to enforce zero-leak sanitization."""
        interceptor = self

        if hasattr(gemini_client, "models") and hasattr(gemini_client.models, "generate_content"):
            orig_generate = gemini_client.models.generate_content

            def wrapped_generate(*args: Any, **kwargs: Any) -> Any:
                if "contents" in kwargs:
                    kwargs["contents"] = interceptor.sanitize_contents(kwargs["contents"])
                elif len(args) > 1:
                    args_list = list(args)
                    args_list[1] = interceptor.sanitize_contents(args_list[1])
                    args = tuple(args_list)
                return orig_generate(*args, **kwargs)

            gemini_client.models.generate_content = wrapped_generate
        elif hasattr(gemini_client, "generate_content"):
            orig_generate = gemini_client.generate_content

            def wrapped_generate(*args: Any, **kwargs: Any) -> Any:
                if "contents" in kwargs:
                    kwargs["contents"] = interceptor.sanitize_contents(kwargs["contents"])
                elif len(args) > 0:
                    args_list = list(args)
                    args_list[0] = interceptor.sanitize_contents(args_list[0])
                    args = tuple(args_list)
                return orig_generate(*args, **kwargs)

            gemini_client.generate_content = wrapped_generate

        return gemini_client


class OpenAIInterceptor:
    """
    Direct interceptor for OpenAI API clients (`openai`).
    Sanitizes message history and inspects generated tool arguments.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_text(self, text: str) -> str:
        if not text:
            return text
        res = self.client.scan_and_redact(text)
        return str(res.get("sanitizedText", text))

    def sanitize_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitizes messages list in-place."""
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = self.sanitize_text(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and "text" in part:
                        part["text"] = self.sanitize_text(part["text"])
        return messages

    def inspect_tool_calls(self, tool_calls: List[Any]) -> None:
        """Inspects OpenAI tool calls (e.g. bash commands) against sandbox."""
        for tc in tool_calls:
            fn = getattr(tc, "function", None) or (tc.get("function") if isinstance(tc, dict) else None)
            if fn:
                args = getattr(fn, "arguments", "") or (fn.get("arguments", "") if isinstance(fn, dict) else "")
                if isinstance(args, str) and args:
                    inspection = self.client.inspect_command(args)
                    if inspection.get("isBlocked"):
                        reason = inspection.get("reason", "Tool call blocked by AgentShield sandbox")
                        raise PermissionError(f"[AgentShield OpenAI Block] {reason}: '{args}'")

    def wrap_client(self, openai_client: Any) -> Any:
        """Wraps openai_client.chat.completions.create with prompt sanitization."""
        interceptor = self
        if hasattr(openai_client, "chat") and hasattr(openai_client.chat, "completions"):
            orig_create = openai_client.chat.completions.create

            def wrapped_create(*args: Any, **kwargs: Any) -> Any:
                if "messages" in kwargs and isinstance(kwargs["messages"], list):
                    interceptor.sanitize_messages(kwargs["messages"])
                return orig_create(*args, **kwargs)

            openai_client.chat.completions.create = wrapped_create
        return openai_client


class AnthropicInterceptor:
    """
    Direct interceptor for Anthropic API clients (`anthropic`).
    Sanitizes messages before sending and inspects tool_use blocks.
    """

    def __init__(self, client: Optional[AgentShieldClient] = None) -> None:
        self.client = client or AgentShieldClient()

    def sanitize_text(self, text: str) -> str:
        if not text:
            return text
        res = self.client.scan_and_redact(text)
        return str(res.get("sanitizedText", text))

    def sanitize_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sanitizes Anthropic messages list in-place."""
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                msg["content"] = self.sanitize_text(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                        part["text"] = self.sanitize_text(part["text"])
        return messages

    def inspect_tool_use(self, content_blocks: List[Any]) -> None:
        """Inspects Anthropic tool_use content blocks against sandbox."""
        for block in content_blocks:
            b_type = getattr(block, "type", None) or (block.get("type") if isinstance(block, dict) else None)
            if b_type == "tool_use":
                input_data = getattr(block, "input", {}) or (block.get("input", {}) if isinstance(block, dict) else {})
                input_str = " ".join(str(v) for v in input_data.values()) if isinstance(input_data, dict) else str(input_data)
                inspection = self.client.inspect_command(input_str)
                if inspection.get("isBlocked"):
                    reason = inspection.get("reason", "Anthropic tool call blocked by sandbox")
                    raise PermissionError(f"[AgentShield Anthropic Block] {reason}: '{input_str}'")

    def wrap_client(self, anthropic_client: Any) -> Any:
        """Wraps anthropic_client.messages.create with prompt sanitization."""
        interceptor = self
        if hasattr(anthropic_client, "messages") and hasattr(anthropic_client.messages, "create"):
            orig_create = anthropic_client.messages.create

            def wrapped_create(*args: Any, **kwargs: Any) -> Any:
                if "messages" in kwargs and isinstance(kwargs["messages"], list):
                    interceptor.sanitize_messages(kwargs["messages"])
                return orig_create(*args, **kwargs)

            anthropic_client.messages.create = wrapped_create
        return anthropic_client
