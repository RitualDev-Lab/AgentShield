"""
Unit tests for AgentShield Python SDK
"""

import sys
from pathlib import Path
import unittest

# Ensure sdks/python is on sys.path regardless of runner working directory
sdk_dir = Path(__file__).resolve().parent.parent
if str(sdk_dir) not in sys.path:
    sys.path.insert(0, str(sdk_dir))

from agentshield import (
    StandaloneEngine,
    AgentCommandSandbox,
    calculate_entropy,
    AgentShieldClient,
    AgentShieldCallbackHandler,
)


class TestAgentShieldPython(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = StandaloneEngine()
        self.sandbox = AgentCommandSandbox()

    def test_shannon_entropy(self) -> None:
        self.assertEqual(calculate_entropy(""), 0.0)
        self.assertEqual(calculate_entropy("aaaaaa"), 0.0)
        entropy = calculate_entropy("The quick brown fox jumps over the lazy dog")
        self.assertGreater(entropy, 3.5)

    def test_scan_and_redact_openai_key(self) -> None:
        prefix = "-".join(["sk", "proj"])
        body = "".join(["abc", "123", "xyz", "789", "def", "456", "ghi", "012"])
        secret = f"{prefix}-{body}"
        prompt = f"Run LLM inference with {secret} as bearer token"

        res = self.engine.scan_and_redact(prompt)
        self.assertTrue(res["hasSecrets"])
        self.assertNotIn(secret, res["sanitizedText"])
        self.assertIn("[AGENT_SHIELD:AI:", res["sanitizedText"])

        # Test in-memory rehydration
        rehydrated = self.engine.rehydrate(res["sanitizedText"])
        self.assertEqual(rehydrated, prompt)

    def test_scan_and_redact_stripe_key(self) -> None:
        prefix = "_".join(["sk", "live"])
        body = "".join(["test", "Stripe", "Key", "123", "456", "789"])
        secret = f"{prefix}_{body}"
        input_text = f"API_SECRET={secret}"

        res = self.engine.scan_and_redact(input_text, mask_style="token")
        self.assertTrue(res["hasSecrets"])
        self.assertNotIn(secret, res["sanitizedText"])
        self.assertIn("[AGENT_SHIELD:SAAS:", res["sanitizedText"])

    def test_command_sandbox_blocking(self) -> None:
        # Should block .env read
        res1 = self.sandbox.inspect_command("cat .env")
        self.assertTrue(res1["isBlocked"])
        self.assertIn(".env", res1["reason"])

        # Should block environment dump
        res2 = self.sandbox.inspect_command("printenv")
        self.assertTrue(res2["isBlocked"])

        # Should block /etc/shadow access
        res3 = self.sandbox.inspect_command("cat /etc/shadow")
        self.assertTrue(res3["isBlocked"])

        # Should allow benign build commands
        res4 = self.sandbox.inspect_command("pytest tests/")
        self.assertFalse(res4["isBlocked"])

    def test_langchain_callback_handler(self) -> None:
        client = AgentShieldClient(use_fallback=True)
        handler = AgentShieldCallbackHandler(client=client)

        prefix = "_".join(["sk", "live"])
        secret = f"{prefix}_" + "".join(["mock", "Stripe", "Key", "123", "456", "789"])
        prompts = [f"Deploy using key={secret}"]

        handler.on_llm_start({}, prompts)
        self.assertNotIn(secret, prompts[0])
        self.assertIn("[AGENT_SHIELD:", prompts[0])

        # Test tool interception
        with self.assertRaises(PermissionError):
            handler.on_tool_start({}, "cat .env")


if __name__ == "__main__":
    unittest.main()
