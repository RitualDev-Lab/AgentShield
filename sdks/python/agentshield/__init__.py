"""
AgentShield Python SDK:
Zero-leak secret defense and shell command sandbox for autonomous AI agents.
"""

from .standalone import (
    StandaloneEngine,
    AgentCommandSandbox,
    calculate_entropy,
)
from .client import AgentShieldClient
from .integrations.langchain import AgentShieldCallbackHandler
from .integrations.llamaindex import AgentShieldLlamaIndexCallbackHandler
from .integrations.litellm import AgentShieldLiteLLMHandler
from .integrations.crewai import AgentShieldCrewAIHook
from .integrations.providers import (
    GeminiInterceptor,
    OpenAIInterceptor,
    AnthropicInterceptor,
)

# Default alias
AgentShieldEngine = StandaloneEngine

__version__ = "0.1.5"
__all__ = [
    "AgentShieldEngine",
    "StandaloneEngine",
    "AgentCommandSandbox",
    "AgentShieldClient",
    "AgentShieldCallbackHandler",
    "AgentShieldLlamaIndexCallbackHandler",
    "AgentShieldLiteLLMHandler",
    "AgentShieldCrewAIHook",
    "GeminiInterceptor",
    "OpenAIInterceptor",
    "AnthropicInterceptor",
    "calculate_entropy",
]
