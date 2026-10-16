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

# Default alias
AgentShieldEngine = StandaloneEngine

__version__ = "0.1.4"
__all__ = [
    "AgentShieldEngine",
    "StandaloneEngine",
    "AgentCommandSandbox",
    "AgentShieldClient",
    "AgentShieldCallbackHandler",
    "calculate_entropy",
]
