"""Target adapters for LLM Security Lab."""

from .demo import DemoTarget
from .openai_compatible import GeminiTarget, OpenAICompatibleTarget, OpenAICompatibleTargetError

__all__ = ["DemoTarget", "GeminiTarget", "OpenAICompatibleTarget", "OpenAICompatibleTargetError"]
