"""Target adapters for LLM Security Lab."""

from .demo import DemoTarget
from .openai_compatible import OpenAICompatibleTarget, OpenAICompatibleTargetError

__all__ = ["DemoTarget", "OpenAICompatibleTarget", "OpenAICompatibleTargetError"]
