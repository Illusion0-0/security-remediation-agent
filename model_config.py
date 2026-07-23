"""Pluggable LLM model configuration for Google ADK agents.

Supports:
  - z.ai GLM (glm-5.2, glm-4 variants — OpenAI-compatible at api.z.ai)
  - Google Gemini (native ADK)
  - Anthropic Claude (via LiteLLM)
  - OpenAI (via LiteLLM)
"""
from __future__ import annotations

import os

# Model aliases → provider-qualified strings
MODEL_ALIASES: dict[str, str] = {
    # z.ai GLM (OpenAI-compatible, international endpoint)
    "glm-5.2": "openai/glm-5.2",
    "glm-4": "openai/glm-4",
    "glm-4-flash": "openai/glm-4-flash",
    "glm-4-plus": "openai/glm-4-plus",
    "glm-4-air": "openai/glm-4-air",
    "glm-4-airx": "openai/glm-4-airx",
    "glm-4-long": "openai/glm-4-long",
    # Google Gemini (native ADK)
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.0-flash": "gemini-2.0-flash",
    # Anthropic Claude
    "claude-sonnet": "litellm/anthropic/claude-3-5-sonnet-20241022",
    "claude-haiku": "litellm/anthropic/claude-3-5-haiku-20241022",
    # OpenAI
    "gpt-4o": "litellm/openai/gpt-4o",
    "gpt-4o-mini": "litellm/openai/gpt-4o-mini",
}

PROVIDER_API_KEY_ENV: dict[str, str] = {
    "zai": "ZAI_API_KEY",
    "gemini": "GOOGLE_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

ZAI_API_BASE = "https://api.z.ai/api/paas/v4"


def _default_model() -> str:
    if os.getenv("ZAI_API_KEY"):
        return "glm-5.2"
    if os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_API_KEY"):
        return "gemini-2.0-flash"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "claude-sonnet"
    return "gemini-2.0-flash"


def resolve_model(model_hint: str | None = None) -> str:
    requested = (model_hint or os.getenv("ADK_MODEL") or "").strip()
    if not requested:
        requested = _default_model()
    resolved = MODEL_ALIASES.get(requested, requested)
    provider = active_provider_from_string(resolved)
    if provider == "zai":
        zai_key = os.getenv("ZAI_API_KEY", "")
        os.environ["OPENAI_API_BASE"] = ZAI_API_BASE
        if zai_key:
            os.environ["OPENAI_API_KEY"] = zai_key
    return resolved


def active_provider_from_string(model: str) -> str:
    if model.startswith("openai/glm"):
        return "zai"
    if model.startswith("gemini"):
        return "gemini"
    if model.startswith("litellm/anthropic") or "claude" in model:
        return "anthropic"
    if model.startswith("litellm/openai") or "gpt" in model:
        return "openai"
    return "zai"


def active_provider() -> str:
    return active_provider_from_string(resolve_model())


def validate_api_key() -> tuple[bool, str]:
    provider = active_provider()
    env_var = PROVIDER_API_KEY_ENV.get(provider, "")
    if not env_var:
        return True, f"Provider '{provider}' has no known key requirement."
    value = os.getenv(env_var, "").strip()
    if value:
        return True, f"{env_var} configured for provider '{provider}'."
    return False, f"Missing {env_var} for provider '{provider}'. Set it to use {resolve_model()}."


def get_litellm_params() -> dict[str, str]:
    if active_provider() == "zai":
        return {"api_base": ZAI_API_BASE}
    return {}