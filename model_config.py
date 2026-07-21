"""Pluggable LLM model configuration for Google ADK agents.

Enables swapping the underlying LLM (Gemini / Claude / GLM / OpenAI) without
rewriting agent logic. The model is selected via the ADK_MODEL environment
variable, with sensible defaults and provider-specific API key resolution.

Usage in agent definitions:
    from model_config import resolve_model
    java_vulnerability_scanner_agent = LlmAgent(
        model=resolve_model(),
        ...
    )

Supported ADK_MODEL values (examples):
    gemini-2.5-pro               -> Google Gemini (default, requires GOOGLE_API_KEY)
    gemini-2.5-flash             -> faster Gemini variant
    claude-sonnet                -> Anthropic Claude (requires ANTHROPIC_API_KEY)
    claude-opus                  -> Anthropic Claude Opus
    glm-4                        -> Zhipu GLM-4 (requires ZHIPUAI_API_KEY)
    gpt-4o                       -> OpenAI GPT-4o (requires OPENAI_API_KEY)

For non-Gemini providers, LiteLLM provider prefixes are applied automatically.
"""
from __future__ import annotations

import os


# Mapping of friendly model aliases to LiteLLM-qualified model strings.
# Gemini models are passed through as-is (native Google ADK support).
MODEL_ALIASES: dict[str, str] = {
    # Google Gemini (native ADK support, eligible for Google vendor award)
    "gemini-2.5-pro": "gemini-2.5-pro",
    "gemini-2.5-flash": "gemini-2.5-flash",
    "gemini-2.0-flash": "gemini-2.0-flash",
    # Anthropic Claude
    "claude-sonnet": "litellm/anthropic/claude-3-5-sonnet-20241022",
    "claude-opus": "litellm/anthropic/claude-3-opus-20240229",
    "claude-haiku": "litellm/anthropic/claude-3-5-haiku-20241022",
    # Zhipu GLM
    "glm-4": "litellm/zhipu/glm-4",
    "glm-4-flash": "litellm/zhipu/glm-4-flash",
    # OpenAI
    "gpt-4o": "litellm/openai/gpt-4o",
    "gpt-4o-mini": "litellm/openai/gpt-4o-mini",
}


# Documentation of which env var each provider needs.
PROVIDER_API_KEY_ENV: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "zhipu": "ZHIPUAI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "gemini": "GOOGLE_API_KEY",  # also GOOGLE_GENAI_API_KEY accepted by ADK
}


def _default_model() -> str:
    """Return the default model based on which API keys are available."""
    # Prefer Gemini if a Google key is present (keeps Google vendor award eligibility).
    if os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_API_KEY"):
        return "gemini-2.5-flash"
    # Fall back to Claude if an Anthropic key is present.
    if os.getenv("ANTHROPIC_API_KEY"):
        return "claude-sonnet"
    # Fall back to GLM if a Zhipu key is present.
    if os.getenv("ZHIPUAI_API_KEY"):
        return "glm-4"
    # No key configured - default to Gemini anyway (ADK will surface the auth error clearly).
    return "gemini-2.5-flash"


def resolve_model(model_hint: str | None = None) -> str:
    """Resolve the LLM model string to pass to ADK LlmAgent(model=...).

    Resolution order:
      1. Explicit model_hint argument (if provided)
      2. ADK_MODEL environment variable
      3. Auto-detected default based on available API keys

    Args:
        model_hint: Optional explicit model alias override.

    Returns:
        A model string understood by Google ADK (native Gemini names or
        LiteLLM-prefixed strings for other providers).
    """
    requested = (model_hint or os.getenv("ADK_MODEL") or "").strip()
    if not requested:
        requested = _default_model()

    return MODEL_ALIASES.get(requested, requested)


def active_provider() -> str:
    """Return a human-readable name of the active model provider for logging."""
    model = resolve_model()
    if model.startswith("litellm/anthropic") or "claude" in model:
        return "anthropic"
    if model.startswith("litellm/zhipu") or "glm" in model:
        return "zhipu"
    if model.startswith("litellm/openai") or "gpt" in model:
        return "openai"
    return "google"


def validate_api_key() -> tuple[bool, str]:
    """Check whether the required API key for the active provider is set.

    Returns:
        (is_configured, message)
    """
    provider = active_provider()
    env_var = PROVIDER_API_KEY_ENV.get(provider, "")
    if not env_var:
        return True, f"Provider '{provider}' has no known key requirement."
    value = os.getenv(env_var, "").strip()
    if value:
        return True, f"{env_var} is configured for provider '{provider}'."
    return False, (
        f"Missing {env_var} for provider '{provider}'. "
        f"Set it to use model '{resolve_model()}'."
    )