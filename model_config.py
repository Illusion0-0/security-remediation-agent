"""Pluggable LLM model configuration for Google ADK agents.

Supports multiple providers:
  - z.ai (GLM models — OpenAI-compatible API at api.z.ai)
  - Google Gemini (native ADK)
  - Anthropic Claude (via LiteLLM)
  - OpenAI (via LiteLLM)

Set via ADK_MODEL env var. Keys via provider-specific env vars.
"""
from __future__ import annotations

import os


# Model aliases → provider-qualified strings
MODEL_ALIASES: dict[str, str] = {
    # z.ai GLM (OpenAI-compatible, international endpoint)
    "glm-5.2": "openai/glm-5.2",
    "glm-5.2-flash": "openai/glm-5.2-flash",
    "glm-4": "openai/glm-4",
    "glm-4-flash": "openai/glm-4-flash",
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

# Provider → API key env var
PROVIDER_API_KEY_ENV: dict[str, str] = {
    "zai": "ZAI_API_KEY",
    "gemini": "GOOGLE_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

# Provider → API base URL (for non-default endpoints)
PROVIDER_API_BASE: dict[str, str] = {
    "zai": "https://api.z.ai/api/paas/v4",
}


def _default_model() -> str:
    """Return the default model based on which API keys are available."""
    if os.getenv("ZAI_API_KEY"):
        return "glm-5.2"
    if os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_API_KEY"):
        return "gemini-2.0-flash"
    if os.getenv("ANTHROPIC_API_KEY"):
        return "claude-sonnet"
    return "gemini-2.0-flash"


def resolve_model(model_hint: str | None = None) -> str:
    """Resolve the LLM model string to pass to ADK / LiteLLM."""
    requested = (model_hint or os.getenv("ADK_MODEL") or "").strip()
    if not requested:
        requested = _default_model()
    return MODEL_ALIASES.get(requested, requested)


def active_provider() -> str:
    """Return the active provider name (zai, gemini, anthropic, openai)."""
    model = resolve_model()
    if model.startswith("openai/glm"):
        return "zai"
    if model.startswith("gemini"):
        return "gemini"
    if model.startswith("litellm/anthropic") or "claude" in model:
        return "anthropic"
    if model.startswith("litellm/openai") or "gpt" in model:
        return "openai"
    return "zai"


def validate_api_key() -> tuple[bool, str]:
    """Check whether the required API key for the active provider is set."""
    provider = active_provider()
    env_var = PROVIDER_API_KEY_ENV.get(provider, "")
    if not env_var:
        return True, f"Provider '{provider}' has no known key requirement."
    value = os.getenv(env_var, "").strip()
    if value:
        return True, f"{env_var} configured for provider '{provider}'."
    return False, f"Missing {env_var} for provider '{provider}'. Set it to use {resolve_model()}."


def get_litellm_params() -> dict[str, str]:
    """Get extra LiteLLM params (api_base) for providers with custom endpoints."""
    provider = active_provider()
    api_base = PROVIDER_API_BASE.get(provider, "")
    if api_base:
        return {"api_base": api_base}
    return {}


def resolve_model_for_litellm() -> tuple[str, dict[str, str]]:
    """Return (model_string, extra_params) for use with LiteLLM directly.
    
    For z.ai (OpenAI-compatible), returns the model without the openai/ prefix
    plus the custom api_base and api_key.
    """
    model = resolve_model()
    provider = active_provider()
    params: dict[str, str] = {}
    
    if provider == "zai":
        # Strip the openai/ prefix — LiteLLM openai provider uses api_base override
        clean_model = model.replace("openai/", "")
        key = os.getenv("ZAI_API_KEY", "")
        params = {
            "model": f"openai/{clean_model}",
            "api_base": PROVIDER_API_BASE["zai"],
            "api_key": key,
        }
        return clean_model, params
    
    return model, params