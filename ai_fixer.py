"""AI fixer — calls GLM-5.2 directly via LiteLLM (bypasses ADK).

Uses AI to fix code issues that arise after version bumps.
If tests fail after a dependency upgrade, this module asks the LLM to
analyze the error and generate a code fix.
"""
from __future__ import annotations

import os
import json
from typing import Any

# z.ai endpoint (OpenAI-compatible)
ZAI_API_BASE = "https://api.z.ai/api/paas/v4"


def _get_model_and_key() -> tuple[str, str]:
    """Resolve the model and API key for direct litellm call."""
    model = os.getenv("ADK_MODEL", "glm-5.2").strip()
    key = os.getenv("ZAI_API_KEY", "").strip()
    
    # Map friendly names to z.ai model IDs
    model_map = {
        "glm-5.2": "glm-5.2",
        "glm-4": "glm-4",
        "glm-4-flash": "glm-4-flash",
    }
    zai_model = model_map.get(model, model)
    
    return zai_model, key


def ai_fix_code(
    workspace_path: str,
    failed_tests: list[dict[str, Any]],
    changed_files: list[str],
) -> dict[str, Any]:
    """Use AI to fix code issues after version bumps.

    Args:
        workspace_path: Path to the workspace
        failed_tests: List of test results that failed
        changed_files: List of files that were modified

    Returns:
        {
            "status": "fixed" | "failed" | "skipped",
            "fixes_applied": [{file, description}],
            "ai_model": str,
            "error": str | None,
        }
    """
    try:
        import litellm
    except ImportError:
        return {"status": "skipped", "fixes_applied": [], "ai_model": None, "error": "litellm not installed"}

    model, api_key = _get_model_and_key()
    if not api_key:
        return {"status": "skipped", "fixes_applied": [], "ai_model": model, "error": "No ZAI_API_KEY set"}

    # Read the changed files to provide context
    from pathlib import Path
    workspace = Path(workspace_path)
    file_context = ""
    for cf in changed_files[:5]:
        fp = workspace / cf
        if fp.exists() and fp.suffix in (".java", ".py", ".js", ".xml", ".json"):
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")[:2000]
                file_context += f"\n--- {cf} ---\n{content}\n"
            except Exception:
                pass

    # Build the error context from failed tests
    error_context = ""
    for ft in failed_tests:
        error_context += f"\nLanguage: {ft.get('language', '?')}\n"
        error_context += f"Service: {ft.get('service_dir', '?')}\n"
        error_context += f"Error: {ft.get('error', 'unknown')}\n"
        output = ft.get("output", "")
        if output:
            error_context += f"Output (last 500 chars):\n{output[-500:]}\n"

    prompt = f"""You are a security remediation AI assistant. Version bumps were applied to fix vulnerabilities, but some tests are now failing.

Your task: Analyze the test failures and provide code fixes to make the tests pass.

CHANGED FILES:
{file_context}

TEST FAILURES:
{error_context}

Instructions:
1. Analyze why the tests are failing (likely API changes from version bumps)
2. Provide the exact code changes needed
3. Respond in JSON format:
{{
  "analysis": "<brief explanation of the issue>",
  "fixes": [
    {{
      "file": "<relative file path>",
      "description": "<what to change>",
      "old_code": "<the code to replace>",
      "new_code": "<the replacement code>"
    }}
  ]
}}

Keep fixes minimal and focused. Only fix what's broken by the version bumps."""

    try:
        # Call z.ai directly via litellm with explicit params
        response = litellm.completion(
            model=f"openai/{model}",
            messages=[{"role": "user", "content": prompt}],
            api_base=ZAI_API_BASE,
            api_key=api_key,
            temperature=0.1,
            max_tokens=2000,
        )
        raw = response.choices[0].message.content or ""
        
        # Parse JSON from response
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
            raw = raw.strip()
        
        result = json.loads(raw)
        
        # Apply the fixes
        fixes_applied = []
        for fix in result.get("fixes", []):
            file_path = fix.get("file", "")
            old_code = fix.get("old_code", "")
            new_code = fix.get("new_code", "")
            
            if not file_path or not old_code:
                continue
            
            full_path = workspace / file_path
            if not full_path.exists():
                continue
            
            try:
                content = full_path.read_text(encoding="utf-8")
                if old_code in content:
                    new_content = content.replace(old_code, new_code, 1)
                    full_path.write_text(new_content, encoding="utf-8")
                    fixes_applied.append({
                        "file": file_path,
                        "description": fix.get("description", "AI-applied code fix"),
                    })
            except Exception:
                continue
        
        return {
            "status": "fixed" if fixes_applied else "analyzed",
            "fixes_applied": fixes_applied,
            "ai_model": model,
            "analysis": result.get("analysis", ""),
            "error": None,
        }
        
    except json.JSONDecodeError:
        return {"status": "failed", "fixes_applied": [], "ai_model": model, "error": "AI response was not valid JSON"}
    except Exception as exc:
        return {"status": "failed", "fixes_applied": [], "ai_model": model, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}