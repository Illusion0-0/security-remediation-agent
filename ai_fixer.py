"""AI fixer — calls GLM-5.2 directly via LiteLLM with language-specific skills."""
from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any

ZAI_API_BASE = "https://api.z.ai/api/paas/v4"


def _load_skill(language: str) -> str:
    """Load the skill file for a language."""
    skill_path = Path(__file__).parent / "skills" / f"skill_{language}.md"
    if skill_path.exists():
        return skill_path.read_text(encoding="utf-8")
    return ""


def _get_model_and_key() -> tuple[str, str]:
    model = os.getenv("ADK_MODEL", "glm-5.2").strip()
    key = os.getenv("ZAI_API_KEY", "").strip()
    return model, key


def ai_fix_code(workspace_path: str, failed_tests: list[dict[str, Any]], changed_files: list[str]) -> dict[str, Any]:
    """Use AI with skill knowledge to fix code issues after version bumps."""
    try:
        import litellm
    except ImportError:
        return {"status": "skipped", "fixes_applied": [], "ai_model": None, "error": "litellm not installed"}

    model, api_key = _get_model_and_key()
    if not api_key:
        return {"status": "skipped", "fixes_applied": [], "ai_model": model, "error": "No ZAI_API_KEY set"}

    workspace = Path(workspace_path)
    all_fixes = []

    for failure in failed_tests:
        lang = failure.get("language", "java")
        skill = _load_skill(lang)

        # Read changed source files for context
        file_context = ""
        for cf in changed_files[:5]:
            fp = workspace / cf
            if fp.exists() and fp.suffix in (".java", ".py", ".js", ".ts"):
                try:
                    content = fp.read_text(encoding="utf-8", errors="replace")[:3000]
                    file_context += f"\n--- {cf} ---\n{content}\n"
                except Exception:
                    pass

        error_context = f"Language: {lang}\nService: {failure.get('service_dir', '?')}\nError: {failure.get('error', 'unknown')}\nOutput (last 500):\n{failure.get('output', '')[-500:]}"

        prompt = f"""You are a {lang} security remediation specialist. Version bumps were applied to fix vulnerabilities, but tests are now failing.

YOUR EXPERTISE:
{skill}

CHANGED FILES:
{file_context}

TEST FAILURES:
{error_context}

Task: Analyze the failures and provide exact code fixes. Respond in JSON:
{{
  "analysis": "<brief explanation>",
  "fixes": [
    {{
      "file": "<relative path>",
      "description": "<what to change>",
      "old_code": "<exact code to find>",
      "new_code": "<replacement code>"
    }}
  ]
}}"""

        try:
            response = litellm.completion(
                model=f"openai/{model}",
                messages=[{"role": "user", "content": prompt}],
                api_base=ZAI_API_BASE,
                api_key=api_key,
                temperature=0.1,
                max_tokens=2000,
            )
            raw = response.choices[0].message.content or ""
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
                raw = raw.strip()

            result = json.loads(raw)

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
                        all_fixes.append({"file": file_path, "description": fix.get("description", ""), "language": lang})
                except Exception:
                    continue

        except json.JSONDecodeError:
            pass
        except Exception as exc:
            all_fixes.append({"file": "", "description": f"AI error: {type(exc).__name__}: {str(exc)[:100]}", "language": lang})

    return {
        "status": "fixed" if all_fixes else "analyzed",
        "fixes_applied": all_fixes,
        "ai_model": model,
        "error": None,
    }
