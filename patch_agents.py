"""Patch agent files to use the pluggable model configuration."""
from pathlib import Path

BASE = Path(__file__).resolve().parent

# Insert model_config import + resolve_model() usage into both agent files.
agent_files = {
    BASE / "subagents" / "java_vulnerablility_scanner_agent" / "agent.py": {
        "old_model_line": '    model="gemini-2.5-pro",',
        "new_model_line": '    model=resolve_model(),',
        "import_after": "from .prompt import JAVA_VULNERABILITY_SCANNER_INSTRUCTION\n",
        "import_add": "from .prompt import JAVA_VULNERABILITY_SCANNER_INSTRUCTION\nfrom model_config import resolve_model\n",
    },
    BASE / "subagents" / "java_vulnerability_fixer_agent" / "agent.py": {
        "old_model_line": '    model="gemini-2.5-pro",',
        "new_model_line": '    model=resolve_model(),',
        "import_after": "from .prompt import JAVA_VULNERABILITY_FIXER_INSTRUCTION\n",
        "import_add": "from .prompt import JAVA_VULNERABILITY_FIXER_INSTRUCTION\nfrom model_config import resolve_model\n",
    },
}

for agent_path, spec in agent_files.items():
    src = agent_path.read_text(encoding="utf-8")

    # Add import if not present
    if "from model_config import resolve_model" not in src:
        if spec["import_after"] in src:
            src = src.replace(spec["import_after"], spec["import_add"], 1)
        else:
            print(f"WARN: import anchor not found in {agent_path.name}")
            continue

    # Replace hardcoded model with pluggable resolve_model()
    if spec["old_model_line"] in src:
        src = src.replace(spec["old_model_line"], spec["new_model_line"], 1)
        agent_path.write_text(src, encoding="utf-8")
        print(f"OK: patched {agent_path.name} (pluggable model)")
    elif "resolve_model()" in src:
        print(f"OK: {agent_path.name} already patched")
    else:
        print(f"WARN: model line not found in {agent_path.name}")

print("DONE")