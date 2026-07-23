"""Direct file editor — applies version bumps without LLM.

Edits pom.xml, requirements.txt, and package.json in monorepo subdirectories.
This replaces the ADK fixer agent for simple version replacement operations.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "target", ".adk_artifacts", ".idea", ".vscode"}


def apply_remediation(workspace_path: str, proposals: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply version bumps to all dependency files in the workspace.

    Args:
        workspace_path: Path to the cloned repo
        proposals: List of {dependency, from_version, to_version, ...}

    Returns:
        {
            "status": "success",
            "changed_files": ["java-service/pom.xml", ...],
            "changes": [{dependency, old_version, new_version, file_path}, ...],
            "updated_count": int,
        }
    """
    workspace = Path(workspace_path)
    changed_files: set[str] = set()
    changes: list[dict[str, Any]] = []
    updated_count = 0

    # Group proposals by ecosystem/file type
    for proposal in proposals:
        dep = proposal.get("dependency", "")
        old_ver = proposal.get("from_version", "")
        new_ver = proposal.get("to_version", "")
        if not dep or not new_ver or new_ver == old_ver:
            continue

        # Determine which file(s) to edit based on dependency format
        # Maven: "groupId:artifactId"
        # PyPI/npm: just "artifactId"
        if ":" in dep and not dep.startswith(("pypi", "npm")):
            # Maven dependency
            parts = dep.split(":")
            group_id = parts[0]
            artifact_id = parts[1]
            edited = _edit_pom_xml(workspace, group_id, artifact_id, old_ver, new_ver)
        else:
            # Could be PyPI or npm — try both
            pkg_name = dep.split(":")[-1]  # handle "pypi:package" format
            edited_pypi = _edit_requirements(workspace, pkg_name, old_ver, new_ver)
            edited_npm = _edit_package_json(workspace, pkg_name, old_ver, new_ver)
            edited = edited_pypi or edited_npm

        if edited:
            changed_files.add(edited)
            changes.append({
                "dependency": dep,
                "old_version": old_ver,
                "new_version": new_ver,
                "file_path": edited,
                "reason": proposal.get("reasoning", f"Security fix: upgrade {dep}"),
            })
            updated_count += 1

    return {
        "status": "success" if updated_count > 0 else "no_changes",
        "changed_files": sorted(changed_files),
        "changes": changes,
        "updated_count": updated_count,
    }


def _edit_pom_xml(workspace: Path, group_id: str, artifact_id: str, old_ver: str, new_ver: str) -> str | None:
    """Edit pom.xml files to update a Maven dependency version."""
    # Search for pom.xml in root and subdirectories
    pom_paths = list(workspace.glob("*/pom.xml")) + ([workspace / "pom.xml"] if (workspace / "pom.xml").exists() else [])

    for pom_path in pom_paths:
        try:
            content = pom_path.read_text(encoding="utf-8")
            # Find the dependency block and replace the version
            pattern = rf"(<groupId>{re.escape(group_id)}</groupId>\s*<artifactId>{re.escape(artifact_id)}</artifactId>\s*<version>){re.escape(old_ver)}(</version>)"
            new_content, count = re.subn(pattern, rf"\g<1>{new_ver}\g<2>", content)
            if count > 0:
                pom_path.write_text(new_content, encoding="utf-8")
                rel_path = str(pom_path.relative_to(workspace)).replace("\\", "/")
                return rel_path
        except Exception:
            continue
    return None


def _edit_requirements(workspace: Path, package_name: str, old_ver: str, new_ver: str) -> str | None:
    """Edit requirements.txt to update a Python package version."""
    req_paths = list(workspace.glob("*/requirements.txt")) + ([workspace / "requirements.txt"] if (workspace / "requirements.txt").exists() else [])

    for req_path in req_paths:
        try:
            content = req_path.read_text(encoding="utf-8")
            # Match: package==version, package>=version, etc.
            pattern = rf"(^{re.escape(package_name)}\s*[=~<>!]+){re.escape(old_ver)}"
            new_content, count = re.subn(pattern, rf"\g<1>{new_ver}", content, flags=re.MULTILINE | re.IGNORECASE)
            if count > 0:
                req_path.write_text(new_content, encoding="utf-8")
                rel_path = str(req_path.relative_to(workspace)).replace("\\", "/")
                return rel_path
        except Exception:
            continue
    return None


def _edit_package_json(workspace: Path, package_name: str, old_ver: str, new_ver: str) -> str | None:
    """Edit package.json to update an npm dependency version."""
    import json
    pkg_paths = list(workspace.glob("*/package.json")) + ([workspace / "package.json"] if (workspace / "package.json").exists() else [])

    for pkg_path in pkg_paths:
        try:
            content = pkg_path.read_text(encoding="utf-8")
            pkg = json.loads(content)
            modified = False
            for section in ("dependencies", "devDependencies"):
                deps = pkg.get(section, {})
                if package_name in deps:
                    current = deps[package_name]
                    # Strip prefixes like ^, ~, >=
                    clean_current = re.sub(r"^[^0-9]*", "", current)
                    if clean_current == old_ver:
                        deps[package_name] = new_ver
                        modified = True
            if modified:
                pkg_path.write_text(json.dumps(pkg, indent=2), encoding="utf-8")
                rel_path = str(pkg_path.relative_to(workspace)).replace("\\", "/")
                return rel_path
        except Exception:
            continue
    return None