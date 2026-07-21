"""Multi-language vulnerability scanner with static CVE fallback.

Detects the project language (Java/Maven, Python/pip, Node.js/npm) from the
workspace contents and runs the appropriate scanner. Each language has a static
CVE database fallback so the pipeline works offline without JFrog/pip-audit/npm.

This module is language-agnostic and plugs into the same /scan endpoint contract.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SEVERITY_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ---------------------------------------------------------------------------
# Version comparison helpers (shared across languages)
# ---------------------------------------------------------------------------

def _version_key(version: str) -> list[tuple[int, int | str]]:
    tokens = re.findall(r"\d+|[A-Za-z]+", str(version))
    parsed: list[tuple[int, int | str]] = []
    for token in tokens:
        if token.isdigit():
            parsed.append((1, int(token)))
        else:
            parsed.append((0, token.lower()))
    return parsed


def _compare_versions(left: str | None, right: str | None) -> int:
    if left == right:
        return 0
    if not left:
        return -1
    if not right:
        return 1
    left_key = _version_key(left)
    right_key = _version_key(right)
    max_length = max(len(left_key), len(right_key))
    for index in range(max_length):
        left_token = left_key[index] if index < len(left_key) else (1, 0)
        right_token = right_key[index] if index < len(right_key) else (1, 0)
        if left_token == right_token:
            continue
        return 1 if left_token > right_token else -1
    return 0


def _is_vulnerable(version: str, entry: dict[str, Any]) -> bool:
    if "vulnerable_below" in entry:
        if _compare_versions(version, entry["vulnerable_below"]) < 0:
            return True
    for lower, upper in entry.get("vulnerable_ranges", []):
        if _compare_versions(version, lower) >= 0 and _compare_versions(version, upper) < 0:
            return True
    return False


# ---------------------------------------------------------------------------
# CVE Databases per language
# ---------------------------------------------------------------------------

PYTHON_CVE_DATABASE: dict[str, dict[str, Any]] = {
    "requests": {
        "cves": ["CVE-2023-32681"],
        "severity": "High",
        "vulnerable_below": "2.31.0",
        "fixed_version": "2.31.0",
        "fixed_candidates": ["2.31.0", "2.32.0"],
        "description": "Proxy-Authorization header leak on redirects",
    },
    "urllib3": {
        "cves": ["CVE-2023-43804", "CVE-2023-45803"],
        "severity": "High",
        "vulnerable_below": "1.26.18",
        "fixed_version": "1.26.18",
        "fixed_candidates": ["1.26.18", "2.0.7", "2.1.0"],
        "description": "Cookie/headers leak on cross-origin redirect",
    },
    "cryptography": {
        "cves": ["CVE-2023-49083"],
        "severity": "High",
        "vulnerable_below": "41.0.6",
        "fixed_version": "41.0.6",
        "fixed_candidates": ["41.0.6", "42.0.0", "43.0.0"],
        "description": "NULL_CIPHER NULL signature forgery",
    },
    "pillow": {
        "cves": ["CVE-2023-50447"],
        "severity": "High",
        "vulnerable_below": "10.2.0",
        "fixed_version": "10.2.0",
        "fixed_candidates": ["10.2.0", "10.3.0"],
        "description": "Arbitrary code execution via crafted image",
    },
    "pyyaml": {
        "cves": ["CVE-2020-1747", "CVE-2020-14343"],
        "severity": "Critical",
        "vulnerable_below": "5.4",
        "fixed_version": "5.4",
        "fixed_candidates": ["5.4", "6.0", "6.0.1"],
        "description": "RCE via unsafe YAML deserialization",
    },
    "jinja2": {
        "cves": ["CVE-2024-22195"],
        "severity": "Medium",
        "vulnerable_below": "3.1.3",
        "fixed_version": "3.1.3",
        "fixed_candidates": ["3.1.3", "3.1.4"],
        "description": "XSS via xmlattr filter",
    },
    "werkzeug": {
        "cves": ["CVE-2023-46136"],
        "severity": "Medium",
        "vulnerable_below": "3.0.1",
        "fixed_version": "3.0.1",
        "fixed_candidates": ["3.0.1", "3.0.3"],
        "description": "Multipart parser DoS via crafted boundary",
    },
    "aiohttp": {
        "cves": ["CVE-2024-23334"],
        "severity": "High",
        "vulnerable_below": "3.9.2",
        "fixed_version": "3.9.2",
        "fixed_candidates": ["3.9.2", "3.9.3", "3.9.4"],
        "description": "Directory traversal in static file routes",
    },
    "setuptools": {
        "cves": ["CVE-2024-6345"],
        "severity": "High",
        "vulnerable_below": "70.0.0",
        "fixed_version": "70.0.0",
        "fixed_candidates": ["70.0.0", "70.3.0"],
        "description": "RCE via package index integration",
    },
    "django": {
        "cves": ["CVE-2023-46695", "CVE-2023-43665"],
        "severity": "High",
        "vulnerable_below": "4.2.7",
        "fixed_version": "4.2.7",
        "fixed_candidates": ["4.2.7", "4.2.16", "5.0.0"],
        "description": "DoS via username field / formset indexing",
    },
}

NODE_CVE_DATABASE: dict[str, dict[str, Any]] = {
    "lodash": {
        "cves": ["CVE-2021-23337", "CVE-2020-8203"],
        "severity": "Critical",
        "vulnerable_below": "4.17.21",
        "fixed_version": "4.17.21",
        "fixed_candidates": ["4.17.21"],
        "description": "Prototype pollution / XSS",
    },
    "axios": {
        "cves": ["CVE-2023-45857", "CVE-2024-39338"],
        "severity": "High",
        "vulnerable_below": "1.6.0",
        "fixed_version": "1.6.0",
        "fixed_candidates": ["1.6.0", "1.7.0", "1.7.4"],
        "description": "CSRF token leak / SSRF via absolute URL",
    },
    "express": {
        "cves": ["CVE-2024-29041"],
        "severity": "Medium",
        "vulnerable_below": "4.19.2",
        "fixed_version": "4.19.2",
        "fixed_candidates": ["4.19.2", "4.21.0"],
        "description": "Open redirect via malformed URLs",
    },
    "minimatch": {
        "cves": ["CVE-2022-3517"],
        "severity": "High",
        "vulnerable_below": "3.0.5",
        "fixed_version": "3.0.5",
        "fixed_candidates": ["3.0.5", "3.1.2", "9.0.0"],
        "description": "ReDoS via crafted pattern",
    },
    "handlebars": {
        "cves": ["CVE-2023-26136"],
        "severity": "Critical",
        "vulnerable_below": "4.7.7",
        "fixed_version": "4.7.7",
        "fixed_candidates": ["4.7.7", "4.7.8"],
        "description": "Prototype pollution leading to RCE",
    },
    "qs": {
        "cves": ["CVE-2022-24999"],
        "severity": "High",
        "vulnerable_below": "6.5.3",
        "fixed_version": "6.5.3",
        "fixed_candidates": ["6.5.3", "6.11.0", "6.13.0"],
        "description": "Prototype pollution via __proto__ keys",
    },
    "moment": {
        "cves": ["CVE-2022-31129"],
        "severity": "High",
        "vulnerable_below": "2.29.4",
        "fixed_version": "2.29.4",
        "fixed_candidates": ["2.29.4"],
        "description": "ReDoS via crafted date string",
    },
    "ws": {
        "cves": ["CVE-2024-37890"],
        "severity": "High",
        "vulnerable_below": "8.17.1",
        "fixed_version": "8.17.1",
        "fixed_candidates": ["8.17.1", "8.18.0"],
        "description": "DoS via crafted HTTP upgrade request",
    },
    "jsonwebtoken": {
        "cves": ["CVE-2022-23529", "CVE-2022-23539", "CVE-2022-23540"],
        "severity": "Critical",
        "vulnerable_below": "9.0.0",
        "fixed_version": "9.0.0",
        "fixed_candidates": ["9.0.0"],
        "description": "Algorithm confusion / key injection",
    },
    "node-forge": {
        "cves": ["CVE-2022-24771", "CVE-2023-28756"],
        "severity": "Critical",
        "vulnerable_below": "1.3.1",
        "fixed_version": "1.3.1",
        "fixed_candidates": ["1.3.1", "1.8.1"],
        "description": "Prototype pollution / ReDoS",
    },
}


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

def detect_language(workspace_url: str) -> str:
    """Detect the project language from workspace files.

    Returns: 'java' | 'python' | 'nodejs' | 'unknown'
    """
    workspace = Path(workspace_url)
    if (workspace / "pom.xml").exists() or (workspace / "build.gradle").exists():
        return "java"
    if (workspace / "requirements.txt").exists() or (workspace / "pyproject.toml").exists() or (workspace / "setup.py").exists():
        return "python"
    if (workspace / "package.json").exists() or (workspace / "package-lock.json").exists():
        return "nodejs"
    return "unknown"


# ---------------------------------------------------------------------------
# Python scanner (static)
# ---------------------------------------------------------------------------

def _parse_requirements(path: Path) -> list[tuple[str, str]]:
    """Parse requirements.txt, returning (package, version) tuples."""
    deps: list[tuple[str, str]] = []
    if not path.exists():
        return deps
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=~<>!]+\s*([0-9A-Za-z.\-]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        match = pattern.match(line)
        if match:
            deps.append((match.group(1).lower(), match.group(2)))
    return deps


def _parse_pyproject(path: Path) -> list[tuple[str, str]]:
    """Parse pyproject.toml [project.dependencies], returning (package, version) tuples."""
    deps: list[tuple[str, str]] = []
    if not path.exists():
        return deps
    text = path.read_text(encoding="utf-8", errors="replace")
    in_deps = False
    pattern = re.compile(r'^\s*"([A-Za-z0-9_.\-]+)\s*[=<>~!^]*\s*([0-9A-Za-z.\-+]*)"')
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[project"):
            in_deps = "dependencies" in stripped or in_deps
            continue
        if stripped.startswith("[") and not "dependencies" in stripped.lower():
            in_deps = False
            continue
        if in_deps:
            match = pattern.match(line)
            if match:
                deps.append((match.group(1).lower(), match.group(2)))
    return deps


def _scan_python_static(workspace_url: str) -> dict[str, Any]:
    workspace = Path(workspace_url)
    deps: list[tuple[str, str]] = []
    deps.extend(_parse_requirements(workspace / "requirements.txt"))
    deps.extend(_parse_pyproject(workspace / "pyproject.toml"))

    artifact_dir = workspace / ".adk_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "scan_latest.txt"

    findings: list[dict[str, Any]] = []
    report_lines = ["=" * 80, "PYTHON STATIC CVE SCAN (Offline Mode)", "=" * 80, f"Workspace: {workspace_url}", f"Dependencies analyzed: {len(deps)}", ""]

    for name, version in deps:
        entry = PYTHON_CVE_DATABASE.get(name)
        if not entry:
            report_lines.append(f"  OK     {name}=={version} (no known CVEs)")
            continue
        if _is_vulnerable(version, entry):
            fixed = entry["fixed_version"]
            report_lines.append(f"  VULN   [{entry['severity']}] {name}=={version} -> {fixed} | {', '.join(entry['cves'])}")
            findings.append({
                "severity": entry["severity"],
                "groupId": "pypi",
                "artifactId": name,
                "current_version": version,
                "fixed_version": fixed,
                "fixed_candidates": entry.get("fixed_candidates", [fixed]),
                "cves": entry["cves"],
                "summary": f"{name} {version} -> {fixed}",
            })
        else:
            report_lines.append(f"  OK     {name}=={version} (version is safe)")

    report_text = "\n".join(report_lines + ["", f"Total: {len(findings)}", "=" * 80])
    report_path.write_text(report_text, encoding="utf-8")
    return _build_result(findings, report_path, report_text, "python", "static")


# ---------------------------------------------------------------------------
# Node.js scanner (static)
# ---------------------------------------------------------------------------

def _scan_nodejs_static(workspace_url: str) -> dict[str, Any]:
    workspace = Path(workspace_url)
    pkg_path = workspace / "package.json"
    artifact_dir = workspace / ".adk_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "scan_latest.txt"

    deps: dict[str, str] = {}
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
            deps.update({k.lower().lstrip("@"): v.lstrip("^~>=< ") for k, v in (pkg.get("dependencies") or {}).items()})
            deps.update({k.lower().lstrip("@"): v.lstrip("^~>=< ") for k, v in (pkg.get("devDependencies") or {}).items()})
        except json.JSONDecodeError:
            pass

    findings: list[dict[str, Any]] = []
    report_lines = ["=" * 80, "NODE.JS STATIC CVE SCAN (Offline Mode)", "=" * 80, f"Workspace: {workspace_url}", f"Dependencies analyzed: {len(deps)}", ""]

    for name, version in deps.items():
        entry = NODE_CVE_DATABASE.get(name)
        if not entry:
            report_lines.append(f"  OK     {name}@{version} (no known CVEs)")
            continue
        if _is_vulnerable(version, entry):
            fixed = entry["fixed_version"]
            report_lines.append(f"  VULN   [{entry['severity']}] {name}@{version} -> {fixed} | {', '.join(entry['cves'])}")
            findings.append({
                "severity": entry["severity"],
                "groupId": "npm",
                "artifactId": name,
                "current_version": version,
                "fixed_version": fixed,
                "fixed_candidates": entry.get("fixed_candidates", [fixed]),
                "cves": entry["cves"],
                "summary": f"{name} {version} -> {fixed}",
            })
        else:
            report_lines.append(f"  OK     {name}@{version} (version is safe)")

    report_text = "\n".join(report_lines + ["", f"Total: {len(findings)}", "=" * 80])
    report_path.write_text(report_text, encoding="utf-8")
    return _build_result(findings, report_path, report_text, "nodejs", "static")


# ---------------------------------------------------------------------------
# Java scanner (reuses existing static_scanner logic)
# ---------------------------------------------------------------------------

def _scan_java_static(workspace_url: str) -> dict[str, Any]:
    """Delegate to the Java static scanner module under the scanner subagent."""
    import sys
    scanner_dir = Path(__file__).resolve().parent / "subagents" / "java_vulnerablility_scanner_agent" / "tools"
    if str(scanner_dir) not in sys.path:
        sys.path.insert(0, str(scanner_dir))
    from static_scanner import scan_workspace_static
    return scan_workspace_static(workspace_url)


# ---------------------------------------------------------------------------
# Shared result builder
# ---------------------------------------------------------------------------

def _build_result(findings: list[dict], report_path: Path, report_text: str, language: str, backend: str) -> dict[str, Any]:
    targets = _build_remediation_targets(findings)
    affected = sorted({f"{f['groupId']}:{f['artifactId']}" for f in findings})
    critical = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")
    return {
        "status": "success",
        "return_code": 0,
        "report_path": str(report_path),
        "report_size_chars": len(report_text),
        "error": "",
        "vulnerabilities_found": len(findings) > 0,
        "scan_execution_error": False,
        "scanner_backend": backend,
        "language": language,
        "critical_vulnerabilities": critical,
        "high_vulnerabilities": high,
        "medium_vulnerabilities": medium,
        "low_vulnerabilities": low,
        "total_vulnerabilities": len(findings),
        "remediation_targets": targets,
        "affected_dependencies": affected,
    }


def _build_remediation_targets(findings: list[dict]) -> list[dict]:
    aggregated: dict[tuple, dict] = {}
    for f in findings:
        sev = f.get("severity")
        if sev not in SEVERITY_PRIORITY:
            continue
        key = (f["groupId"], f["artifactId"], f.get("current_version"))
        if key not in aggregated:
            aggregated[key] = {
                "dependency": f"{f['groupId']}:{f['artifactId']}" if f["groupId"] != "pypi" and f["groupId"] != "npm" else f["artifactId"],
                "groupId": f["groupId"],
                "artifactId": f["artifactId"],
                "current_version": f.get("current_version"),
                "fixed_candidates": [],
                "highest_severity": sev,
                "cves": [],
            }
        t = aggregated[key]
        if SEVERITY_PRIORITY[sev] < SEVERITY_PRIORITY.get(t["highest_severity"], 99):
            t["highest_severity"] = sev
        t["fixed_candidates"].extend(f.get("fixed_candidates", []))
        t["cves"] = sorted(set(t["cves"] + f.get("cves", [])))
    targets = []
    for t in aggregated.values():
        candidates = sorted(set(t["fixed_candidates"]), key=_version_key)
        fixed = candidates[0] if candidates else None
        targets.append({
            "dependency": t["dependency"],
            "groupId": t["groupId"],
            "artifactId": t["artifactId"],
            "current_version": t["current_version"],
            "fixed_version": fixed,
            "fixed_candidates": candidates,
            "highest_severity": t["highest_severity"],
            "cves": t["cves"],
            "summary": f"{t['dependency']} {t['current_version'] or ''} -> {fixed or 'unknown'}".strip(),
        })
    targets.sort(key=lambda x: (SEVERITY_PRIORITY.get(x.get("highest_severity"), 99), x["dependency"]))
    return targets


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_workspace_multi(workspace_url: str) -> dict[str, Any]:
    """Auto-detect project language and run the appropriate static scanner.

    Supports Java/Maven, Python/pip, and Node.js/npm workspaces.
    Returns a result dict identical in shape to run_jf_audit_scan.
    """
    language = detect_language(workspace_url)
    if language == "java":
        return _scan_java_static(workspace_url)
    if language == "python":
        return _scan_python_static(workspace_url)
    if language == "nodejs":
        return _scan_nodejs_static(workspace_url)
    # Unknown language - return empty result with clear status.
    workspace = Path(workspace_url)
    artifact_dir = workspace / ".adk_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "scan_latest.txt"
    report_path.write_text(f"Unsupported workspace: no pom.xml, requirements.txt, or package.json found in {workspace_url}\n", encoding="utf-8")
    return {
        "status": "error",
        "return_code": 1,
        "report_path": str(report_path),
        "report_size_chars": 0,
        "error": "Unsupported workspace language (no pom.xml / requirements.txt / package.json found)",
        "vulnerabilities_found": False,
        "scan_execution_error": True,
        "scanner_backend": "static",
        "language": "unknown",
        "critical_vulnerabilities": 0,
        "high_vulnerabilities": 0,
        "medium_vulnerabilities": 0,
        "low_vulnerabilities": 0,
        "total_vulnerabilities": 0,
        "remediation_targets": [],
        "affected_dependencies": [],
    }