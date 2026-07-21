"""Multi-language vulnerability scanner with static CVE fallback.

Supports monorepos — scans all subdirectories for different languages.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SEVERITY_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _version_key(version: str) -> list[tuple[int, int | str]]:
    tokens = re.findall(r"\d+|[A-Za-z]+", str(version))
    parsed: list[tuple[int, int | str]] = []
    for token in tokens:
        parsed.append((1, int(token)) if token.isdigit() else (0, token.lower()))
    return parsed


def _compare_versions(left: str | None, right: str | None) -> int:
    if left == right:
        return 0
    if not left:
        return -1
    if not right:
        return 1
    left_key, right_key = _version_key(left), _version_key(right)
    for i in range(max(len(left_key), len(right_key))):
        lt = left_key[i] if i < len(left_key) else (1, 0)
        rt = right_key[i] if i < len(right_key) else (1, 0)
        if lt != rt:
            return 1 if lt > rt else -1
    return 0


def _is_vulnerable(version: str, entry: dict[str, Any]) -> bool:
    if "vulnerable_below" in entry and _compare_versions(version, entry["vulnerable_below"]) < 0:
        return True
    for lower, upper in entry.get("vulnerable_ranges", []):
        if _compare_versions(version, lower) >= 0 and _compare_versions(version, upper) < 0:
            return True
    return False


# CVE Databases
PYTHON_CVE_DATABASE: dict[str, dict[str, Any]] = {
    "requests": {"cves": ["CVE-2023-32681"], "severity": "High", "vulnerable_below": "2.31.0", "fixed_version": "2.31.0", "fixed_candidates": ["2.31.0", "2.32.0"], "description": "Proxy-Authorization header leak"},
    "urllib3": {"cves": ["CVE-2023-43804", "CVE-2023-45803"], "severity": "High", "vulnerable_below": "1.26.18", "fixed_version": "1.26.18", "fixed_candidates": ["1.26.18", "2.0.7"], "description": "Cookie leak on redirect"},
    "cryptography": {"cves": ["CVE-2023-49083"], "severity": "High", "vulnerable_below": "41.0.6", "fixed_version": "41.0.6", "fixed_candidates": ["41.0.6", "42.0.0"], "description": "NULL signature forgery"},
    "pillow": {"cves": ["CVE-2023-50447"], "severity": "High", "vulnerable_below": "10.2.0", "fixed_version": "10.2.0", "fixed_candidates": ["10.2.0", "10.3.0"], "description": "RCE via crafted image"},
    "pyyaml": {"cves": ["CVE-2020-1747", "CVE-2020-14343"], "severity": "Critical", "vulnerable_below": "5.4", "fixed_version": "5.4", "fixed_candidates": ["5.4", "6.0"], "description": "RCE via unsafe YAML"},
    "jinja2": {"cves": ["CVE-2024-22195"], "severity": "Medium", "vulnerable_below": "3.1.3", "fixed_version": "3.1.3", "fixed_candidates": ["3.1.3", "3.1.4"], "description": "XSS via xmlattr"},
    "werkzeug": {"cves": ["CVE-2023-46136"], "severity": "Medium", "vulnerable_below": "3.0.1", "fixed_version": "3.0.1", "fixed_candidates": ["3.0.1", "3.0.3"], "description": "Multipart DoS"},
    "aiohttp": {"cves": ["CVE-2024-23334"], "severity": "High", "vulnerable_below": "3.9.2", "fixed_version": "3.9.2", "fixed_candidates": ["3.9.2", "3.9.3"], "description": "Directory traversal"},
    "setuptools": {"cves": ["CVE-2024-6345"], "severity": "High", "vulnerable_below": "70.0.0", "fixed_version": "70.0.0", "fixed_candidates": ["70.0.0"], "description": "RCE via package index"},
    "django": {"cves": ["CVE-2023-46695"], "severity": "High", "vulnerable_below": "4.2.7", "fixed_version": "4.2.7", "fixed_candidates": ["4.2.7", "4.2.16"], "description": "DoS via username"},
}

NODE_CVE_DATABASE: dict[str, dict[str, Any]] = {
    "lodash": {"cves": ["CVE-2021-23337"], "severity": "Critical", "vulnerable_below": "4.17.21", "fixed_version": "4.17.21", "fixed_candidates": ["4.17.21"], "description": "Prototype pollution"},
    "axios": {"cves": ["CVE-2023-45857"], "severity": "High", "vulnerable_below": "1.6.0", "fixed_version": "1.6.0", "fixed_candidates": ["1.6.0", "1.7.0"], "description": "CSRF token leak"},
    "express": {"cves": ["CVE-2024-29041"], "severity": "Medium", "vulnerable_below": "4.19.2", "fixed_version": "4.19.2", "fixed_candidates": ["4.19.2"], "description": "Open redirect"},
    "minimatch": {"cves": ["CVE-2022-3517"], "severity": "High", "vulnerable_below": "3.0.5", "fixed_version": "3.0.5", "fixed_candidates": ["3.0.5"], "description": "ReDoS"},
    "handlebars": {"cves": ["CVE-2023-26136"], "severity": "Critical", "vulnerable_below": "4.7.7", "fixed_version": "4.7.7", "fixed_candidates": ["4.7.7"], "description": "Prototype pollution RCE"},
    "qs": {"cves": ["CVE-2022-24999"], "severity": "High", "vulnerable_below": "6.5.3", "fixed_version": "6.5.3", "fixed_candidates": ["6.5.3"], "description": "Prototype pollution"},
    "moment": {"cves": ["CVE-2022-31129"], "severity": "High", "vulnerable_below": "2.29.4", "fixed_version": "2.29.4", "fixed_candidates": ["2.29.4"], "description": "ReDoS"},
    "ws": {"cves": ["CVE-2024-37890"], "severity": "High", "vulnerable_below": "8.17.1", "fixed_version": "8.17.1", "fixed_candidates": ["8.17.1"], "description": "DoS via upgrade"},
    "jsonwebtoken": {"cves": ["CVE-2022-23529"], "severity": "Critical", "vulnerable_below": "9.0.0", "fixed_version": "9.0.0", "fixed_candidates": ["9.0.0"], "description": "Algorithm confusion"},
    "node-forge": {"cves": ["CVE-2022-24771"], "severity": "Critical", "vulnerable_below": "1.3.1", "fixed_version": "1.3.1", "fixed_candidates": ["1.3.1"], "description": "Prototype pollution"},
}

SKIP_DIRS = {".", "..", ".git", ".venv", "venv", "node_modules", "__pycache__", "target", ".adk_artifacts", ".idea", ".vscode"}


def detect_language(workspace_url: str) -> str:
    """Detect language from root OR one level deep (monorepo support)."""
    workspace = Path(workspace_url)
    for d in [workspace] + [s for s in workspace.iterdir() if s.is_dir() and s.name not in SKIP_DIRS]:
        if (d / "pom.xml").exists() or (d / "build.gradle").exists():
            return "java"
        if (d / "requirements.txt").exists() or (d / "pyproject.toml").exists():
            return "python"
        if (d / "package.json").exists():
            return "nodejs"
    return "unknown"


def _detect_all_services(workspace_url: str) -> list[tuple[str, Path]]:
    """Find all (language, dir) services in a workspace (monorepo)."""
    workspace = Path(workspace_url)
    services: list[tuple[str, Path]] = []
    for d in [workspace] + [s for s in workspace.iterdir() if s.is_dir() and s.name not in SKIP_DIRS]:
        if (d / "pom.xml").exists() or (d / "build.gradle").exists():
            services.append(("java", d))
        if (d / "requirements.txt").exists() or (d / "pyproject.toml").exists():
            services.append(("python", d))
        if (d / "package.json").exists():
            services.append(("nodejs", d))
    return services


def _parse_requirements(path: Path) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    if not path.exists():
        return deps
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=~<>!]+\s*([0-9A-Za-z.\-]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#")[0].strip()
        if line:
            m = pattern.match(line)
            if m:
                deps.append((m.group(1).lower(), m.group(2)))
    return deps


def _scan_python(workspace_url: str) -> list[dict[str, Any]]:
    workspace = Path(workspace_url)
    deps = _parse_requirements(workspace / "requirements.txt")
    findings: list[dict[str, Any]] = []
    for name, version in deps:
        entry = PYTHON_CVE_DATABASE.get(name)
        if entry and _is_vulnerable(version, entry):
            findings.append({"severity": entry["severity"], "groupId": "pypi", "artifactId": name, "current_version": version, "fixed_version": entry["fixed_version"], "fixed_candidates": entry.get("fixed_candidates", [entry["fixed_version"]]), "cves": entry["cves"], "summary": f"{name} {version} -> {entry['fixed_version']}"})
    return findings


def _scan_nodejs(workspace_url: str) -> list[dict[str, Any]]:
    workspace = Path(workspace_url)
    pkg_path = workspace / "package.json"
    deps: dict[str, str] = {}
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
            for section in ("dependencies", "devDependencies"):
                deps.update({k.lower().lstrip("@"): v.lstrip("^~>=< ") for k, v in (pkg.get(section) or {}).items()})
        except json.JSONDecodeError:
            pass
    findings: list[dict[str, Any]] = []
    for name, version in deps.items():
        entry = NODE_CVE_DATABASE.get(name)
        if entry and _is_vulnerable(version, entry):
            findings.append({"severity": entry["severity"], "groupId": "npm", "artifactId": name, "current_version": version, "fixed_version": entry["fixed_version"], "fixed_candidates": entry.get("fixed_candidates", [entry["fixed_version"]]), "cves": entry["cves"], "summary": f"{name} {version} -> {entry['fixed_version']}"})
    return findings


def _scan_java(workspace_url: str) -> list[dict[str, Any]]:
    """Java scanner — parses pom.xml for vulnerable dependencies."""
    workspace = Path(workspace_url)
    pom_path = workspace / "pom.xml"
    if not pom_path.exists():
        return []

    # Java CVE database (keyed by artifactId)
    JAVA_CVE_DB: dict[str, dict[str, Any]] = {
        "log4j-core": {"cves": ["CVE-2021-44228"], "severity": "Critical", "vulnerable_below": "2.17.1", "fixed_version": "2.17.1", "fixed_candidates": ["2.17.1", "2.20.0"], "groupId": "org.apache.logging.log4j"},
        "commons-text": {"cves": ["CVE-2022-42889"], "severity": "Critical", "vulnerable_below": "1.10.0", "fixed_version": "1.10.0", "fixed_candidates": ["1.10.0"], "groupId": "org.apache.commons"},
        "jackson-databind": {"cves": ["CVE-2022-42003"], "severity": "Critical", "vulnerable_below": "2.14.0", "fixed_version": "2.14.0", "fixed_candidates": ["2.14.0", "2.15.0"], "groupId": "com.fasterxml.jackson.core"},
        "snakeyaml": {"cves": ["CVE-2022-1471"], "severity": "Critical", "vulnerable_below": "1.32", "fixed_version": "1.33", "fixed_candidates": ["1.33", "2.0"], "groupId": "org.yaml"},
        "commons-io": {"cves": ["CVE-2021-29425"], "severity": "High", "vulnerable_below": "2.7", "fixed_version": "2.7", "fixed_candidates": ["2.7", "2.11.0"], "groupId": "commons-io"},
        "dom4j": {"cves": ["CVE-2020-10683"], "severity": "Critical", "vulnerable_below": "2.1.3", "fixed_version": "2.1.3", "fixed_candidates": ["2.1.3"], "groupId": "org.dom4j"},
        "guava": {"cves": ["CVE-2020-8908"], "severity": "High", "vulnerable_below": "30.0-jre", "fixed_version": "30.0-jre", "fixed_candidates": ["30.0-jre", "32.0.0-jre"], "groupId": "com.google.guava"},
        "xstream": {"cves": ["CVE-2021-21351"], "severity": "Critical", "vulnerable_below": "1.4.18", "fixed_version": "1.4.18", "fixed_candidates": ["1.4.18", "1.4.20"], "groupId": "com.thoughtworks.xstream"},
        "commons-compress": {"cves": ["CVE-2021-35515"], "severity": "High", "vulnerable_below": "1.21", "fixed_version": "1.21", "fixed_candidates": ["1.21", "1.23.0"], "groupId": "org.apache.commons"},
    }

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
    except ET.ParseError:
        return []

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    findings: list[dict[str, Any]] = []
    for dep in root.iter(f"{ns}dependency"):
        gid_el = dep.find(f"{ns}groupId")
        aid_el = dep.find(f"{ns}artifactId")
        ver_el = dep.find(f"{ns}version")
        if gid_el is None or aid_el is None or ver_el is None:
            continue
        artifact_id = aid_el.text or ""
        version = (ver_el.text or "").strip()
        entry = JAVA_CVE_DB.get(artifact_id)
        if entry and _is_vulnerable(version, entry):
            findings.append({
                "severity": entry["severity"], "groupId": entry["groupId"], "artifactId": artifact_id,
                "current_version": version, "fixed_version": entry["fixed_version"],
                "fixed_candidates": entry.get("fixed_candidates", [entry["fixed_version"]]),
                "cves": entry["cves"], "summary": f"{artifact_id} {version} -> {entry['fixed_version']}",
            })
    return findings


def _build_result(findings: list[dict], report_path: Path, report_text: str, language: str, backend: str) -> dict[str, Any]:
    targets = _build_remediation_targets(findings)
    affected = sorted({f"{f['groupId']}:{f['artifactId']}" for f in findings})
    return {
        "status": "success", "return_code": 0, "report_path": str(report_path), "report_size_chars": len(report_text),
        "error": "", "vulnerabilities_found": len(findings) > 0, "scan_execution_error": False, "scanner_backend": backend,
        "language": language,
        "critical_vulnerabilities": sum(1 for f in findings if f["severity"] == "Critical"),
        "high_vulnerabilities": sum(1 for f in findings if f["severity"] == "High"),
        "medium_vulnerabilities": sum(1 for f in findings if f["severity"] == "Medium"),
        "low_vulnerabilities": sum(1 for f in findings if f["severity"] == "Low"),
        "total_vulnerabilities": len(findings),
        "remediation_targets": targets, "affected_dependencies": affected,
    }


def _build_remediation_targets(findings: list[dict]) -> list[dict]:
    aggregated: dict[tuple, dict] = {}
    for f in findings:
        sev = f.get("severity")
        if sev not in SEVERITY_PRIORITY:
            continue
        key = (f["groupId"], f["artifactId"], f.get("current_version"))
        if key not in aggregated:
            aggregated[key] = {"dependency": f["artifactId"] if f["groupId"] in ("pypi", "npm") else f"{f['groupId']}:{f['artifactId']}", "groupId": f["groupId"], "artifactId": f["artifactId"], "current_version": f.get("current_version"), "fixed_candidates": [], "highest_severity": sev, "cves": []}
        t = aggregated[key]
        if SEVERITY_PRIORITY[sev] < SEVERITY_PRIORITY.get(t["highest_severity"], 99):
            t["highest_severity"] = sev
        t["fixed_candidates"].extend(f.get("fixed_candidates", []))
        t["cves"] = sorted(set(t["cves"] + f.get("cves", [])))
    targets = []
    for t in aggregated.values():
        candidates = sorted(set(t["fixed_candidates"]), key=_version_key)
        targets.append({"dependency": t["dependency"], "groupId": t["groupId"], "artifactId": t["artifactId"], "current_version": t["current_version"], "fixed_version": candidates[0] if candidates else None, "fixed_candidates": candidates, "highest_severity": t["highest_severity"], "cves": t["cves"], "summary": f"{t['dependency']} {t['current_version'] or ''} -> {candidates[0] if candidates else 'unknown'}".strip()})
    targets.sort(key=lambda x: (SEVERITY_PRIORITY.get(x.get("highest_severity"), 99), x["dependency"]))
    return targets


def scan_workspace_multi(workspace_url: str) -> dict[str, Any]:
    """Scan a workspace — supports monorepos with multiple languages."""
    services = _detect_all_services(workspace_url)

    if not services:
        workspace = Path(workspace_url)
        artifact_dir = workspace / ".adk_artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        report_path = artifact_dir / "scan_latest.txt"
        report_path.write_text(f"No pom.xml, requirements.txt, or package.json found in {workspace_url}\n", encoding="utf-8")
        return {"status": "error", "return_code": 1, "report_path": str(report_path), "report_size_chars": 0, "error": "No supported project files found", "vulnerabilities_found": False, "scan_execution_error": True, "scanner_backend": "static", "language": "unknown", "critical_vulnerabilities": 0, "high_vulnerabilities": 0, "medium_vulnerabilities": 0, "low_vulnerabilities": 0, "total_vulnerabilities": 0, "remediation_targets": [], "affected_dependencies": []}

    # Scan each service and merge findings
    all_findings: list[dict[str, Any]] = []
    languages_found: list[str] = []
    report_lines = ["=" * 80, "MULTI-LANGUAGE SCAN (Offline CVE Database)", "=" * 80, f"Workspace: {workspace_url}", f"Services: {len(services)}", ""]

    for lang, svc_dir in services:
        if lang == "java":
            findings = _scan_java(str(svc_dir))
        elif lang == "python":
            findings = _scan_python(str(svc_dir))
        elif lang == "nodejs":
            findings = _scan_nodejs(str(svc_dir))
        else:
            continue
        languages_found.append(lang)
        all_findings.extend(findings)
        report_lines.append(f"--- {lang} ({svc_dir.name}): {len(findings)} vulns ---")

    workspace = Path(workspace_url)
    artifact_dir = workspace / ".adk_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "scan_latest.txt"
    report_text = "\n".join(report_lines + ["", f"TOTAL: {len(all_findings)} vulnerabilities", "=" * 80])
    report_path.write_text(report_text, encoding="utf-8")

    return _build_result(all_findings, report_path, report_text, "+".join(languages_found) or "mixed", "static")