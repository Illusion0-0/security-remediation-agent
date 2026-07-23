"""Multi-language vulnerability scanner using OSV.dev API.

Replaces the hardcoded CVE database with real-time vulnerability data from
Google's OSV.dev (https://osv.dev) — a free, open-source vulnerability database.

Supports:
  - Java/Maven (pom.xml)
  - Python/PyPI (requirements.txt)
  - Node.js/npm (package.json)
  - Monorepos (scans subdirectories)

The OSV.dev API is free, requires no API key, and covers all major ecosystems.
"""
from __future__ import annotations

import json
import re
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SEVERITY_PRIORITY = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}
SEVERITY_DISPLAY = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "target", ".adk_artifacts", ".idea", ".vscode", ".mvn"}


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def _version_key(version: str) -> list[tuple[int, int | str]]:
    tokens = re.findall(r"\d+|[A-Za-z]+", str(version))
    parsed: list[tuple[int, int | str]] = []
    for token in tokens:
        parsed.append((1, int(token)) if token.isdigit() else (0, token.lower()))
    return parsed


def _compare_versions(left: str, right: str) -> int:
    if left == right:
        return 0
    lk, rk = _version_key(left), _version_key(right)
    for i in range(max(len(lk), len(rk))):
        lt = lk[i] if i < len(lk) else (1, 0)
        rt = rk[i] if i < len(rk) else (1, 0)
        if lt != rt:
            return 1 if lt > rt else -1
    return 0


def _is_affected(version: str, affected_entry: dict) -> bool:
    """Check if a version is affected by an OSV vulnerability entry."""
    ranges = affected_entry.get("ranges", [])
    for r in ranges:
        if r.get("type") == "ECOSYSTEM":
            for event in r.get("events", []):
                introduced = event.get("introduced")
                fixed = event.get("fixed")
                if introduced and _compare_versions(version, introduced) >= 0:
                    if not fixed or _compare_versions(version, fixed) < 0:
                        return True
        elif r.get("type") == "SEMVER":
            for event in r.get("events", []):
                introduced = event.get("introduced")
                fixed = event.get("fixed")
                if introduced and _compare_versions(version, introduced) >= 0:
                    if not fixed or _compare_versions(version, fixed) < 0:
                        return True
    # Also check explicit version lists
    versions = affected_entry.get("versions", [])
    if version in versions:
        return True
    return False


# ---------------------------------------------------------------------------
# Dependency file parsers
# ---------------------------------------------------------------------------

def _parse_pom_xml(pom_path: Path) -> list[dict[str, str]]:
    """Parse pom.xml → list of {name, version, ecosystem: 'Maven'}."""
    deps: list[dict[str, str]] = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
    except ET.ParseError:
        return deps

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # Extract parent version for property resolution
    parent_version = ""
    parent = root.find(f"{ns}parent")
    if parent is not None:
        pv = parent.find(f"{ns}version")
        if pv is not None and pv.text:
            parent_version = pv.text.strip()

    # Collect properties
    props: dict[str, str] = {}
    props_el = root.find(f"{ns}properties")
    if props_el is not None:
        for child in props_el:
            tag = child.tag.replace(ns, "")
            if child.text:
                props[tag] = child.text.strip()

    for dep in root.iter(f"{ns}dependency"):
        gid_el = dep.find(f"{ns}groupId")
        aid_el = dep.find(f"{ns}artifactId")
        ver_el = dep.find(f"{ns}version")
        if gid_el is None or aid_el is None:
            continue
        gid = (gid_el.text or "").strip()
        aid = (aid_el.text or "").strip()
        ver = (ver_el.text or "").strip() if ver_el is not None else ""

        # Resolve ${propertyName} references
        if ver.startswith("${") and ver.endswith("}"):
            prop_key = ver[2:-1]
            ver = props.get(prop_key, parent_version)

        if gid and aid and ver:
            deps.append({"package": f"{gid}:{aid}", "version": ver, "ecosystem": "Maven"})

    return deps


def _parse_requirements(path: Path) -> list[dict[str, str]]:
    """Parse requirements.txt → list of {name, version, ecosystem: 'PyPI'}."""
    deps: list[dict[str, str]] = []
    if not path.exists():
        return deps
    pattern = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[=~<>!]+\s*([0-9A-Za-z.\-+]+)")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        m = pattern.match(line)
        if m:
            deps.append({"package": m.group(1), "version": m.group(2), "ecosystem": "PyPI"})
    return deps


def _parse_package_json(path: Path) -> list[dict[str, str]]:
    """Parse package.json → list of {name, version, ecosystem: 'npm'}."""
    deps: list[dict[str, str]] = []
    if not path.exists():
        return deps
    try:
        pkg = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in (pkg.get(section) or {}).items():
            clean_ver = re.sub(r"^[^0-9]*", "", version.strip())
            if clean_ver:
                deps.append({"package": name, "version": clean_ver, "ecosystem": "npm"})
    return deps


# ---------------------------------------------------------------------------
# OSV.dev API
# ---------------------------------------------------------------------------

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _query_osv_batch(packages: list[dict[str, str]]) -> dict[str, list[dict]]:
    """Batch-query OSV.dev for vulnerabilities.

    Returns a dict mapping "package@version" → list of vulnerability entries.
    """
    if not packages:
        return {}

    # Build batch queries
    queries: list[dict] = []
    for pkg in packages:
        queries.append({
            "version": pkg["version"],
            "package": {"name": pkg["package"], "ecosystem": pkg["ecosystem"]},
        })

    # OSV batch API has a limit — chunk into groups of 100
    results: dict[str, list[dict]] = {}
    for i in range(0, len(queries), 100):
        chunk = queries[i:i + 100]
        batch_request = {"queries": chunk}

        try:
            data = json.dumps(batch_request).encode("utf-8")
            req = urllib.request.Request(OSV_BATCH_URL, data=data, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch_resp = json.loads(resp.read().decode("utf-8"))

            for j, result in enumerate(batch_resp.get("results", [])):
                pkg = packages[i + j]
                key = f"{pkg['package']}@{pkg['version']}"
                vuln_ids = result.get("vulns", [])
                if vuln_ids:
                    results[key] = vuln_ids
        except Exception:
            # Fallback: query individually
            for pkg in packages[i:i + 100]:
                key = f"{pkg['package']}@{pkg['version']}"
                try:
                    query = {"version": pkg["version"], "package": {"name": pkg["package"], "ecosystem": pkg["ecosystem"]}}
                    data = json.dumps(query).encode("utf-8")
                    req = urllib.request.Request(OSV_QUERY_URL, data=data, headers={"Content-Type": "application/json"})
                    with urllib.request.urlopen(req, timeout=15) as resp:
                        query_resp = json.loads(resp.read().decode("utf-8"))
                    if query_resp.get("vulns"):
                        results[key] = query_resp["vulns"]
                except Exception:
                    pass

    return results


def _fetch_vuln_detail(vuln_id: str) -> dict | None:
    """Fetch full vulnerability details from OSV.dev."""
    url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _extract_severity(vuln: dict) -> str:
    """Extract the highest severity from an OSV vulnerability entry."""
    severity_list = vuln.get("severity", [])
    best = "LOW"
    for sev in severity_list:
        score_str = sev.get("score", "")
        # CVSS vector string: extract severity from text
        for level in ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"]:
            if level in score_str.upper():
                if SEVERITY_PRIORITY.get(level, 99) < SEVERITY_PRIORITY.get(best, 99):
                    best = level
                break
    # Also check database_specific for severity
    db_specific = vuln.get("database_specific", {})
    if "severity" in db_specific:
        sev = db_specific["severity"].upper()
        if SEVERITY_PRIORITY.get(sev, 99) < SEVERITY_PRIORITY.get(best, 99):
            best = sev
    return SEVERITY_DISPLAY.get(best, "Medium")


def _extract_fixed_version(vuln: dict, package_name: str, ecosystem: str) -> str | None:
    """Extract the fixed version from an OSV vulnerability entry."""
    for affected in vuln.get("affected", []):
        pkg_info = affected.get("package", {})
        if pkg_info.get("name", "").lower() == package_name.lower() and pkg_info.get("ecosystem") == ecosystem:
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


# ---------------------------------------------------------------------------
# Language detection (monorepo support)
# ---------------------------------------------------------------------------

def detect_language(workspace_url: str) -> str:
    """Detect language from root or subdirectories."""
    workspace = Path(workspace_url)
    for d in [workspace] + [s for s in workspace.iterdir() if s.is_dir() and s.name not in SKIP_DIRS]:
        if (d / "pom.xml").exists():
            return "java"
        if (d / "requirements.txt").exists():
            return "python"
        if (d / "package.json").exists():
            return "nodejs"
    return "unknown"


def _detect_all_services(workspace_url: str) -> list[tuple[str, Path]]:
    """Find all (language, dir) services in a workspace (monorepo)."""
    workspace = Path(workspace_url)
    services: list[tuple[str, Path]] = []
    for d in [workspace] + [s for s in workspace.iterdir() if s.is_dir() and s.name not in SKIP_DIRS]:
        if (d / "pom.xml").exists():
            services.append(("java", d))
        if (d / "requirements.txt").exists():
            services.append(("python", d))
        if (d / "package.json").exists():
            services.append(("nodejs", d))
    return services


# ---------------------------------------------------------------------------
# Scanner entry point
# ---------------------------------------------------------------------------

def scan_workspace_multi(workspace_url: str, languages: list[str] | None = None) -> dict[str, Any]:
    """Scan a workspace for vulnerabilities using OSV.dev API.

    Parses dependency files, queries OSV.dev for real CVE data,
    and returns findings in the same format as the previous scanner.
    """
    all_services = _detect_all_services(workspace_url)
    # Filter services by selected languages
    if languages:
        lang_map = {"java": "java", "python": "python", "nodejs": "nodejs"}
        services = [(lang, d) for lang, d in all_services if lang in (languages or [])]
    else:
        services = all_services

    if not services:
        workspace = Path(workspace_url)
        artifact_dir = workspace / ".adk_artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        report_path = artifact_dir / "scan_latest.txt"
        report_path.write_text(f"No pom.xml, requirements.txt, or package.json found in {workspace_url}\n", encoding="utf-8")
        return {
            "status": "error", "return_code": 1, "report_path": str(report_path), "report_size_chars": 0,
            "error": "No supported project files found", "vulnerabilities_found": False, "scan_execution_error": True,
            "scanner_backend": "osv", "language": "unknown",
            "critical_vulnerabilities": 0, "high_vulnerabilities": 0, "medium_vulnerabilities": 0, "low_vulnerabilities": 0,
            "total_vulnerabilities": 0, "remediation_targets": [], "affected_dependencies": [],
        }

    # Collect all dependencies across services
    all_deps: list[dict[str, str]] = []
    report_lines = ["=" * 80, "OSV.DEV VULNERABILITY SCAN (Live API)", "=" * 80, f"Workspace: {workspace_url}", f"Services: {len(services)}", ""]

    for lang, svc_dir in services:
        deps: list[dict[str, str]] = []
        if lang == "java":
            deps = _parse_pom_xml(svc_dir / "pom.xml")
        elif lang == "python":
            deps = _parse_requirements(svc_dir / "requirements.txt")
        elif lang == "nodejs":
            deps = _parse_package_json(svc_dir / "package.json")

        for d in deps:
            d["service_dir"] = svc_dir.name
            d["language"] = lang
        all_deps.extend(deps)
        report_lines.append(f"  {lang} ({svc_dir.name}): {len(deps)} dependencies")

    report_lines.append(f"\n  Total dependencies: {len(all_deps)}")
    report_lines.append("\n  Querying OSV.dev for vulnerabilities...")

    # Query OSV.dev
    vuln_results = _query_osv_batch(all_deps)

    # Build findings
    findings: list[dict[str, Any]] = []
    processed_vulns: set[str] = set()

    for pkg in all_deps:
        key = f"{pkg['package']}@{pkg['version']}"
        vulns = vuln_results.get(key, [])

        if not vulns:
            report_lines.append(f"  OK     [{pkg['ecosystem']}] {pkg['package']}@{pkg['version']}")
            continue

        for vuln_ref in vulns:
            vuln_id = vuln_ref.get("id", "")
            if not vuln_id or vuln_id in processed_vulns:
                continue
            # Only process once per (package, vuln) pair
            pair_key = f"{pkg['package']}:{vuln_id}"
            if pair_key in processed_vulns:
                continue
            processed_vulns.add(pair_key)

            # Fetch full details
            detail = _fetch_vuln_detail(vuln_id)
            if not detail:
                continue

            severity = _extract_severity(detail)
            fixed = _extract_fixed_version(detail, pkg["package"], pkg["ecosystem"])

            # Check if this version is actually affected
            is_affected = False
            for aff in detail.get("affected", []):
                pi = aff.get("package", {})
                if pi.get("name", "").lower() == pkg["package"].lower() and pi.get("ecosystem") == pkg["ecosystem"]:
                    if _is_affected(pkg["version"], aff):
                        is_affected = True
                        break

            if not is_affected:
                continue

            summary = detail.get("summary", detail.get("details", "")[:100])
            cve_aliases = [a for a in detail.get("aliases", []) if a.startswith("CVE")]
            cve = cve_aliases[0] if cve_aliases else vuln_id

            report_lines.append(f"  VULN   [{severity}] {pkg['package']}@{pkg['version']} -> {fixed or '?'} | {cve}")

            # Determine groupId/artifactId
            if pkg["ecosystem"] == "Maven":
                parts = pkg["package"].split(":")
                group_id = parts[0] if len(parts) == 2 else ""
                artifact_id = parts[1] if len(parts) == 2 else pkg["package"]
            else:
                group_id = pkg["ecosystem"].lower()
                artifact_id = pkg["package"]

            findings.append({
                "severity": severity,
                "groupId": group_id,
                "artifactId": artifact_id,
                "current_version": pkg["version"],
                "fixed_version": fixed,
                "fixed_candidates": [fixed] if fixed else [],
                "cves": [cve],
                "summary": f"{pkg['package']} {pkg['version']} -> {fixed or 'unknown'}: {summary[:80]}",
                "service_dir": pkg.get("service_dir", ""),
                "language": pkg.get("language", ""),
            })

    # Build result
    workspace = Path(workspace_url)
    artifact_dir = workspace / ".adk_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "scan_latest.txt"
    report_text = "\n".join(report_lines + ["", f"TOTAL: {len(findings)} vulnerabilities found", "=" * 80])
    report_path.write_text(report_text, encoding="utf-8")

    return _build_result(findings, report_path, report_text, "+".join(set(d.get("language", "") for d in all_deps)) or "mixed", "osv")


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
        sev = f.get("severity", "Medium").upper()
        sev_norm = SEVERITY_DISPLAY.get(sev, sev.title())
        key = (f["groupId"], f["artifactId"], f.get("current_version"))
        if key not in aggregated:
            dep_name = f["artifactId"] if f["groupId"] in ("pypi", "npm") else f"{f['groupId']}:{f['artifactId']}"
            aggregated[key] = {"dependency": dep_name, "groupId": f["groupId"], "artifactId": f["artifactId"], "current_version": f.get("current_version"), "fixed_candidates": [], "highest_severity": sev_norm, "cves": []}
        t = aggregated[key]
        if SEVERITY_PRIORITY.get(sev, 99) < SEVERITY_PRIORITY.get(t["highest_severity"].upper(), 99):
            t["highest_severity"] = sev_norm
        t["fixed_candidates"].extend(f.get("fixed_candidates", []))
        t["cves"] = sorted(set(t["cves"] + f.get("cves", [])))

    targets = []
    for t in aggregated.values():
        candidates = sorted(set(filter(None, t["fixed_candidates"])), key=_version_key)
        targets.append({
            "dependency": t["dependency"], "groupId": t["groupId"], "artifactId": t["artifactId"],
            "current_version": t["current_version"], "fixed_version": candidates[0] if candidates else None,
            "fixed_candidates": candidates, "highest_severity": t["highest_severity"], "cves": t["cves"],
            "summary": f"{t['dependency']} {t['current_version'] or ''} -> {candidates[0] if candidates else 'unknown'}".strip(),
        })
    targets.sort(key=lambda x: (SEVERITY_PRIORITY.get(x.get("highest_severity", "Medium").upper(), 99), x["dependency"]))
    return targets