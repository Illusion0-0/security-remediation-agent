"""
Static CVE scanner for Java Maven projects.

This module provides offline vulnerability detection by parsing pom.xml dependencies
and matching them against a curated static CVE database. It serves as a zero-dependency
fallback when JFrog CLI (jf audit) is unavailable, ensuring the remediation pipeline
works end-to-end in any environment (hackathon demo, CI, offline).

The output format is identical to run_jf_audit_scan so the rest of the pipeline
(scanner agent, fixer agent, api_server) requires no changes.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Static CVE Database
# ---------------------------------------------------------------------------
# Each entry maps a Maven coordinate (groupId:artifactId) to known-vulnerable
# version ranges and their fixed versions + CVE references.
#
# Version matching:
#   - "vulnerable_below": any version strictly below this is vulnerable
#   - "vulnerable_ranges": explicit [inclusive_lower, exclusive_upper) ranges
#   - "fixed_version": the recommended remediation target
#
# This database covers the most impactful Java CVEs for demo/educational use.
# ---------------------------------------------------------------------------

STATIC_CVE_DATABASE: dict[str, dict[str, Any]] = {
    "log4j:log4j": {
        "cves": ["CVE-2021-44228"],
        "severity": "Critical",
        "vulnerable_below": "2.17.1",
        "fixed_version": "2.17.1",
        "fixed_candidates": ["2.17.2", "2.18.0", "2.20.0"],
        "description": "Log4Shell - Remote Code Execution via JNDI lookup",
    },
    "org.apache.logging.log4j:log4j-core": {
        "cves": ["CVE-2021-44228", "CVE-2021-45046"],
        "severity": "Critical",
        "vulnerable_below": "2.17.1",
        "fixed_version": "2.17.1",
        "fixed_candidates": ["2.17.2", "2.18.0", "2.20.0", "2.22.0"],
        "description": "Log4Shell - Remote Code Execution via JNDI lookup",
    },
    "org.apache.logging.log4j:log4j-api": {
        "cves": ["CVE-2021-44228"],
        "severity": "Critical",
        "vulnerable_below": "2.17.1",
        "fixed_version": "2.17.1",
        "fixed_candidates": ["2.17.2", "2.18.0", "2.20.0"],
        "description": "Log4Shell - companion API module vulnerability",
    },
    "org.apache.commons:commons-text": {
        "cves": ["CVE-2022-42889"],
        "severity": "Critical",
        "vulnerable_below": "1.10.0",
        "fixed_version": "1.10.0",
        "fixed_candidates": ["1.10.0", "1.11.0", "1.12.0"],
        "description": "Text4Shell - RCE via StringSubstitutor lookup",
    },
    "com.fasterxml.jackson.core:jackson-databind": {
        "cves": ["CVE-2020-36518", "CVE-2022-42003", "CVE-2022-42004"],
        "severity": "High",
        "vulnerable_below": "2.14.0",
        "fixed_version": "2.14.0",
        "fixed_candidates": ["2.14.0", "2.14.3", "2.15.4", "2.16.1", "2.17.0"],
        "description": "Denial of service via deeply nested objects",
    },
    "org.yaml:snakeyaml": {
        "cves": ["CVE-2022-1471"],
        "severity": "Critical",
        "vulnerable_below": "2.0",
        "fixed_version": "2.0",
        "fixed_candidates": ["2.0", "2.1", "2.2"],
        "description": "Unsafe deserialization leading to RCE via SnakeYAML Constructor",
    },
    "commons-io:commons-io": {
        "cves": ["CVE-2021-29425"],
        "severity": "High",
        "vulnerable_below": "2.7.0",
        "fixed_version": "2.7.0",
        "fixed_candidates": ["2.7.0", "2.11.0", "2.15.1"],
        "description": "Path traversal via XmlStreamReader",
    },
    "org.dom4j:dom4j": {
        "cves": ["CVE-2020-10683"],
        "severity": "Critical",
        "vulnerable_below": "2.1.3",
        "fixed_version": "2.1.3",
        "fixed_candidates": ["2.1.3", "2.1.4"],
        "description": "XXE vulnerability allowing information disclosure",
    },
    "com.google.guava:guava": {
        "cves": ["CVE-2020-8908"],
        "severity": "Medium",
        "vulnerable_below": "30.0-jre",
        "fixed_version": "30.0-jre",
        "fixed_candidates": ["30.0-jre", "31.1-jre", "32.0.0-jre", "32.1.3-jre"],
        "description": "Temp directory permissions weakness",
    },
    "org.springframework:spring-core": {
        "cves": ["CVE-2022-22965"],
        "severity": "Critical",
        "vulnerable_ranges": [["5.3.0", "5.3.17"], ["5.2.0", "5.2.19"]],
        "fixed_version": "5.3.18",
        "fixed_candidates": ["5.3.18", "5.3.20", "5.3.31", "5.3.34"],
        "description": "Spring4Shell - RCE via data binding on JDK 9+",
    },
    "com.thoughtworks.xstream:xstream": {
        "cves": ["CVE-2021-21351"],
        "severity": "Critical",
        "vulnerable_below": "1.4.18",
        "fixed_version": "1.4.18",
        "fixed_candidates": ["1.4.18", "1.4.19", "1.4.20", "1.4.21"],
        "description": "XSS/RCE via deserialization of crafted XML",
    },
    "commons-fileupload:commons-fileupload": {
        "cves": ["CVE-2023-24998"],
        "severity": "High",
        "vulnerable_below": "1.5",
        "fixed_version": "1.5",
        "fixed_candidates": ["1.5"],
        "description": "Denial of service via excessive request parts",
    },
    "org.apache.commons:commons-compress": {
        "cves": ["CVE-2021-35515", "CVE-2021-36090"],
        "severity": "High",
        "vulnerable_below": "1.21",
        "fixed_version": "1.21",
        "fixed_candidates": ["1.21", "1.23", "1.24.0", "1.26.1"],
        "description": "Denial of service via crafted archive files",
    },
    "com.netflix.hystrix:hystrix-core": {
        "cves": ["CVE-2021-39068"],
        "severity": "High",
        "vulnerable_below": "1.5.18",
        "fixed_version": "1.5.18",
        "fixed_candidates": ["1.5.18"],
        "description": "Information disclosure via serialization gadgets",
    },
}

SEVERITY_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _version_key(version: str) -> list[tuple[int, int | str]]:
    tokens = re.findall(r"\d+|[A-Za-z]+", version)
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


def _parse_pom_dependencies(pom_path: Path) -> list[dict[str, str]]:
    """Parse pom.xml and return all dependencies with their versions.

    Handles:
    - Direct dependencies
    - dependencyManagement section
    - Parent POM version (for spring-boot-starter-parent)
    - Property placeholders (${...}) with basic resolution
    """
    dependencies: list[dict[str, str]] = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
    except ET.ParseError:
        return dependencies

    namespace_match = re.match(r"\{(.+)\}", root.tag)
    namespace = namespace_match.group(1) if namespace_match else ""

    def qname(tag: str) -> str:
        return f"{{{namespace}}}{tag}" if namespace else tag

    # Collect properties for placeholder resolution
    properties: dict[str, str] = {}
    props_section = root.find(qname("properties"))
    if props_section is not None:
        for prop in props_section:
            tag_name = prop.tag.split("}")[-1] if "}" in prop.tag else prop.tag
            properties[tag_name] = (prop.text or "").strip()

    def resolve_version(raw_version: str | None) -> str | None:
        if not raw_version:
            return None
        resolved = raw_version.strip()
        prop_match = re.match(r"\$\{(.+?)}", resolved)
        if prop_match:
            prop_name = prop_match.group(1)
            return properties.get(prop_name, resolved)
        return resolved

    # Parent POM
    parent = root.find(qname("parent"))
    if parent is not None:
        gid = parent.find(qname("groupId"))
        aid = parent.find(qname("artifactId"))
        ver = parent.find(qname("version"))
        if gid is not None and aid is not None:
            dependencies.append({
                "groupId": (gid.text or "").strip(),
                "artifactId": (aid.text or "").strip(),
                "version": resolve_version(ver.text if ver is not None else None) or "",
                "section": "parent",
            })

    # Direct dependencies (identify whether each <dependencies> block sits inside <dependencyManagement>)
    dep_mgmt_parent = root.find(qname("dependencyManagement"))
    dep_mgmt_deps_section = dep_mgmt_parent.find(qname("dependencies")) if dep_mgmt_parent is not None else None
    for deps_section in root.findall(f".//{qname('dependencies')}"):
        section_name = "dependencyManagement" if deps_section is dep_mgmt_deps_section else "dependencies"
        for dep in deps_section.findall(qname("dependency")):
            gid = dep.find(qname("groupId"))
            aid = dep.find(qname("artifactId"))
            ver = dep.find(qname("version"))
            if gid is not None and aid is not None:
                group = (gid.text or "").strip()
                artifact = (aid.text or "").strip()
                version = resolve_version(ver.text if ver is not None else None) or ""
                if version or section_name == "dependencies":
                    dependencies.append({
                        "groupId": group,
                        "artifactId": artifact,
                        "version": version,
                        "section": section_name,
                    })

    return dependencies


def _build_remediation_targets(findings: list[dict]) -> list[dict]:
    aggregated: dict[tuple[str, str, str | None], dict] = {}
    for finding in findings:
        severity = finding.get("severity")
        if severity not in SEVERITY_PRIORITY:
            continue
        key = (finding["groupId"], finding["artifactId"], finding.get("current_version"))
        if key not in aggregated:
            aggregated[key] = {
                "dependency": f"{finding['groupId']}:{finding['artifactId']}",
                "groupId": finding["groupId"],
                "artifactId": finding["artifactId"],
                "current_version": finding.get("current_version"),
                "fixed_candidates": [],
                "highest_severity": severity,
                "cves": [],
            }
        target = aggregated[key]
        if SEVERITY_PRIORITY[severity] < SEVERITY_PRIORITY.get(target["highest_severity"], 99):
            target["highest_severity"] = severity
        target["fixed_candidates"].extend(finding.get("fixed_candidates", []))
        target["cves"] = sorted(set(target["cves"] + finding.get("cves", [])))

    targets = []
    for target in aggregated.values():
        fixed_candidates = sorted(set(target["fixed_candidates"]), key=_version_key)
        cve_entry = STATIC_CVE_DATABASE.get(f"{target['groupId']}:{target['artifactId']}", {})
        fixed_version = cve_entry.get("fixed_version") or (fixed_candidates[0] if fixed_candidates else None)
        targets.append({
            "dependency": target["dependency"],
            "groupId": target["groupId"],
            "artifactId": target["artifactId"],
            "current_version": target["current_version"],
            "fixed_version": fixed_version,
            "fixed_candidates": fixed_candidates,
            "highest_severity": target["highest_severity"],
            "cves": target["cves"],
            "summary": (
                f"{target['dependency']} {target['current_version'] or ''} -> "
                f"{fixed_version or 'no compatible fixed version found'}"
            ).strip(),
        })
    targets.sort(key=lambda item: (SEVERITY_PRIORITY.get(item.get("highest_severity"), 99), item["dependency"]))
    return targets


def scan_workspace_static(workspace_url: str) -> dict:
    """Scan a Maven workspace for vulnerabilities using the static CVE database.

    This is the offline fallback scanner. It parses pom.xml and matches
    dependencies against STATIC_CVE_DATABASE - no external tools or network
    access required.

    Args:
        workspace_url: Path to the workspace root containing pom.xml

    Returns:
        Dictionary matching the run_jf_audit_scan output schema.
    """
    pom_path = Path(workspace_url) / "pom.xml"

    # Write artifact for evidence/audit trail
    artifact_dir = Path(workspace_url) / ".adk_artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    report_path = artifact_dir / "jf_audit_latest.txt"

    if not pom_path.exists():
        report_path.write_text("ERROR: pom.xml not found in workspace\n", encoding="utf-8")
        return {
            "status": "error",
            "return_code": 1,
            "report_path": str(report_path),
            "report_size_chars": 0,
            "error": "pom.xml not found in workspace",
            "vulnerabilities_found": False,
            "scan_execution_error": True,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0,
            "total_vulnerabilities": 0,
            "remediation_targets": [],
            "affected_dependencies": [],
        }

    dependencies = _parse_pom_dependencies(pom_path)
    findings: list[dict] = []
    report_lines: list[str] = []
    report_lines.append("=" * 80)
    report_lines.append("STATIC CVE SCAN REPORT (Offline Mode)")
    report_lines.append("=" * 80)
    report_lines.append(f"Workspace: {workspace_url}")
    report_lines.append(f"Dependencies analyzed: {len(dependencies)}")
    report_lines.append("")

    for dep in dependencies:
        coordinate = f"{dep['groupId']}:{dep['artifactId']}"
        version = dep.get("version", "")
        cve_entry = STATIC_CVE_DATABASE.get(coordinate)

        if not cve_entry:
            report_lines.append(f"  OK     {coordinate}:{version} (no known CVEs)")
            continue

        if not version:
            report_lines.append(f"  SKIP   {coordinate} (version not specified, cannot check)")
            continue

        if _is_vulnerable(version, cve_entry):
            severity = cve_entry["severity"]
            fixed = cve_entry["fixed_version"]
            cves = cve_entry["cves"]
            report_lines.append(
                f"  VULN   [{severity}] {coordinate}:{version} "
                f"-> fixed in {fixed} | {', '.join(cves)} | {cve_entry.get('description', '')}"
            )
            findings.append({
                "severity": severity,
                "groupId": dep["groupId"],
                "artifactId": dep["artifactId"],
                "current_version": version,
                "fixed_version": fixed,
                "fixed_candidates": cve_entry.get("fixed_candidates", [fixed]),
                "cves": cves,
                "summary": f"{coordinate} {version} -> {fixed}",
            })
        else:
            report_lines.append(f"  OK     {coordinate}:{version} (version is safe)")

    report_lines.append("")
    report_lines.append(f"Total vulnerabilities found: {len(findings)}")
    report_lines.append("=" * 80)

    report_text = "\n".join(report_lines)
    report_path.write_text(report_text, encoding="utf-8")

    remediation_targets = _build_remediation_targets(findings)
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
        "scanner_backend": "static",
        "critical_vulnerabilities": critical,
        "high_vulnerabilities": high,
        "medium_vulnerabilities": medium,
        "low_vulnerabilities": low,
        "total_vulnerabilities": len(findings),
        "remediation_targets": remediation_targets,
        "affected_dependencies": affected,
    }