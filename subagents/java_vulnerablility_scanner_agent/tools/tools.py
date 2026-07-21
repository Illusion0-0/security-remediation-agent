import json
import os
import re
import subprocess
import tempfile
import shutil
from pathlib import Path

from .static_scanner import scan_workspace_static

MAX_REMEDIATION_TARGETS = 100
MAX_SUMMARY_LENGTH = 320
TABLE_COLUMN_COUNT = 8
SEVERITY_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
DEFAULT_REPO_BASE_BRANCH = os.getenv("ADK_REPO_BASE_BRANCH", "develop").strip() or "develop"


def clone_repository(repository_url: str, run_id: str | None = None) -> dict:
    """Clone the given repository into a temporary workspace.

    Returns a payload containing workspace path and clone status.
    """
    if not repository_url or not repository_url.startswith(("http://", "https://", "git@", "ssh://")):
        return {
            "status": "error",
            "error": "Invalid repository_url. Expected a Git URL.",
            "workspace_path": None,
        }

    suffix = (run_id or "scan").replace("/", "-")[:20]
    workspace_path = Path(tempfile.mkdtemp(prefix=f"adk-scan-{suffix}-"))
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    target_branch = DEFAULT_REPO_BASE_BRANCH

    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--branch",
                target_branch,
                repository_url,
                str(workspace_path),
            ],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
            cwd=str(Path.home()),
        )
        if result.returncode != 0:
            shutil.rmtree(workspace_path, ignore_errors=True)
            return {
                "status": "error",
                "error": (result.stderr or result.stdout or "git clone failed")[:500],
                "workspace_path": None,
            }

        return {
            "status": "success",
            "workspace_path": str(workspace_path),
            "repository_url": repository_url,
            "branch": target_branch,
        }
    except subprocess.TimeoutExpired:
        shutil.rmtree(workspace_path, ignore_errors=True)
        return {
            "status": "error",
            "error": "git clone timed out after 180 seconds",
            "workspace_path": None,
        }
    except Exception as exc:
        shutil.rmtree(workspace_path, ignore_errors=True)
        return {
            "status": "error",
            "error": str(exc),
            "workspace_path": None,
        }


def cleanup_workspace(workspace_path: str | None) -> dict:
    if not workspace_path:
        return {"status": "skipped", "message": "No workspace path provided"}
    try:
        shutil.rmtree(Path(workspace_path), ignore_errors=True)
        return {"status": "success", "workspace_path": workspace_path}
    except Exception as exc:
        pass


def _get_report_directory(workspace_url: str) -> Path:
    report_dir = Path(workspace_url) / ".adk_artifacts"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def _get_latest_report_path(workspace_url: str) -> Path:
    return _get_report_directory(workspace_url) / "jf_audit_latest.txt"


def _load_audit_text(report_input: str) -> str:
    if not report_input:
        return ""

    if any(marker in report_input for marker in ["\n", "\r", "|", "CVE-"]):
        return report_input

    try:
        candidate = Path(report_input)
        if candidate.exists():
            return candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return report_input

    return report_input


def _normalize_severity(raw_severity: str | None) -> str | None:
    if not raw_severity:
        return None
    severity = re.sub(r"[^A-Za-z]", "", str(raw_severity)).strip().title()
    return severity if severity in {"Critical", "High", "Medium", "Low"} else None


def _extract_cves(node) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d+", json.dumps(node, ensure_ascii=False))))


def _split_table_columns(line: str) -> list[str] | None:
    if "|" not in line:
        return None

    raw_columns = line.split("|")
    if len(raw_columns) < TABLE_COLUMN_COUNT + 2:
        return None
    return [part.strip() for part in raw_columns[1:-1]]


def _split_dependency(dependency: str) -> tuple[str | None, str | None]:
    dependency_parts = dependency.split(":", 1)
    if len(dependency_parts) != 2:
        return None, None
    return dependency_parts[0], dependency_parts[1]


def _version_key(version: str) -> list[tuple[int, int | str]]:
    tokens = re.findall(r"\d+|[A-Za-z]+", version)
    parsed_tokens: list[tuple[int, int | str]] = []
    for token in tokens:
        if token.isdigit():
            parsed_tokens.append((1, int(token)))
        else:
            parsed_tokens.append((0, token.lower()))
    return parsed_tokens


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


def _numeric_prefix(version: str | None, length: int) -> tuple[int, ...]:
    if not version:
        return tuple()
    numbers = [int(token) for token in re.findall(r"\d+", version)]
    return tuple(numbers[:length])


def _choose_best_fixed_version(current_version: str | None, candidates: list[str]) -> str | None:
    unique_candidates = []
    seen = set()
    for candidate in candidates:
        normalized = candidate.strip().strip("[]")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique_candidates.append(normalized)

    if not unique_candidates:
        return None
    if not current_version:
        return min(unique_candidates, key=_version_key)

    greater_candidates = [
        candidate for candidate in unique_candidates if _compare_versions(candidate, current_version) > 0
    ]
    if not greater_candidates:
        return None

    current_major_minor = _numeric_prefix(current_version, 2)
    same_major_minor = [
        candidate for candidate in greater_candidates if _numeric_prefix(candidate, 2) == current_major_minor
    ]
    if same_major_minor:
        return min(same_major_minor, key=_version_key)

    current_major = _numeric_prefix(current_version, 1)
    same_major = [
        candidate for candidate in greater_candidates if _numeric_prefix(candidate, 1) == current_major
    ]
    if same_major:
        return min(same_major, key=_version_key)

    return min(greater_candidates, key=_version_key)


def _extract_table_text(audit_output: str) -> str:
    table_lines = []
    for line in audit_output.splitlines():
        stripped = line.rstrip()
        if "|" in stripped or re.match(r"^[┌└├│─]+$", stripped.replace(" ", "")):
            table_lines.append(stripped)
    return "\n".join(table_lines)


def _append_if_value(parts: list[str], value: str) -> None:
    if value:
        parts.append(value)


def _finalize_table_block(block: dict | None) -> dict | None:
    if not block or not block.get("cve"):
        return None

    severity = _normalize_severity(block.get("severity"))
    if not severity:
        return None

    direct_dependency = "".join(block.get("direct_dependency_parts", []))
    affected_dependency = "".join(block.get("affected_dependency_parts", []))
    dependency = affected_dependency or direct_dependency
    group_id, artifact_id = _split_dependency(dependency)
    current_version = block.get("affected_version") or block.get("direct_version")
    fixed_candidates = block.get("fixed_candidates", [])
    fixed_version = _choose_best_fixed_version(current_version, fixed_candidates)

    if not group_id or not artifact_id:
        return None

    return {
        "severity": severity,
        "groupId": group_id,
        "artifactId": artifact_id,
        "current_version": current_version,
        "fixed_version": fixed_version,
        "fixed_candidates": sorted(set(candidate.strip("[]") for candidate in
                                      fixed_candidates if candidate.strip("[]")), key=_version_key),
        "cves": [block["cve"]],
        "direct_dependency": direct_dependency or None,
        "direct_version": block.get("direct_version"),
        "summary": (
            f"{dependency} {current_version or ''} -> {fixed_version or 'no compatible fixed version found'}"
        ).strip()[:MAX_SUMMARY_LENGTH],
    }


def _extract_from_json(audit_data: dict | list) -> list[dict]:
    findings: list[dict] = []
    seen = set()
    dependency_keys = [
        "dependency",
        "component",
        "package",
        "package_id",
        "packageId",
        "impacted_dependency_name",
        "impactedDependencyName",
        "artifact",
        "gav",
        "name",
    ]
    version_keys = ["version", "current_version", "installed_version", "installedVersion"]
    fixed_keys = [
        "fixed_version",
        "fixedVersion",
        "fixed_versions",
        "fixedVersions",
        "fix_versions",
        "recommended_version",
        "recommendedVersion",
    ]

    def walk(node) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict):
            return

        severity = _normalize_severity(node.get("severity") or node.get("severity_level") or node.get("severityLevel"))
        cves = _extract_cves(node)

        dependency = None
        for key in dependency_keys:
            value = node.get(key)
            if isinstance(value, str) and ":" in value and not value.startswith("http"):
                dependency = value.strip()
                break

        current_version = None
        for key in version_keys:
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                current_version = value.strip().strip("[]")
                break

        fixed_candidates: list[str] = []
        for key in fixed_keys:
            value = node.get(key)
            if isinstance(value, str) and value.strip():
                fixed_candidates.append(value.strip().strip("[]"))
                break
            if isinstance(value, list) and value:
                fixed_candidates.extend(str(item).strip().strip("[]") for item in value if str(item).strip())
                break

        if dependency and severity:
            group_id, artifact_id = _split_dependency(dependency)
            fixed_version = _choose_best_fixed_version(current_version, fixed_candidates)
            finding = {
                "severity": severity,
                "groupId": group_id,
                "artifactId": artifact_id,
                "current_version": current_version,
                "fixed_version": fixed_version,
                "fixed_candidates": sorted(set(fixed_candidates), key=_version_key),
                "cves": cves,
                "summary": f"{dependency} {current_version or ''} -> {fixed_version or 'unknown fixed version'}"
                .strip()[:MAX_SUMMARY_LENGTH],
            }
            key = (
                finding["severity"],
                finding["groupId"],
                finding["artifactId"],
                finding["current_version"],
                finding["fixed_version"],
                tuple(finding["cves"]),
            )
            if finding["groupId"] and finding["artifactId"] and key not in seen:
                seen.add(key)
                findings.append(finding)

        for value in node.values():
            if isinstance(value, (dict, list)):
                walk(value)

    walk(audit_data)
    return findings


def _extract_findings(audit_output: str) -> list[dict]:
    try:
        parsed_json = json.loads(audit_output)
        json_findings = _extract_from_json(parsed_json)
        if json_findings:
            return json_findings
    except Exception:
        pass

    findings = []
    current_block = None
    for raw_line in _extract_table_text(audit_output).splitlines():
        columns = _split_table_columns(raw_line)
        if not columns:
            finalized = _finalize_table_block(current_block)
            if finalized:
                findings.append(finalized)
            current_block = None
            continue

        if not any(columns):
            continue

        if columns[0] == "CVE" or columns[1] == "SEVERITY":
            continue

        cve = columns[0]
        if cve and re.match(r"CVE-\d{4}-\d+", cve):
            finalized = _finalize_table_block(current_block)
            if finalized:
                findings.append(finalized)
            current_block = {
                "cve": cve,
                "severity": columns[1],
                "direct_dependency_parts": [],
                "direct_version": columns[3] or None,
                "affected_dependency_parts": [],
                "affected_version": columns[5] or None,
                "fixed_candidates": [],
            }
        elif current_block is None:
            continue

        _append_if_value(current_block["direct_dependency_parts"], columns[2])
        if columns[3] and not current_block.get("direct_version"):
            current_block["direct_version"] = columns[3]
        _append_if_value(current_block["affected_dependency_parts"], columns[4])
        if columns[5] and not current_block.get("affected_version"):
            current_block["affected_version"] = columns[5]
        current_block["fixed_candidates"].extend(re.findall(r"([^\]\|]+)", columns[6]))

    finalized = _finalize_table_block(current_block)
    if finalized:
        findings.append(finalized)

    return findings


def _build_remediation_targets(findings: list[dict]) -> list[dict]:
    aggregated_targets: dict[tuple[str, str, str | None], dict] = {}

    for finding in findings:
        severity = finding.get("severity")
        if severity not in SEVERITY_PRIORITY:
            continue

        key = (finding["groupId"], finding["artifactId"], finding.get("current_version"))
        if key not in aggregated_targets:
            aggregated_targets[key] = {
                "dependency": f"{finding['groupId']}:{finding['artifactId']}",
                "groupId": finding["groupId"],
                "artifactId": finding["artifactId"],
                "current_version": finding.get("current_version"),
                "fixed_candidates": [],
                "highest_severity": severity,
                "cves": [],
            }

        target = aggregated_targets[key]
        if SEVERITY_PRIORITY[severity] < SEVERITY_PRIORITY.get(target["highest_severity"], 99):
            target["highest_severity"] = severity
        target["fixed_candidates"].extend(finding.get("fixed_candidates", []))
        target["cves"] = sorted(set(target["cves"] + finding.get("cves", [])))

    remediation_targets = []
    for target in aggregated_targets.values():
        fixed_version = _choose_best_fixed_version(target["current_version"], target["fixed_candidates"])
        remediation_targets.append(
            {
                "dependency": target["dependency"],
                "groupId": target["groupId"],
                "artifactId": target["artifactId"],
                "current_version": target["current_version"],
                "fixed_version": fixed_version,
                "fixed_candidates": sorted(set(target["fixed_candidates"]), key=_version_key),
                "highest_severity": target["highest_severity"],
                "cves": target["cves"],
                "summary": (
                    f"{target['dependency']} {target['current_version'] or ''} -> "
                    f"{fixed_version or 'no compatible fixed version found'}"
                ).strip()[:MAX_SUMMARY_LENGTH],
            }
        )

    remediation_targets.sort(
        key=lambda item: (
            SEVERITY_PRIORITY.get(item.get("highest_severity"), 99),
            item["dependency"],
        )
    )
    return remediation_targets[:MAX_REMEDIATION_TARGETS]


def _jf_cli_available() -> bool:
    """Check whether the JFrog CLI (jf) is installed and reachable."""
    try:
        result = subprocess.run(["jf", "--version"], capture_output=True, text=True, timeout=15)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


SCANNER_BACKEND = os.getenv("SCANNER_BACKEND", "auto").strip().lower() or "auto"


def run_jf_audit_scan(workspace_url: str) -> dict:
    """Run a vulnerability scan, dispatching to JFrog or the static CVE fallback.

    Backend selection:
      - SCANNER_BACKEND=static -> offline CVE database (no jf/network needed)
      - SCANNER_BACKEND=jf     -> JFrog CLI (requires jf installed + configured)
      - SCANNER_BACKEND=auto   -> jf if available, else static (default)
    """
    backend = SCANNER_BACKEND
    if backend == "static":
        return scan_workspace_static(workspace_url)
    if backend == "jf":
        return _run_jf_audit_scan_raw(workspace_url)
    # auto
    if _jf_cli_available():
        return _run_jf_audit_scan_raw(workspace_url)
    return scan_workspace_static(workspace_url)


def _run_jf_audit_scan_raw(workspace_url: str) -> dict:
    """
    Run JFrog Audit scan on the Maven project.

    Args:
        workspace_url: The workspace root directory path or URL

    Returns:
        Dictionary containing scan results with vulnerabilities found
    """
    try:
        # Run full audit to capture all vulnerabilities, not only fixable ones.
        result = subprocess.run(
            ["jf", "audit", "--mvn"],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=workspace_url,
        )

        scan_output = result.stdout
        scan_error = result.stderr
        combined_output = "\n\n".join(part for part in [scan_output.strip(), scan_error.strip()] if part)
        filtered_output = _extract_table_text(combined_output) or combined_output
        report_path = _get_latest_report_path(workspace_url)
        report_path.write_text(filtered_output, encoding="utf-8")
        parsed_report = parse_vulnerability_report(str(report_path))

        has_findings = parsed_report.get("total_vulnerabilities", 0) > 0
        has_scan_error = result.returncode != 0 and bool(scan_error.strip())
        if result.returncode == 0:
            scan_status = "success"
        elif has_findings:
            scan_status = "warning"
        else:
            scan_status = "error"

        return {
            "status": scan_status,
            "return_code": result.returncode,
            "report_path": str(report_path),
            "report_size_chars": len(filtered_output),
            "error": "" if result.returncode == 0 else scan_error[:500],
            "vulnerabilities_found": has_findings,
            "scan_execution_error": has_scan_error,
            **parsed_report,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "JF Audit scan timed out after 300 seconds",
            "vulnerabilities_found": None
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "vulnerabilities_found": None
        }


def parse_vulnerability_report(audit_output: str) -> dict:
    """
    Parse the JFrog Audit output to extract vulnerability information.

    Args:
        audit_output: Raw output from jf audit --mvn command

    Returns:
        Dictionary with parsed vulnerability details
    """
    try:
        report_text = _load_audit_text(audit_output)
        findings = _extract_findings(report_text)

        critical_count = sum(1 for finding in findings if finding["severity"] == "Critical")
        high_count = sum(1 for finding in findings if finding["severity"] == "High")
        medium_count = sum(1 for finding in findings if finding["severity"] == "Medium")
        low_count = sum(1 for finding in findings if finding["severity"] == "Low")

        return {
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "medium_vulnerabilities": medium_count,
            "low_vulnerabilities": low_count,
            "total_vulnerabilities": critical_count + high_count + medium_count + low_count,
            "remediation_targets": _build_remediation_targets(findings),
            "affected_dependencies": sorted(
                {
                    f"{finding['groupId']}:{finding['artifactId']}"
                    for finding in findings
                    if (
                        finding.get("groupId")
                        and finding.get("artifactId")
                    )
                }
            ),
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "remediation_targets": [],
            "affected_dependencies": [],
        }