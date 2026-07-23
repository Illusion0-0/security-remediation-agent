import subprocess
import os
import json
import logging
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.genai import types as genai_types
from pydantic import BaseModel, Field

from subagents.java_vulnerability_fixer_agent.agent import java_vulnerability_fixer_agent
from subagents.java_vulnerability_fixer_agent.tools.tools import (
    run_mvn_clean_install,
    run_mvn_test,
    update_pom_xml,
)
from subagents.java_vulnerablility_scanner_agent.agent import java_vulnerability_scanner_agent
from subagents.java_vulnerablility_scanner_agent.tools.tools import (
    cleanup_workspace,
    clone_repository,
)
from subagents.java_vulnerablility_scanner_agent.tools.static_scanner import scan_workspace_static
from multi_scanner import scan_workspace_multi
from cross_model_judge import judge_proposals
from github_pr import create_pull_request, build_pr_body


app = FastAPI(title="Java Vulnerabilities Remover ADK Wrapper", version="1.0.0")
logger = logging.getLogger(__name__)


class ScanRequest(BaseModel):
    repo_url: str
    run_id: str | None = None
    languages: list[str] | None = None


class PlanRequest(BaseModel):
    repo_url: str
    run_id: str
    findings: list[dict[str, Any]]


class ApplyRequest(BaseModel):
    repo_url: str
    run_id: str
    proposals: list[dict[str, Any]]


class ValidateRequest(BaseModel):
    repo_url: str
    run_id: str
    proposals: list[dict[str, Any]]
    apply_result: dict[str, Any] = Field(default_factory=dict)


class ReportRequest(BaseModel):
    run: dict[str, Any]


class _RunContext(BaseModel):
    run_id: str
    repo_url: str
    workspace_path: str
    managed_workspace: bool = False


RUN_CONTEXTS: dict[str, _RunContext] = {}
SESSION_SERVICE = InMemorySessionService()


def _coerce_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return {}
    return {}


def _get_attr_or_key(value: Any, name: str) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def _event_state_delta(event: Any) -> dict[str, Any]:
    actions = _get_attr_or_key(event, "actions")
    delta = _get_attr_or_key(actions, "state_delta")
    return _coerce_dict(delta)


def _event_last_function_response(event: Any) -> dict[str, Any]:
    content = _get_attr_or_key(event, "content")
    parts = _get_attr_or_key(content, "parts") or []
    for part in reversed(parts):
        function_response = _get_attr_or_key(part, "function_response")
        if not function_response:
            continue
        response = _get_attr_or_key(function_response, "response")
        parsed = _coerce_dict(response)
        if parsed:
            return parsed
    return {}


def _event_last_text_json(event: Any) -> dict[str, Any]:
    content = _get_attr_or_key(event, "content")
    parts = _get_attr_or_key(content, "parts") or []
    for part in reversed(parts):
        text = _get_attr_or_key(part, "text")
        parsed = _coerce_dict(text)
        if parsed:
            return parsed
    return {}


async def _invoke_agent(
    *,
    app_name: str,
    agent: Any,
    state: dict[str, Any],
    message: str,
) -> dict[str, Any]:
    runner = Runner(app_name=app_name, agent=agent, session_service=SESSION_SERVICE)
    user_id = f"api-user-{app_name}"
    session = await SESSION_SERVICE.create_session(app_name=app_name, user_id=user_id, state=state)
    content = genai_types.Content(role="user", parts=[genai_types.Part(text=message)])
    state_delta_accumulator: dict[str, Any] = {}
    last_function_response: dict[str, Any] = {}
    last_text_json: dict[str, Any] = {}
    try:
        try:
            async for event in runner.run_async(
                user_id=session.user_id,
                session_id=session.id,
                new_message=content,
            ):
                state_delta_accumulator.update(_event_state_delta(event))
                function_response = _event_last_function_response(event)
                if function_response:
                    last_function_response = function_response
                text_json = _event_last_text_json(event)
                if text_json:
                    last_text_json = text_json
        except HTTPException:
            raise
        except Exception as exc:
            logger.exception("ADK runner invocation failed for app '%s'", app_name)
            raise HTTPException(
                status_code=502,
                detail=f"ADK runtime invocation failed for {app_name}: {type(exc).__name__}: {exc}",
            ) from exc
    finally:
        await runner.close()

    updated = await SESSION_SERVICE.get_session(
        app_name=app_name,
        user_id=session.user_id,
        session_id=session.id,
    )
    merged_state: dict[str, Any] = {}
    if updated is not None:
        merged_state.update(dict(updated.state or {}))
    merged_state.update(state_delta_accumulator)
    if last_function_response:
        merged_state["__last_function_response"] = last_function_response
    if last_text_json:
        merged_state["__last_text_json"] = last_text_json
    return merged_state


def _ensure_workspace(repo_url: str, run_id: str) -> _RunContext:
    if run_id in RUN_CONTEXTS:
        return RUN_CONTEXTS[run_id]

    local_path = Path(repo_url).expanduser()
    if local_path.exists() and local_path.is_dir():
        context = _RunContext(
            run_id=run_id,
            repo_url=repo_url,
            workspace_path=str(local_path),
            managed_workspace=False,
        )
        RUN_CONTEXTS[run_id] = context
        return context

    clone_result = clone_repository(repo_url, run_id=run_id)
    if clone_result.get("status") != "success":
        raise HTTPException(status_code=400, detail=clone_result.get("error") or "Repository clone failed")

    context = _RunContext(
        run_id=run_id,
        repo_url=repo_url,
        workspace_path=str(clone_result["workspace_path"]),
        managed_workspace=True,
    )
    RUN_CONTEXTS[run_id] = context
    return context


def _scan_to_findings(scan_result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for target in scan_result.get("remediation_targets", []):
        dependency = target.get("dependency") or f"{target.get('groupId')}:{target.get('artifactId')}"
        cves = target.get("cves") or ["CVE-UNKNOWN"]
        fixed_version = target.get("fixed_version")
        fixed_candidates = list(target.get("fixed_candidates") or [])
        recommended_versions = list(fixed_candidates)
        if fixed_version:
            recommended_versions = [fixed_version] + [candidate for candidate in fixed_candidates if candidate != fixed_version]
        findings.append(
            {
                "id": str(uuid4()),
                "dependency": dependency,
                "current_version": target.get("current_version") or "unknown",
                "fixed_version": fixed_version,
                "recommended_versions": recommended_versions,
                "severity": target.get("highest_severity") or "Medium",
                "cve": cves[0],
            }
        )
    return findings


def _group_artifact(dependency: str) -> tuple[str | None, str | None]:
    parts = dependency.split(":")
    if len(parts) < 2:
        return None, None
    return parts[0], parts[1]


def _proposal_to_dependency_update(proposal: dict[str, Any]) -> dict[str, str] | None:
    dependency = str(proposal.get("dependency") or "").strip()
    new_version = str(proposal.get("to_version") or "").strip()
    if not dependency or not new_version:
        return None
    group_id, artifact_id = _group_artifact(dependency)
    if not group_id or not artifact_id:
        return None
    return {"groupId": group_id, "artifactId": artifact_id, "new_version": new_version}


def _sanitize_pom_with_approved_proposals(
    *,
    workspace_path: str,
    pom_before_content: str | None,
    proposals: list[dict[str, Any]],
) -> dict[str, Any]:
    pom_path = Path(workspace_path) / "pom.xml"
    if pom_before_content is None or not pom_path.exists():
        return {"status": "skipped", "reason": "pom baseline unavailable", "updated_dependencies": []}

    dependency_updates: list[tuple[dict[str, Any], dict[str, str]]] = []
    for proposal in proposals:
        update = _proposal_to_dependency_update(proposal)
        if update:
            dependency_updates.append((proposal, update))

    if not dependency_updates:
        return {"status": "skipped", "reason": "no valid approved proposals", "updated_dependencies": []}

    accepted_updates: list[dict[str, str]] = []
    accepted_proposals: list[dict[str, Any]] = []
    rejected_proposals: list[dict[str, Any]] = []
    # Reset pom.xml to pre-fixer baseline, then retain only approved updates that keep builds healthy.
    for proposal, update in dependency_updates:
        trial_updates = accepted_updates + [update]
        pom_path.write_text(pom_before_content, encoding="utf-8")
        apply_result = update_pom_xml(str(pom_path), trial_updates)
        if apply_result.get("status") == "error":
            rejected_proposals.append(
                {
                    "proposal_id": proposal.get("id"),
                    "dependency": proposal.get("dependency"),
                    "to_version": proposal.get("to_version"),
                    "reason": apply_result.get("error") or "failed to apply dependency update",
                }
            )
            continue

        build_result = run_mvn_clean_install(workspace_path)
        if build_result.get("build_success"):
            accepted_updates = trial_updates
            accepted_proposals.append(
                {
                    "proposal_id": proposal.get("id"),
                    "dependency": proposal.get("dependency"),
                    "to_version": proposal.get("to_version"),
                }
            )
        else:
            rejected_proposals.append(
                {
                    "proposal_id": proposal.get("id"),
                    "dependency": proposal.get("dependency"),
                    "to_version": proposal.get("to_version"),
                    "reason": build_result.get("summary") or build_result.get("error") or "build failed",
                }
            )

    pom_path.write_text(pom_before_content, encoding="utf-8")
    final_result = update_pom_xml(str(pom_path), accepted_updates)
    final_result["enforced"] = True
    final_result["accepted_proposals"] = accepted_proposals
    final_result["rejected_proposals"] = rejected_proposals
    final_result["accepted_count"] = len(accepted_proposals)
    final_result["rejected_count"] = len(rejected_proposals)
    return final_result



def _diff_excerpt(workspace_path: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "--no-pager", "diff"],
            cwd=workspace_path,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            return None
        return result.stdout[:5000] if result.stdout else None
    except Exception:
        return None


def _git_changed_files(workspace_path: str) -> list[str]:
    try:
        result = subprocess.run(
            ["git", "status", "--short"],
            cwd=workspace_path,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode != 0:
            return []
        changed_files = []
        for line in result.stdout.splitlines():
            if len(line) < 4:
                continue
            path = line[3:].strip()
            if path and not path.startswith(".adk_artifacts"):
                changed_files.append(path)
        return sorted(set(changed_files))
    except Exception:
        return []


def _build_dependency_changes_from_targets(remediation_targets: list[dict[str, Any]], changed_files: list[str]) -> list[dict[str, Any]]:
    if not changed_files:
        return []
    default_file = changed_files[0]
    changes: list[dict[str, Any]] = []
    for target in remediation_targets:
        changes.append(
            {
                "dependency": target.get("dependency", "unknown:unknown"),
                "old_version": target.get("current_version"),
                "new_version": target.get("fixed_version") or "unknown",
                "file_path": default_file,
                "reason": f"Updated to address {', '.join(target.get('cves', [])) or 'reported vulnerability'}",
            }
        )
    return changes


def _build_dependency_changes_from_proposals(proposals: list[dict[str, Any]], changed_files: list[str]) -> list[dict[str, Any]]:
    if not changed_files:
        return []
    default_file = changed_files[0]
    changes: list[dict[str, Any]] = []
    for proposal in proposals:
        dependency = proposal.get("dependency", "unknown:unknown")
        changes.append(
            {
                "dependency": dependency,
                "artifact": dependency,
                "old_version": proposal.get("from_version"),
                "new_version": proposal.get("to_version") or "unknown",
                "file_path": default_file,
                "reason": proposal.get("reasoning") or f"Applied approved proposal for {dependency}",
            }
        )
    return changes


def _map_updated_dependencies(updated_dependencies: list[dict[str, Any]], default_file: str) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for item in updated_dependencies:
        artifact = item.get("artifact") or "unknown:unknown"
        changes.append(
            {
                "dependency": artifact,
                "artifact": artifact,
                "old_version": item.get("old_version"),
                "new_version": item.get("new_version") or "unknown",
                "section": item.get("section"),
                "file_path": item.get("file_path") or default_file,
                "reason": item.get("reason") or f"Updated via fixer for {artifact}",
            }
        )
    return changes


def _scanner_backend() -> str:
    """Resolve the active scanner backend: 'jf', 'static', or 'auto' (jf if available else static)."""
    backend = os.getenv("SCANNER_BACKEND", "auto").strip().lower() or "auto"
    if backend in {"jf", "static"}:
        return backend
    # auto: use JFrog CLI if it is installed and reachable, otherwise static fallback.
    try:
        probe = subprocess.run(["jf", "--version"], capture_output=True, text=True, timeout=15)
        return "jf" if probe.returncode == 0 else "static"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "static"



def _maybe_create_github_pr(*, repo_url: str, workspace_path: str, changed_files: list[str], changes: list, run_id: str, findings_count: int):
    branch = f"auto-remediation-{run_id[:8]}"
    body = build_pr_body(run_id, findings_count, changes)
    title = f"[Auto-Remediation] Fix {findings_count} vulnerabilities ({run_id[:8]})"
    rel_files = []
    for f in changed_files:
        rel_files.append(os.path.relpath(f, workspace_path).replace(os.sep, "/") if os.path.isabs(f) else f)
    return create_pull_request(repo_url=repo_url, workspace_path=workspace_path, changed_files=rel_files, branch_name=branch, title=title, body=body)


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "tracked_runs": len(RUN_CONTEXTS), "scanner_backend": _scanner_backend()}


@app.post("/scan")
async def scan(request: ScanRequest) -> dict[str, Any]:
    run_id = request.run_id or str(uuid4())
    context = _ensure_workspace(request.repo_url, run_id)

    backend = _scanner_backend()

    if backend == "static":
        # Offline deterministic scanner - no JFrog CLI or network required.
        merged = scan_workspace_multi(context.workspace_path, languages=request.languages)
        if merged.get("scan_execution_error") or merged.get("status") == "error":
            raise HTTPException(status_code=400, detail=merged.get("error") or "Static scan failed")
    else:
        # JFrog CLI-backed scan via the ADK scanner agent.
        state = await _invoke_agent(
            app_name="java-vulnerability-scan",
            agent=java_vulnerability_scanner_agent,
            state={"workspace_url": context.workspace_path, "run_id": run_id, "repo_url": request.repo_url},
            message=(
                "Run vulnerability scan for this workspace and return strict JSON only. "
                f"workspace_url={context.workspace_path}."
            ),
        )
        merged = _coerce_dict(state.get("vulnerability_scan_report"))
        if not merged:
            merged = _coerce_dict(state.get("__last_function_response"))
        if not merged:
            merged = _coerce_dict(state.get("__last_text_json"))
        if not merged:
            raise HTTPException(status_code=502, detail="Scanner ADK agent returned no structured output")
        if merged.get("scan_execution_error"):
            raise HTTPException(status_code=502, detail=merged.get("error") or "JFrog scan execution failed")
        if merged.get("return_code") not in (None, 0) and merged.get("total_vulnerabilities", 0) == 0:
            raise HTTPException(status_code=502, detail=merged.get("error") or "JFrog scan failed before producing findings")
        if merged.get("scan_status") == "error" or merged.get("status") == "error":
            raise HTTPException(status_code=400, detail=merged.get("error") or "Scan failed")

    return {
        "run_id": run_id,
        "repo_url": request.repo_url,
        "workspace_path": context.workspace_path,
        "scanner_backend": backend,
        "findings": _scan_to_findings(merged),
        "scan_status": merged.get("status", "success"),
        "critical_vulnerabilities": merged.get("critical_vulnerabilities", 0),
        "high_vulnerabilities": merged.get("high_vulnerabilities", 0),
        "medium_vulnerabilities": merged.get("medium_vulnerabilities", 0),
        "low_vulnerabilities": merged.get("low_vulnerabilities", 0),
        "total_vulnerabilities": merged.get("total_vulnerabilities", 0),
        "report_path": merged.get("report_path"),
    }



@app.post("/judge")
async def judge(request: PlanRequest) -> dict[str, Any]:
    """Cross-model judge: a second LLM reviews remediation proposals."""
    proposals = []
    for finding in request.findings:
        recommended = list(finding.get("recommended_versions") or [])
        preferred = finding.get("fixed_version")
        to_v = preferred or (recommended[0] if recommended else finding.get("current_version", "unknown"))
        dep_name = finding.get("dependency", "unknown")
        cve_name = finding.get("cve", "CVE-unknown")
        proposals.append({
            "id": str(uuid4()),
            "finding_id": finding.get("id") or str(uuid4()),
            "dependency": dep_name,
            "from_version": finding.get("current_version", "unknown"),
            "to_version": to_v,
            "reasoning": f"Upgrade {dep_name} to {to_v} for {cve_name}",
            "confidence_score": 0.82,
        })
    summary = judge_proposals(proposals, request.findings)
    return {"proposals": proposals, "judge_review": summary}


@app.post("/remediate/plan")
async def remediate_plan(request: PlanRequest) -> dict[str, Any]:
    _ensure_workspace(request.repo_url, request.run_id)

    proposals: list[dict[str, Any]] = []
    for finding in request.findings:
        recommended = list(finding.get("recommended_versions") or [])
        preferred_version = finding.get("fixed_version")
        to_version = preferred_version or (recommended[0] if recommended else finding.get("current_version", "unknown"))
        proposals.append(
            {
                "id": str(uuid4()),
                "finding_id": finding.get("id") or str(uuid4()),
                "dependency": finding.get("dependency", "unknown:unknown"),
                "from_version": finding.get("current_version", "unknown"),
                "to_version": to_version,
                "reasoning": (
                    f"Upgrade {finding.get('dependency', 'dependency')} to {to_version} "
                    f"to remediate {finding.get('cve', 'CVE-UNKNOWN')}"
                ),
                "confidence_score": 0.82,
                "approval_status": "approved",
            }
        )

    return {"proposals": proposals}


@app.post("/remediate/apply")
async def remediate_apply(request: ApplyRequest) -> dict[str, Any]:
    """Apply version bumps, run tests, AI-fix failures, create PR."""
    from file_editor import apply_remediation
    from breaking_change_checker import check_breaking_changes
    from ai_fixer import ai_fix_code

    context = _ensure_workspace(request.repo_url, request.run_id)
    workspace_path = context.workspace_path

    # Step 1: Apply version bumps directly (no AI needed for pom.xml/requirements.txt/package.json)
    edit_result = apply_remediation(workspace_path, request.proposals)
    changes = edit_result.get("changes", [])
    changed_files = edit_result.get("changed_files", [])
    # Filter out generated/build files - only include source files we edited
    _GEN = ["package-lock.json", "node_modules", "/target/", ".class", "__pycache__", ".pyc"]
    changed_files = [f for f in changed_files if not any(g in f for g in _GEN)]
    if not changed_files:
        git_files = _git_changed_files(workspace_path)
        changed_files = [f for f in git_files if not any(g in f for g in _GEN)]
    if not changed_files:
        changed_files = ["pom.xml"]

    # Step 2: Run tests to validate the fixes
    detected=set()
    for p in request.proposals:
        d=p.get('dependency','')
        if ':' in d and not d.lower().startswith(('pypi','npm')): detected.add('java')
        elif any(x in d.lower() for x in ['requests','urllib3','cryptography','pillow','pyyaml','jinja2','werkzeug','aiohttp','setuptools','django']): detected.add('python')
        elif any(x in d.lower() for x in ['lodash','axios','express','minimatch','handlebars','qs','moment','jsonwebtoken','node-forge']): detected.add('nodejs')
    test_results = check_breaking_changes(workspace_path, changed_files, request.proposals)
    ai_fix_result = None

    # Step 3: If tests failed, use AI to fix code issues (GLM-5.2 via z.ai)
    failed_tests = [r for r in test_results.get("results", []) if not r.get("passed")]
    if failed_tests:
        ai_fix_result = ai_fix_code(workspace_path, failed_tests, changed_files)
        # Re-run tests after AI fix
        test_results_after = check_breaking_changes(workspace_path, changed_files, request.proposals)
        test_results["ai_fix_applied"] = ai_fix_result
        test_results["after_ai_fix"] = test_results_after
        test_results["status"] = test_results_after.get("status", "failed")
        # Update changed files if AI modified anything
        new_changed = _git_changed_files(workspace_path)
        _GEN2 = ["package-lock.json", "node_modules", "/target/", ".class", "__pycache__", ".pyc"]
        new_changed = [f for f in new_changed if not any(g in f for g in _GEN2)]
        if new_changed:
            changed_files = sorted(set(changed_files + new_changed))

    # Step 4: Create GitHub PR (direct API, no AI)
    _GEN3 = ['package-lock.json', 'node_modules', '/target/', '.class', '__pycache__', '.pyc']
    all_git = _git_changed_files(workspace_path)
    all_git = [f for f in all_git if not any(g in f for g in _GEN3)]
    if all_git:
        changed_files = sorted(set(changed_files + all_git))

    pr_result = _maybe_create_github_pr(
        repo_url=request.repo_url, workspace_path=workspace_path,
        changed_files=changed_files, changes=changes,
        run_id=request.run_id, findings_count=len(request.proposals),
    )

    return {
        "workspace_path": workspace_path,
        "changed_files": changed_files,
        "changes": changes,
        "diff_excerpt": _diff_excerpt(workspace_path),
        "remediation_result": {
            "status": edit_result.get("status"),
            "updated_count": edit_result.get("updated_count", 0),
            "test_results": test_results,
            "ai_fix": ai_fix_result,
        },
        "pull_request": pr_result,
    }


@app.post("/validate")
async def validate(request: ValidateRequest) -> dict[str, Any]:
    """Run tests for all languages (Java/Python/Node.js) to validate fixes."""
    from test_runner import run_tests

    context = _ensure_workspace(request.repo_url, request.run_id)
    workspace_path = context.workspace_path

    # Run multi-language tests
    # Infer languages from proposals (Java deps have "groupId:artifactId" format)
    detected_langs = set()
    JAVA_PKGS = {"log4j-core", "commons-text", "jackson-databind", "snakeyaml", "commons-io", "dom4j", "guava", "xstream", "commons-compress"}
    PY_PKGS = {"requests", "urllib3", "cryptography", "pillow", "pyyaml", "jinja2", "werkzeug", "aiohttp", "setuptools", "django"}
    NODE_PKGS = {"lodash", "axios", "express", "minimatch", "handlebars", "qs", "moment", "ws", "jsonwebtoken", "node-forge"}
    for prop in request.proposals:
        dep = prop.get("dependency", "").lower()
        pkg = dep.split(":")[-1] if ":" in dep else dep
        if ":" in prop.get("dependency", "") and not dep.startswith(("pypi", "npm")):
            detected_langs.add("java")
        elif pkg in PY_PKGS or "pypi" in dep:
            detected_langs.add("python")
        elif pkg in NODE_PKGS or "npm" in dep:
            detected_langs.add("nodejs")
    languages = list(detected_langs) if detected_langs else None
    test_results = run_tests(workspace_path, languages=languages)

    # Build validation results for each proposal
    validations: list[dict[str, Any]] = []
    overall_passed = test_results.get("status") == "passed"

    for proposal in request.proposals:
        validations.append({
            "proposal_id": proposal.get("id") or str(uuid4()),
            "passed": overall_passed,
            "build_ok": overall_passed,
            "tests_ok": overall_passed,
            "startup_ok": True,
            "details": f"services: {test_results.get('passed_services', 0)}/{test_results.get('total_services', 0)} passed",
        })

    return {"validations": validations}


@app.post("/report")
async def report(request: ReportRequest) -> dict[str, Any]:
    run = request.run
    run_id = str(run.get("id") or uuid4())

    findings = list(run.get("findings") or [])
    validations = list(run.get("validations") or [])
    proposals = list(run.get("proposals") or [])
    pull_request = run.get("pull_request") or {}

    passed = sum(1 for item in validations if item.get("passed"))
    summary = (
        f"Run {run_id}: findings={len(findings)}, proposals={len(proposals)}, "
        f"validated={passed}/{len(validations)}, pr_status={pull_request.get('status', 'not_attempted')}"
    )

    evidence = {
        "run_id": run_id,
        "summary": summary,
        "export_links": [
            f"/exports/{run_id}/audit.json",
            f"/exports/{run_id}/executive-summary.txt",
        ],
        "audit_events": len(run.get("events") or []),
    }

    return {"evidence": evidence, "summary": summary}


@app.delete("/runs/{run_id}")
async def cleanup_run(run_id: str) -> dict[str, Any]:
    context = RUN_CONTEXTS.pop(run_id, None)
    if context is None:
        return {"status": "skipped", "message": "Run context not found", "run_id": run_id}
    if not context.managed_workspace:
        return {
            "status": "skipped",
            "message": "Workspace is not managed by ADK wrapper",
            "run_id": run_id,
            "workspace_path": context.workspace_path,
        }

    cleanup = cleanup_workspace(context.workspace_path)
    return {"run_id": run_id, **cleanup}
