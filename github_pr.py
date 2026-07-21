"""GitHub PR creation for remediation runs.

Creates a real branch, commits the remediated files, and opens a Pull Request
on GitHub via the REST API. Falls back gracefully to a generated compare URL
when no GitHub token is available (so the pipeline never breaks).

Required env vars for real PR creation:
    GH_TOKEN (or GITHUB_TOKEN) - a GitHub personal access token with repo scope

Usage:
    from github_pr import create_pull_request
    result = create_pull_request(
        repo_url="https://github.com/owner/repo",
        workspace_path="/path/to/cloned/repo",
        changed_files=["pom.xml"],
        branch_name="auto-remediation-abc123",
        title="Auto-remediate 9 vulnerabilities",
        body="...",
        base_branch="develop",
    )
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import urllib.request
import urllib.error
from typing import Any


def _github_token() -> str | None:
    return os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")


def _parse_github_repo(repo_url: str) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL. Returns None if not a GitHub repo."""
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url.strip())
    if match:
        return match.group(1), match.group(2)
    return None


def _gh_api(method: str, path: str, token: str, body: dict | None = None) -> dict[str, Any]:
    """Call the GitHub REST API."""
    url = f"https://api.github.com{path}"
    data = json.dumps(body).encode("utf-8") if body else None
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API {method} {path} failed ({exc.code}): {detail}") from exc


def _get_default_branch(token: str, owner: str, repo: str) -> str:
    info = _gh_api("GET", f"/repos/{owner}/{repo}", token)
    return info.get("default_branch") or "main"


def _get_file_sha(token: str, owner: str, repo: str, path: str, branch: str) -> str | None:
    try:
        info = _gh_api("GET", f"/repos/{owner}/{repo}/contents/{path}?ref={branch}", token)
        return info.get("sha")
    except Exception:
        return None


def create_pull_request(
    *,
    repo_url: str,
    workspace_path: str,
    changed_files: list[str],
    branch_name: str,
    title: str,
    body: str,
    base_branch: str | None = None,
) -> dict[str, Any]:
    """Create a real GitHub PR with the remediated files.

    Returns a dict with: status ("created" | "skipped" | "failed"),
    url, reason, method ("github_api" | "compare_url").
    """
    token = _github_token()
    parsed = _parse_github_repo(repo_url)

    # No GitHub repo or no token -> graceful fallback to compare URL
    if not parsed or not token:
        if parsed:
            owner, repo = parsed
            base = base_branch or "main"
            compare = f"https://github.com/{owner}/{repo}/compare/{base}...{branch_name}?expand=1"
            return {
                "status": "skipped",
                "url": compare,
                "reason": "GH_TOKEN not set; generated compare URL for manual PR creation.",
                "method": "compare_url",
                "branch": branch_name,
            }
        return {
            "status": "skipped",
            "url": None,
            "reason": "Not a GitHub repository or no token; PR creation skipped.",
            "method": "compare_url",
            "branch": branch_name,
        }

    owner, repo = parsed
    try:
        base = base_branch or _get_default_branch(token, owner, repo)

        # Create branch from base branch's HEAD SHA
        ref_info = _gh_api("GET", f"/repos/{owner}/{repo}/git/ref/heads/{base}", token)
        base_sha = ref_info["object"]["sha"]
        _gh_api("POST", f"/repos/{owner}/{repo}/git/refs", token, {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        })

        # Commit each changed file via the contents API
        committed = 0
        for rel_path in changed_files:
            full = os.path.join(workspace_path, rel_path)
            if not os.path.isfile(full):
                continue
            content_bytes = open(full, "rb").read()
            content_b64 = base64.b64encode(content_bytes).decode("ascii")
            file_sha = _get_file_sha(token, owner, repo, rel_path, base)
            payload = {
                "message": f"fix(security): update {rel_path} for vulnerability remediation",
                "content": content_b64,
                "branch": branch_name,
            }
            if file_sha:
                payload["sha"] = file_sha
            _gh_api("PUT", f"/repos/{owner}/{repo}/contents/{rel_path}", token, payload)
            committed += 1

        if committed == 0:
            return {
                "status": "skipped",
                "url": None,
                "reason": "No changed files to commit.",
                "method": "github_api",
                "branch": branch_name,
            }

        # Open the pull request
        pr_info = _gh_api("POST", f"/repos/{owner}/{repo}/pulls", token, {
            "title": title,
            "body": body,
            "head": branch_name,
            "base": base,
        })
        return {
            "status": "created",
            "url": pr_info.get("html_url"),
            "reason": None,
            "method": "github_api",
            "branch": branch_name,
            "pr_number": pr_info.get("number"),
            "files_committed": committed,
        }
    except Exception as exc:
        return {
            "status": "failed",
            "url": None,
            "reason": f"GitHub PR creation error: {type(exc).__name__}: {exc}",
            "method": "github_api",
            "branch": branch_name,
        }


def build_pr_body(run_id: str, findings_count: int, changes: list[dict[str, Any]], judge_summary: dict | None = None) -> str:
    """Build a markdown PR body describing the remediation."""
    lines = [
        "## Automated Security Remediation",
        "",
        f"**Run ID:** `{run_id}`",
        f"**Vulnerabilities remediated:** {findings_count}",
        "",
        "### Changes",
        "",
        "| Dependency | Old | New | Reason |",
        "|---|---|---|---|",
    ]
    for c in changes[:20]:
        dep = c.get("dependency", "?")
        old = c.get("old_version", "?")
        new = c.get("new_version", "?")
        reason = (c.get("reason") or "").replace("|", "/")[:80]
        lines.append(f"| `{dep}` | `{old}` | `{new}` | {reason} |")

    if judge_summary:
        lines += [
            "",
            "### Cross-Model Judge Review",
            "",
            f"- Judge model: `{judge_summary.get('judge_model', 'N/A')}`",
            f"- Approved: {len(judge_summary.get('approved', []))}",
            f"- Rejected: {len(judge_summary.get('rejected', []))}",
            f"- Needs review: {len(judge_summary.get('needs_review', []))}",
            "",
            "_Reviewed by an independent LLM for Responsible AI transparency._",
        ]

    lines += [
        "",
        "---",
        "_This PR was generated automatically by the AI-Assisted Secure Software Development prototype (Hackathon 2026)._",
    ]
    return "\n".join(lines)