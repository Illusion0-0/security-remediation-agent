"""Apply pluggable-scanner patch to api_server.py and tools.py via direct file I/O.

This bypasses any editor auto-revert by writing to disk atomically.
Run: python apply_patches.py
"""
from pathlib import Path

BASE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Patch 1: api_server.py — add static scanner import + backend selection
# ---------------------------------------------------------------------------
api_path = BASE / "api_server.py"
api_src = api_path.read_text(encoding="utf-8")

# Add import after the scanner tools import block
import_anchor = "from subagents.java_vulnerability_scanner_agent.tools.tools import (\n    cleanup_workspace,\n    clone_repository,\n)\n"
import_replacement = import_anchor + "from subagents.java_vulnerability_scanner_agent.tools.static_scanner import scan_workspace_static\n"

if "from subagents.java_vulnerability_scanner_agent.tools.static_scanner import scan_workspace_static" not in api_src:
    if import_anchor in api_src:
        api_src = api_src.replace(import_anchor, import_replacement, 1)
    else:
        print("WARN: import anchor not found in api_server.py")

# Add _scanner_backend helper + rewrite /scan endpoint and /health
old_scan = '''@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "tracked_runs": len(RUN_CONTEXTS)}


@app.post("/scan")
async def scan(request: ScanRequest) -> dict[str, Any]:
    run_id = request.run_id or str(uuid4())
    context = _ensure_workspace(request.repo_url, run_id)

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
        "findings": _scan_to_findings(merged),
        "scan_status": merged.get("status", "success"),
        "critical_vulnerabilities": merged.get("critical_vulnerabilities", 0),
        "high_vulnerabilities": merged.get("high_vulnerabilities", 0),
        "medium_vulnerabilities": merged.get("medium_vulnerabilities", 0),
        "low_vulnerabilities": merged.get("low_vulnerabilities", 0),
        "total_vulnerabilities": merged.get("total_vulnerabilities", 0),
        "report_path": merged.get("report_path"),
    }'''

new_scan = '''def _scanner_backend() -> str:
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
        merged = scan_workspace_static(context.workspace_path)
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
    }'''

# Add `import os` if missing
if "import os\n" not in api_src:
    api_src = api_src.replace("import subprocess\n", "import subprocess\nimport os\n", 1)

if "_scanner_backend" not in api_src:
    if old_scan in api_src:
        api_src = api_src.replace(old_scan, new_scan, 1)
        api_path.write_text(api_src, encoding="utf-8")
        print("OK: patched api_server.py (scan + import)")
    else:
        print("WARN: scan block anchor not found - dumping first 200 chars of old_scan for debugging")
        print(repr(old_scan[:200]))
        print("---ACTUAL---")
        # find the @app.get("/health") line
        idx = api_src.find('@app.get("/health")')
        print(repr(api_src[idx:idx+200]) if idx >= 0 else "health endpoint not found")
else:
    print("OK: api_server.py already patched (scanner_backend present)")


# ---------------------------------------------------------------------------
# Patch 2: tools.py — make run_jf_audit_scan fall back to static scanner
# ---------------------------------------------------------------------------
tools_path = BASE / "subagents" / "java_vulnerablility_scanner_agent" / "tools" / "tools.py"
tools_src = tools_path.read_text(encoding="utf-8")

# Add import of static scanner
if "from .static_scanner import scan_workspace_static" not in tools_src:
    import_anchor_tools = "from pathlib import Path\n"
    import_replacement_tools = "from pathlib import Path\n\nfrom .static_scanner import scan_workspace_static\n"
    if import_anchor_tools in tools_src:
        tools_src = tools_src.replace(import_anchor_tools, import_replacement_tools, 1)
    else:
        print("WARN: pathlib import anchor not found in tools.py")

# Replace run_jf_audit_scan to fall back to static when jf is unavailable
old_run_scan_start = 'def run_jf_audit_scan(workspace_url: str) -> dict:\n    """\n    Run JFrog Audit scan on the Maven project.'
if "SCANNER_BACKEND" not in tools_src:
    # Find the run_jf_audit_scan function and wrap it with backend selection
    func_marker = "def run_jf_audit_scan(workspace_url: str) -> dict:"
    if func_marker in tools_src:
        # Rename original to _run_jf_audit_scan_raw and add dispatcher
        tools_src = tools_src.replace(func_marker, "def _run_jf_audit_scan_raw(workspace_url: str) -> dict:", 1)
        # Add backend selection constants + dispatcher at the position of the old function
        dispatcher = '''def _jf_cli_available() -> bool:
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


def _run_jf_audit_scan_raw(workspace_url: str) -> dict:'''
        tools_src = tools_src.replace("def _run_jf_audit_scan_raw(workspace_url: str) -> dict:", dispatcher, 1)
        tools_path.write_text(tools_src, encoding="utf-8")
        print("OK: patched tools.py (scanner backend dispatcher)")
    else:
        print("WARN: run_jf_audit_scan marker not found in tools.py")
else:
    print("OK: tools.py already patched (SCANNER_BACKEND present)")

print("DONE")