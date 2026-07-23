"""Test runner module — runs language-appropriate tests after remediation.

Executes:
  - Java/Maven: mvn test
  - Python: pytest
  - Node.js: npm test

Returns structured results for the UI and report.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "target", ".adk_artifacts"}


def detect_all_services(workspace_url: str) -> list[tuple[str, Path]]:
    """Find all (language, dir) services."""
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


def run_tests(workspace_url: str, languages: list[str] | None = None) -> dict[str, Any]:
    """Run tests for all services in the workspace.

    Returns:
        {
            "status": "passed" | "failed" | "error",
            "total_services": int,
            "results": [
                {
                    "language": "java" | "python" | "nodejs",
                    "service_dir": "java-service",
                    "passed": bool,
                    "tests_run": int,
                    "tests_passed": int,
                    "tests_failed": int,
                    "output": "last 500 chars of test output",
                    "error": "error message if failed"
                }
            ]
        }
    """
    services = detect_all_services(workspace_url)
    # Filter by selected languages if provided
    if languages:
        lang_map = {"java": "java", "python": "python", "nodejs": "nodejs"}
        services = [(lang, d) for lang, d in services if lang in (languages or [])]
    results: list[dict[str, Any]] = []
    any_failed = False

    for lang, svc_dir in services:
        if lang == "java":
            result = _run_java_tests(svc_dir)
        elif lang == "python":
            result = _run_python_tests(svc_dir)
        elif lang == "nodejs":
            result = _run_nodejs_tests(svc_dir)
        else:
            continue

        result["language"] = lang
        result["service_dir"] = svc_dir.name
        if not result["passed"]:
            any_failed = True
        results.append(result)

    return {
        "status": "failed" if any_failed else "passed",
        "total_services": len(results),
        "passed_services": sum(1 for r in results if r["passed"]),
        "failed_services": sum(1 for r in results if not r["passed"]),
        "results": results,
    }


def _run_java_tests(svc_dir: Path) -> dict[str, Any]:
    """Run mvn test in the Java service directory."""
    try:
        proc = subprocess.run(
            ["mvn", "test", "-q", "--no-transfer-progress"],
            cwd=str(svc_dir),
            capture_output=True,
            text=True,
            timeout=300,  # 5 min max
        )
        output = proc.stdout + proc.stderr
        passed = proc.returncode == 0

        # Parse test counts from Maven output
        tests_run = 0
        tests_failed = 0
        for line in output.splitlines():
            if "Tests run:" in line:
                import re
                m = re.search(r"Tests run:\s*(\d+),\s*Failures:\s*(\d+)", line)
                if m:
                    tests_run += int(m.group(1))
                    tests_failed += int(m.group(2))

        return {
            "passed": passed,
            "tests_run": tests_run,
            "tests_passed": tests_run - tests_failed,
            "tests_failed": tests_failed,
            "output": output[-500:] if output else "",
            "error": "" if passed else f"mvn test exited with code {proc.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": "Test execution timed out (5 min)"}
    except FileNotFoundError:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": "Maven (mvn) not installed"}
    except Exception as exc:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": str(exc)}


def _run_python_tests(svc_dir: Path) -> dict[str, Any]:
    """Run pytest in the Python service directory."""
    try:
        proc = subprocess.run(
            ["python", "-m", "pytest", "-v", "--tb=short"],
            cwd=str(svc_dir),
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = proc.stdout + proc.stderr
        passed = proc.returncode == 0

        # Parse pytest output
        import re
        tests_run = 0
        tests_failed = 0
        m = re.search(r"(\d+) passed", output)
        if m:
            tests_run += int(m.group(1))
        m = re.search(r"(\d+) failed", output)
        if m:
            tests_failed += int(m.group(1))
            tests_run += tests_failed

        return {
            "passed": passed,
            "tests_run": tests_run,
            "tests_passed": tests_run - tests_failed,
            "tests_failed": tests_failed,
            "output": output[-500:] if output else "",
            "error": "" if passed else f"pytest exited with code {proc.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": "Test execution timed out (2 min)"}
    except FileNotFoundError:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": "pytest not installed"}
    except Exception as exc:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": str(exc)}


def _run_nodejs_tests(svc_dir: Path) -> dict[str, Any]:
    """Run npm test in the Node.js service directory."""
    try:
        # Install deps first if node_modules doesn't exist
        if not (svc_dir / "node_modules").exists():
            subprocess.run(["npm", "install", "--silent"], cwd=str(svc_dir), capture_output=True, timeout=120)

        proc = subprocess.run(
            ["npm", "test", "--silent"],
            cwd=str(svc_dir),
            capture_output=True,
            text=True,
            timeout=120,
            shell=True,  # npm needs shell on Windows
        )
        output = proc.stdout + proc.stderr
        passed = proc.returncode == 0

        return {
            "passed": passed,
            "tests_run": 1,  # npm test doesn't always report counts
            "tests_passed": 1 if passed else 0,
            "tests_failed": 0 if passed else 1,
            "output": output[-500:] if output else "",
            "error": "" if passed else f"npm test exited with code {proc.returncode}",
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": "Test execution timed out"}
    except FileNotFoundError:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": "npm not installed"}
    except Exception as exc:
        return {"passed": False, "tests_run": 0, "tests_passed": 0, "tests_failed": 0, "output": "", "error": str(exc)}