"""Fix the scanner agent directory name mismatch.

The scanner subagent directory is named 'java_vulnerablility_scanner_agent'
(with a typo: 'vulnerablility' instead of 'vulnerability'). All imports use
the correct spelling, so the server fails to start. This script updates the
imports to match the actual directory name on disk.
"""
from pathlib import Path

BASE = Path(__file__).resolve().parent

WRONG = "java_vulnerability_scanner_agent"
RIGHT = "java_vulnerablility_scanner_agent"  # the actual (misspelled) dir on disk

files_to_fix = [
    BASE / "api_server.py",
    BASE / "agent.py",
]

for fpath in files_to_fix:
    if not fpath.exists():
        print(f"SKIP: {fpath.name} not found")
        continue
    src = fpath.read_text(encoding="utf-8")
    if WRONG in src:
        new_src = src.replace(f"subagents.{WRONG}", f"subagents.{RIGHT}")
        if new_src != src:
            fpath.write_text(new_src, encoding="utf-8")
            count = src.count(f"subagents.{WRONG}")
            print(f"OK: {fpath.name} - fixed {count} import path(s)")
        else:
            print(f"OK: {fpath.name} - no changes needed")
    else:
        print(f"OK: {fpath.name} - already correct")

print("DONE")