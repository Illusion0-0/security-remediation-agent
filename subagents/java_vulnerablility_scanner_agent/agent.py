from google.adk.agents import LlmAgent
from google.adk.tools import FunctionTool
from .tools.tools import clone_repository, parse_vulnerability_report, run_jf_audit_scan
from .prompt import JAVA_VULNERABILITY_SCANNER_INSTRUCTION
from model_config import resolve_model

java_vulnerability_scanner_agent = LlmAgent(
    name="java_vulnerability_scanner_agent",
    model=resolve_model(),
    description="Agent to scan Java projects for security vulnerabilities using JFrog Audit",
    instruction=JAVA_VULNERABILITY_SCANNER_INSTRUCTION,
    output_key="vulnerability_scan_report",
    tools=[
        FunctionTool(clone_repository),
        FunctionTool(run_jf_audit_scan),
        FunctionTool(parse_vulnerability_report)
    ]
)