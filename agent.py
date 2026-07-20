from google.adk.agents import SequentialAgent
from .subagents.java_vulnerability_scanner_agent.agent import java_vulnerability_scanner_agent
from .subagents.java_vulnerability_fixer_agent.agent import java_vulnerability_fixer_agent

root_agent = SequentialAgent(
    name="java_vulnerabilities_remover",
    description="Agent to scan and fix Java Maven project vulnerabilities using JFrog Audit and dependency updates",
    sub_agents=[java_vulnerability_scanner_agent, java_vulnerability_fixer_agent]
)