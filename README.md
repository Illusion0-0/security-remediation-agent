# Security Remediation Agent

AI-Assisted Secure Software Development (Hackathon 2026 — Example 2.4).

Multi-language vulnerability remediation agent built on Google ADK with pluggable
LLM support (Claude / GLM / Gemini / OpenAI).

## Features

- **Multi-language scanning** — Java/Maven, Python/pip, Node.js/npm (auto-detected)
- **Pluggable scanner backend** — static CVE database (offline) or JFrog CLI
- **Pluggable LLM** — Claude (default), GLM-4, Gemini, or GPT-4o via LiteLLM
- **Cross-model judge** — a second LLM independently reviews each remediation
- **GitHub PR creation** — real pull requests via the GitHub REST API
- **ADK agents** — scanner + fixer agents with tool integrations

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --only-binary :all: -r requirements.txt

# Configure model (auto-detects from available API keys)
$env:ADK_MODEL = "claude-sonnet"   # or gemini-2.5-flash, glm-4, gpt-4o
$env:SCANNER_BACKEND = "static"    # offline CVE database

# Start the agent server (port 8081)
.\start_agent.bat
```

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Service health + active scanner backend |
| `POST /scan` | Scan a workspace (auto-detects Java/Python/Node.js) |
| `POST /judge` | Cross-model review of remediation proposals |
| `POST /remediate/plan` | Generate fix proposals from findings |
| `POST /remediate/apply` | Apply fixes + create GitHub PR |
| `POST /validate` | Validate build/tests after remediation |
| `POST /report` | Generate evidence bundle |
| `DELETE /runs/{run_id}` | Cleanup workspace |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ADK_MODEL` | auto | `claude-sonnet`, `glm-4`, `gemini-2.5-flash`, `gpt-4o` |
| `SCANNER_BACKEND` | auto | `static`, `jf`, or `auto` (jf if available) |
| `GH_TOKEN` | — | GitHub token for PR creation |
| `ANTHROPIC_API_KEY` | — | For Claude |
| `GOOGLE_API_KEY` | — | For Gemini |
| `ZHIPUAI_API_KEY` | — | For GLM-4 |

## Architecture

```
api_server.py              <- FastAPI wrapper exposing /scan, /judge, /remediate/*
multi_scanner.py           <- Multi-language static CVE scanner
cross_model_judge.py       <- Cross-model judge (LiteLLM)
github_pr.py               <- GitHub PR creation via REST API
model_config.py            <- Pluggable LLM resolution
agent.py                   <- ADK SequentialAgent (scanner -> fixer)
subagents/                 <- Scanner + Fixer ADK agents with tools