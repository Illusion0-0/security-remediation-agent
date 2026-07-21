@echo off
REM ============================================================================
REM Security Remediation Agent - Startup Script (Windows)
REM ============================================================================
REM Starts the ADK wrapper API server (Service B) on port 8081.
REM
REM Configuration (set before running or export in your environment):
REM   ADK_MODEL          = claude-sonnet | claude-opus | glm-4 | gemini-2.5-flash | gpt-4o
REM   SCANNER_BACKEND    = auto | jf | static     (default: auto)
REM   ANTHROPIC_API_KEY  = sk-ant-...             (for Claude)
REM   GOOGLE_API_KEY     = ...                    (for Gemini)
REM   ZHIPUAI_API_KEY    = ...                    (for GLM)
REM ============================================================================

cd /d "%~dp0"

REM Use the project venv
set "PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo [ERROR] Virtual environment not found. Creating one...
    python -m venv .venv
    set "PYTHON=%~dp0.venv\Scripts\python.exe"
    "%PYTHON%" -m pip install --upgrade pip
    "%PYTHON%" -m pip install --only-binary :all: -r requirements.txt
)

echo.
echo ============================================================
echo  Security Remediation Agent (Service B - ADK Wrapper)
echo ============================================================
echo  Model:    %ADK_MODEL% (auto-detected if empty)
echo  Scanner:  %SCANNER_BACKEND% (auto = jf if available, else static)
echo  Port:     8081
echo ============================================================
echo.

"%PYTHON%" -m uvicorn api_server:app --host 127.0.0.1 --port 8081 --reload