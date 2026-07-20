# Java Vulnerabilities Remover

## Overview
This is a multi-agent workflow to scan and fix Java Maven project vulnerabilities using JFrog Audit.

## Agents Included

### 1. Java Vulnerability Scanner Agent
- **Purpose:** Scans the Maven project for security vulnerabilities
- **Action:** Executes `jf audit --mvn` in the workspace root
- **Output:** Comprehensive vulnerability report with counts and affected dependencies

### 2. Java Vulnerability Fixer Agent
- **Purpose:** Fixes identified vulnerabilities by updating Maven dependencies
- **Actions:**
  - Updates pom.xml with recommended fixed versions
  - Runs tests to validate changes
  - Performs iterative remediation until all High/Critical vulnerabilities are eliminated
  - Starts the application to verify runtime stability

## Workflow

The agents work sequentially:
1. **Scanner Agent** -> Scans for vulnerabilities and creates report
2. **Fixer Agent** -> Reads report, fixes vulnerabilities, validates changes

## Success Criteria

The workflow is considered successful when:
1. `jf audit --mvn` reports ZERO High and ZERO Critical vulnerabilities
2. All Maven tests pass
3. Application starts successfully

## Usage

Run with: `Start the scan` or similar command to trigger the workflow.

## ADK Wrapper API Server

This project now includes an HTTP wrapper service used by `hackathon_prototype_v2`.

### Start the wrapper

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn api_server:app --host 127.0.0.1 --port 8081
```

### Exposed endpoints

- `POST /scan` (accepts `repo_url`, optional `run_id`)
- `POST /remediate/plan`
- `POST /remediate/apply`
- `POST /validate`
- `POST /report`
- `DELETE /runs/{run_id}` (cleanup temporary cloned workspace)

### URL-based scan flow

1. Accept GitHub repository URL from caller.
2. Clone repository into temporary local workspace.
3. Run `jf audit --mvn --fixable-only` from cloned workspace.
4. Return normalized findings and remediation targets.

## Tools Used

### Scanner Agent Tools
- `run_jf_audit_scan` - Runs JFrog audit scan
- `parse_vulnerability_report` - Parses scan results

### Fixer Agent Tools
- `update_pom_xml` - Updates dependencies in pom.xml
- `run_mvn_clean_install` - Builds project with Maven
- `run_mvn_test` - Runs test suite
- `start_application` - Starts Spring Boot application
- `extract_recommended_versions` - Extracts fix recommendations

## Configuration

- **Java Version:** Requires Java/Maven environment
- **Tools:** JFrog CLI (`jf`) must be installed
- **Timeout:** Individual operations timeout after specific durations
- **Memory:** Findings stored in the memoey context between agents
