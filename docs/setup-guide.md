# Setup & Installation Guide: ARES Defense Intelligence Platform

> **This document contains verified, step-by-step instructions to install, test, and run ARES.**

---

## Prerequisites

Ensure you have the following installed on your machine:

- Python 3.11 or Python 3.12 (`python --version`)
- Git (`git --version`)
- (Optional) IBM Bob CLI (`bob --version`)
- (Optional) IBM Cloud account with watsonx.ai access (if running live cloud inference; local mode requires 0 credentials)

---

## Environment Variables

Copy `.env.example` to `.env`:

```bash
cp src/.env.example .env
```

| Variable | Description | Required | Default / Example |
|---|---|---|---|
| `WATSONX_API_KEY` | IBM watsonx.ai Cloud API key | Optional (uses local mode if unset) | `your_api_key_here` |
| `WATSONX_PROJECT_ID` | watsonx.ai project ID | Optional | `your_project_id_here` |
| `WATSONX_URL` | watsonx.ai endpoint URL | No | `https://us-south.ml.cloud.ibm.com` |
| `APP_PORT` | Port for FastAPI REST backend | No | `8000` |
| `APP_ENV` | Application environment mode | No | `development` |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/drijesh-ppatel/bob-ai-hackathon-pretzel.git
cd bob-ai-hackathon-pretzel

# 2. Create and activate a Python virtual environment
python -m venv .venv

# On Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# 3. Install backend dependencies
pip install -r src/requirements.txt

# 4. Install frontend dependencies
cd src
npm install
cd ..
```

---

## Running the Application

### Option A: Interactive Command Line Interface (CLI)
Run the full 5-step threat intelligence pipeline directly in your terminal:

```powershell
# Scenario 1: Coordinated APT Hybrid Strike (Cyber + Satellite + SCADA)
python -m src.cli --scenario apt_hybrid

# Scenario 2: Adversarial Chaff & Alert Storm (Decoy Flooding)
python -m src.cli --scenario chaff_flood --sector Sector-2-East

# Scenario 3: Benign Background Baseline (Routine Maintenance)
python -m src.cli --scenario benign --sector Sector-3-Central
```

### Option B: Tactical Commander War Room (Web Dashboard)
Start both the FastAPI REST backend and the React frontend simultaneously:

```powershell
.\run.bat
```
Then navigate to: **`http://localhost:5173`** for the UI, and **`http://127.0.0.1:8000`** for the API.

To run them manually:
```powershell
# Terminal 1 (Backend)
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000

# Terminal 2 (Frontend)
cd src
npm run dev
```

### Option C: IBM Bob Model Context Protocol (MCP) Server
To integrate ARES tools directly into IBM Bob:

```powershell
python -m src.mcp_server
```

---

## Running Automated Tests

Run the full automated test suite (10 unit & integration tests covering data ingestion, graph correlation, anti-chaff filtering, and REST endpoints):

```powershell
python -m pytest src/tests/ -v
```

Run the quantitative precision & benchmark evaluator:

```powershell
python -m src.tests.benchmark_evaluator
```

---

## Troubleshooting

| Issue | Root Cause | Solution |
|---|---|---|
| `PSSecurityException: running scripts is disabled` | Windows PowerShell execution policy | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` in PowerShell. |
| `ModuleNotFoundError: No module named 'fastapi'` | Virtual environment not activated | Activate `.venv` using `.\.venv\Scripts\Activate.ps1` or run via `.\.venv\Scripts\python.exe`. |
| `watsonx 401 Unauthorized` | Invalid or expired IBM Cloud API key | Check `WATSONX_API_KEY` in `.env`. Leave empty to run in local zero-cost mode. |
| Port 8000 already in use | Another process listening on port 8000 | Specify a custom port: `python -m uvicorn src.api:app --port 8080`. |
