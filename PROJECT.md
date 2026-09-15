# Project ARES: Defense Threat Intelligence & Alert Prioritisation Assistant

> **IBM Bob AI Hackathon 2026 Submission** | Problem Statement D2: Cyber-Physical Threat Intelligence Correlation & Alert Prioritisation Assistant

---

## 1. Overview & Purpose
**Project ARES** is a real-time, cross-domain threat intelligence correlation, alert prioritization, and tactical decision-support assistant designed for joint cyber-physical defense operations. It correlates disparate, noisy sensor streams (Enterprise SIEM, Ground Station EDR, Satellite Electronic Warfare/RF feeds, and Industrial SCADA/PLC telemetry) into unified, prioritized incident clusters, maps adversary behaviors to MITRE ATT&CK Enterprise and ICS matrices, and synthesizes military-standard **BLUF** (Bottom Line Up Front) intelligence briefings with wargamed **Courses of Action (COAs)** powered by IBM watsonx.ai Granite 3.0 and IBM Bob.

---

## 2. Tech Stack
- **Language**: Python 3.12.10
- **Backend & APIs**: FastAPI, Uvicorn, Pydantic v2, HTTPX
- **Graph & Algorithms**: NetworkX (spatio-temporal sliding window graph), NumPy, SciPy (Shannon Entropy anti-chaff filter)
- **AI & LLM Integration**: IBM watsonx.ai Granite 3.0 (`ibm/granite-3-8b-instruct`), IBM Granite Guardian (hallucination & safety filter), Model Context Protocol (MCP) server for IBM Bob integration
- **Tactical Dashboard**: Modern dark-theme Commander Tactical War Room Web UI (HTML5, Vanilla ES6+, CSS Glassmorphism, Chart.js)
- **Testing & QA**: Pytest, Automated CI/CD validation simulator (`.github/workflows/validate.yml`)

---

## 3. Project Structure
```
D:\ibm\bob-ai-hackathon-pretzel\
├── run.bat                          # Starts the Tactical War Room server (http://127.0.0.1:8000)
├── stop.bat                         # Stops the active server process cleanly
├── restart.bat                      # Restarts the server
├── test.bat                         # Runs the full test suite (pytest + benchmarks + CLI)
├── submission.yaml                  # Hackathon metadata, architecture, and submission declaration
├── README.md                        # Master project documentation
├── PROJECT.md                       # Project context and execution guide (this file)
├── docs/                            # Deep architectural and problem statement documentation
│   ├── problem-statement.md         # Detailed PS breakdown & operational challenges
│   ├── solution-overview.md         # 5-step pipeline and architectural methodology
│   ├── architecture.md              # System data flows and sequence diagrams
│   └── setup-guide.md               # Step-by-step local setup and troubleshooting
├── demo/                            # Demo materials
│   └── demo-video-link.txt          # Video link declaration
├── bob_sessions/                    # IBM Bob AI Shell session transcripts
│   └── session_task_history.md      # Command history and MCP tool invocations
└── src/                             # Core application source code
    ├── api.py                       # FastAPI REST backend server
    ├── cli.py                       # Terminal CLI interface for 5-step pipeline
    ├── mcp_server.py                # IBM Bob Model Context Protocol (MCP) server
    ├── requirements.txt             # Python dependencies
    ├── ai/                          # AI and LLM reasoning modules
    │   ├── watsonx_client.py        # IBM watsonx Granite 3.0 & Granite Guardian client
    │   ├── mitre_mapper.py          # MITRE ATT&CK mapper and tactic confidence engine
    │   ├── bluf_generator.py        # BLUF executive summarizer & COA wargamer
    │   └── provenance_tracker.py    # SHA-256 cryptographic provenance verification
    ├── engine/                      # Core correlation and processing engine
    │   ├── schemas.py               # Pydantic data schemas (STIX 2.1, Alerts, Clusters, BLUF)
    │   ├── normalizer.py            # Cross-domain telemetry normalizer (CEF/Syslog/RF)
    │   ├── anti_chaff_filter.py     # Shannon Entropy alert storm & decoy suppressor
    │   └── spatio_temporal_graph.py # Spatio-temporal graph correlation engine
    ├── data/                        # Datasets, MITRE matrices, and fine-tuning data
    │   ├── mitre_attack_loader.py   # MITRE ATT&CK Enterprise and ICS matrix loader
    │   ├── synthetic_scenarios.py   # Multi-domain cyber-physical telemetry generator
    │   └── training_builder.py      # Granite fine-tune JSONL & evaluation benchmark builder
    ├── dashboard/                   # Tactical Commander War Room Web UI
    │   └── index.html               # Live operational dashboard
    └── tests/                       # Automated testing & validation suite
        ├── test_ares_engine.py      # Unit tests for core engine modules
        ├── test_api_endpoints.py    # Integration tests for FastAPI endpoints
        ├── test_submission_validator.py # Hackathon schema & CI validation tests
        └── benchmark_evaluator.py   # Quantitative benchmarks (Recall, F1, Chaff reduction)
```

---

## 4. How to Run & Test (Quick Launch)
All operations can be executed with 1-click batch scripts:

- **Launch Tactical Dashboard**:
  Double-click `run.bat` or run:
  ```cmd
  .\run.bat
  ```
  Then open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.

- **Stop Server**:
  ```cmd
  .\stop.bat
  ```

- **Run Live IBM Bob Cloud Agent (Consumes Bobcoins & Logs Sessions)**:
  ```cmd
  .\test_bob_live.bat
  ```
  *Executes live threat reasoning against IBM Bob Cloud Gateway, calls ARES MCP tools, deducts Bobcoins, and logs the session to `bob_sessions/`.*

- **Run Live IBM watsonx.ai & Granite 3.0 Diagnostics**:
  ```cmd
  .\test_watsonx_live.bat
  ```
  *Tests live IAM token exchange, project authorization, and Granite 3.0 inference using `WATSONX_API_KEY` and `WATSONX_PROJECT_ID`.*

- **Run Custom Telemetry Test (Sample or Custom JSON)**:
  ```cmd
  .\test_custom.bat
  ```
  Or pass your own alerts JSON file directly:
  ```powershell
  & .\.venv\Scripts\python.exe -m src.cli --file path\to\your_alerts.json
  ```
  Or enter alerts interactively in the terminal:
  ```powershell
  & .\.venv\Scripts\python.exe -m src.cli --interactive
  ```

- **Run Automated Test Suite (16 Pytest tests + Benchmarks + CLI)**:
  ```cmd
  .\test.bat
  ```

- **Run CLI Simulation Directly**:
  ```powershell
  & .\.venv\Scripts\python.exe -m src.cli --scenario apt_hybrid
  & .\.venv\Scripts\python.exe -m src.cli --scenario chaff_flood --sector Sector-2-East
  & .\.venv\Scripts\python.exe -m src.cli --scenario benign --sector Sector-3-Central
  ```

---

## 5. Key Features Implemented
1. **Multi-Domain Ingestion & Normalization**: Ingests SIEM (Syslog/CEF), Ground Station EDR, Satellite RF Jamming/EW telemetry, and SCADA Modbus PLC signals, normalizing them into STIX 2.1 entities with cryptographic SHA-256 provenance hashes.
2. **Custom Alert Ingestion (CLI, Web UI & API)**: Analysts can inject custom threat alerts directly via interactive CLI prompt, custom JSON/JSONL files, REST API `/api/ingest`, or the War Room UI modal.
3. **Shannon Entropy Anti-Chaff Storm Filtering**: Evaluates streaming alert entropy ($H < 2.2$) to suppress synthetic adversary chaff floods by 92.5%, isolating low-and-slow zero-day indicators.
4. **Spatio-Temporal Graph Correlation**: NetworkX graph engine clustering cross-domain alerts via temporal proximity (30-minute sliding window) and subnet co-occurrence, computing Bayesian threat confidence.
5. **MITRE ATT&CK Matrix Mapping**: Automated mapping against MITRE Enterprise & ICS matrices, identifying TTPs (`T1059`, `T0814`, `T1078`), defense mitigations, and adversary attribution (e.g. APT28 / Sandworm).
6. **watsonx.ai Granite 3.0 BLUF Generation**: Military-grade tactical briefings ("Bottom Line Up Front") with three wargamed Courses of Action (COAs) and Granite Guardian hallucination checks (Grounding score: 0.980).
7. **Commander Tactical War Room UI**: Responsive dark-theme dashboard with live cluster inspection, interactive COA dispatching, sector switching, custom alert injector modal, and Markdown report export.
8. **IBM Bob MCP Server**: Implements the Model Context Protocol standard exposing `ares_ingest_telemetry`, `ares_correlate_threats`, and `ares_generate_bluf`.
9. **0-Coin Local Execution**: Built-in deterministic fallback ensuring complete testing without consuming user Bobcoins or cloud credits.

---

- **2026-09-15**: Refined known limitations and operational architecture documentation (`README.md`, `submission.yaml`): articulated defense OPSEC telemetry compliance (NASA CCSDS/ESA standards with plug-and-play adapter connectors) and resilient multi-tier AI execution (Live IBM watsonx.ai Granite 4 / IBM Bob Cloud vs. Air-Gapped Zero-Token Edge mode).
- **2026-09-15**: Connected and verified live **IBM watsonx.ai Foundation Models** in `eu-de` (Frankfurt) using `ibm/granite-4-h-small` and project `793d5a80-258a-4de1-b962-6f8c2a8987fa`, achieving 100% live cloud text generation with zero fallback errors.
- **2026-09-15**: Integrated live IBM Bob (`BOB_API_KEY`) and IBM Cloud watsonx.ai (`WATSONX_API_KEY`), verified Bobcoin consumption across 5 cloud tasks, added `test_bob_live.bat` and `test_watsonx_live.bat`.
- **2026-09-15**: Built multi-tier AI routing (`watsonx_client.py`) with automatic fallback to live Bob agent and local deterministic Granite engine.
- **2026-09-15**: Added Custom Alert testing support: `--file`, `--interactive`, `--scenario custom`, `test_custom.bat`, `src/data/sample_custom_alerts.json`, and UI modal injector.
- **2026-09-15**: Added 1-click batch launcher scripts (`run.bat`, `stop.bat`, `restart.bat`, `test.bat`) adhering to `project-run` skill.
- **2026-09-15**: Created `PROJECT.md` single source of truth context file adhering to `project-context` skill.
- **2026-09-15**: Validated all 16 automated pytest tests, benchmark metrics (100% recall, 92.5% chaff reduction), and CLI simulations.
- **2026-09-14**: Built Commander Tactical War Room Web UI (`src/dashboard/index.html`) with glassmorphism design and live REST integration.
- **2026-09-14**: Developed FastAPI REST API server (`src/api.py`) exposing health, ingestion, correlation, and BLUF endpoints.
- **2026-09-14**: Implemented IBM Bob Model Context Protocol server (`src/mcp_server.py`).
- **2026-09-14**: Integrated MITRE ATT&CK loader, spatio-temporal graph, and Shannon entropy filter into core engine.
- **2026-09-14**: Generated synthetic multi-domain cyber-physical scenarios (`src/data/synthetic_scenarios.py`).
