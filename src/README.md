# 🛡️ ARES Source Code Directory Layout

This directory contains the complete source code for **ARES (Automated Reconnaissance & Threat Evaluation System)**, an agentic multi-domain threat correlation and military BLUF prioritisation assistant powered by **IBM Bob (MCP CLI)** and **IBM watsonx.ai Granite 3.0**.

---

## 📁 Layout & Components

```
src/
├── data/                            # 1. Multi-Domain Data & MITRE CTI Ingestion
│   ├── mitre_attack_loader.py       # Downloads & indexes official MITRE STIX 2.1 CTI
│   ├── synthetic_scenarios.py       # Generates multi-source synchronized feeds (SIEM, SAT, EDR)
│   ├── training_builder.py          # Builds Granite 3.0 JSONL fine-tuning data & eval benchmarks
│   └── processed/                   # Generated JSONL, few-shot prompts, & benchmark pairs
│
├── engine/                          # 2. Defense Intelligence & Graph Correlation Core
│   ├── schemas.py                   # Pydantic STIX 2.1 entities, Incident Clusters, & BLUF models
│   ├── normalizer.py                # Extracts IOCs & computes SHA-256 cryptographic provenance
│   ├── anti_chaff_filter.py         # Shannon Entropy & false positive noise suppressor
│   └── spatio_temporal_graph.py     # Spatio-Temporal Knowledge Graph & Bayesian confidence
│
├── ai/                              # 3. watsonx.ai Granite 3.0 & Assurance Layer
│   ├── watsonx_client.py            # IBM Granite 3.0 & Granite Guardian client (with local fallback)
│   ├── mitre_mapper.py              # Classifies attacker TTPs to MITRE ATT&CK Enterprise/ICS matrix
│   ├── bluf_generator.py            # Synthesizes military BLUF briefings & wargames COAs
│   └── provenance_tracker.py        # Cryptographic citation lineage linking BLUF claims to sensor IDs
│
├── dashboard/                       # 4. Tactical Commander War Room UI
│   └── index.html                   # Dark-theme tactical command dashboard
│
├── tests/                           # 5. Automated Verification Test Suite
│   └── test_ares_engine.py          # Pytest suite covering all 5 pipeline stages (100% pass)
│
├── src/                             # 6. React Frontend Application (Sentinel-X)
│   ├── components/                  # React components for the UI
│   ├── pages/                       # UI Pages (Alerts, Dashboard, etc.)
│   └── App.tsx                      # Main React application entry
│
├── mcp_server.py                    # Core IBM Bob MCP Server (Exposes tools to `bob` CLI)
├── api.py                           # FastAPI REST backend server
├── cli.py                           # Interactive CLI tool for full 5-step terminal execution
├── requirements.txt                 # Python dependencies manifest
└── .env.example                     # Environment template (watsonx keys, ports)
```

---

## ⚡ Quick Start & Run Commands

```powershell
# 1. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 2. Run automated test suite (5/5 passed)
python -m pytest src/tests/ -v

# 3. Run full 5-step pipeline via CLI
python -m src.cli --scenario apt_hybrid

# 4. Start REST API & Tactical War Room Web UI
python -m uvicorn src.api:app --host 127.0.0.1 --port 8000 --reload

# 5. Start the React Frontend Application
cd src
npm run dev
```
