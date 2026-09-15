# ARES Full Architecture & Implementation Phases

Based on the team alignment plans and the ML/Claude agent architecture, here is the complete project architecture mapped out in phases. 

## Phase 1: Data Ingestion, Normalisation & Staging
**Goal:** Gather all required multi-domain datasets, add timestamps, and normalize them into STIX 2.1 JSON schema.

### Data Sources to Download
*   **MITRE ATT&CK STIX Bundles**: [MITRE CTI GitHub](https://github.com/mitre/cti)
*   **CISA KEV (Known Exploited Vulnerabilities)**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
*   **EVTX-ATTACK-SAMPLES (evtx_data.csv)**: [OTRF/Security-Datasets (formerly Mordor)](https://github.com/OTRF/Security-Datasets)
*   **Telemanom Satellite Anomalies**: [Telemanom GitHub](https://github.com/khundman/telemanom)
*   **Emerging Threats Suricata Rules**: [Proofpoint Emerging Threats](https://rules.emergingthreats.net/open/suricata/)
*   **CIC-IDS2018 Network Flows**: [UNB CIC Datasets](https://www.unb.ca/cic/datasets/ids-2018.html)
*   **NORAD Satellite Ephemeris (CelesTrak)**: [CelesTrak GP API](https://celestrak.org/NORAD/elements/)

### Normalisation (Layer 1)
*   **Tooling**: Python (`src/engine/normalizer.py`), Pydantic models for STIX 2.1 (`src/engine/schemas.py`).
*   **Action**: Unify all datasets by appending strict `x_timestamp`s to ensure the correlation engine can map disparate events to identical time windows. 
*   **Output**: Produces a unified `fused_dataset.json` containing standardized Indicator, ObservedData, and Vulnerability objects.

---

## Phase 2: Live Log Transmission & Simulation
**Goal**: Create a realistic "live" telemetry feed to stress-test the correlation engine.

### Transmission (Layer 2)
*   **Tooling**: Python Replay Simulator (`src/log_transmitter.py`).
*   **Action**: Instead of static logs, run a log transmitter or integrate with an open-source SIEM simulator (like Splunk Attack Range) to simulate high-fidelity attacks across endpoints and networks.
*   **Output**: Live streaming events broadcasted for ingestion.

---

## Phase 3: Entity Extraction & STIX Conversion
**Goal**: Transform simulated raw streams into formal threat intelligence graph components.

### Conversion (Layer 3)
*   **Tooling**: `stix_converter.py` and `StixStore`.
*   **Action**: Convert incoming streaming events into STIX 2.1 objects (Indicators, Observables).
*   **Output**: A populated `StixStore` (time-series event store / in-memory knowledge base).

---

## Phase 4: MITRE ATT&CK TTP Mapping
**Goal**: Classify abstract attacks to documented techniques.

### TTP Linker (Layer 4)
*   **Tooling**: `technique_linker.py`, `mitre_mapper.py` using `ibm/granite-3-8b-instruct`.
*   **Action**: Map raw payload strings and observed behaviors to the MITRE ATT&CK matrix (Enterprise & ICS) via semantic search (`all-MiniLM-L6-v2`) and LLM validation.
*   **Output**: Enriched alerts with exact Tactics, Techniques, and mitigation arrays.

---

## Phase 5: Spatio-Temporal Correlation & Fusion
**Goal**: The core differentiator—identifying stealth attacks inside massive alert storms.

### Fusion Engine (Layer 5)
*   **Tooling**: `src/engine/spatio_temporal_graph.py`, `anti_chaff_filter.py`.
*   **Action**: 
    1.  **L1 - Deterministic:** Match IOCs over strict time windows.
    2.  **L2 - Graph-Based:** Build a temporal entity graph (NetworkX) to find connected attack clusters.
    3.  **L3 - Anti-Chaff:** Use a Shannon Entropy filter to discard adversarial decoy alerts (chaff) and surface stealth threats.
*   **Output**: Correlated Incident Clusters ready for ML scoring.

---

## Phase 6: Machine Learning Confidence Scoring
**Goal**: Rank and prioritize the correlated threat clusters.

### ML Prioritisation (Layer 6)
*   **Tooling**: `ml_model.py`, Bayesian multi-hypothesis tracker.
*   **Action**: Blend rule-based scores (from Phase 5) with ML confidence scores. Adjust for CISA KEV presence and attack asset criticality.
*   **Output**: Ranked `CorrelatedAlert` objects with computed Severities (LOW to CRITICAL).

---

## Phase 7: Automated BLUF Intelligence Generation
**Goal**: Synthesize complex data into commander-ready briefings.

### BLUF Generator (Layer 7)
*   **Tooling**: `src/ai/bluf_generator.py`, `ibm/granite-3-8b-instruct`, `watsonx Granite Guardian`.
*   **Action**: Convert the highest severity alerts into military-standard **Bottom Line Up Front (BLUF)** reports. Run Granite Guardian to verify zero-hallucinations (ensuring every claim links back to a sensor ID via cryptographic provenance).
*   **Output**: Structured markdown / STIX Report output containing Wargamed Courses of Action (COAs).

---

## Phase 8: REST API & User Interface
**Goal**: Expose the intelligence via backend API and interactive Tactical War Room.

### FastAPI & React Frontend (Layer 8 & 9)
*   **Tooling**: FastAPI (`src/api.py`), React/Vite/Tailwind (`src/src/App.tsx`).
*   **Action**: 
    *   API endpoints (`/ingest/run`, `/alerts`, `/reports`) bridge the python backend to the frontend.
    *   React UI renders dark-theme tactical dashboards, displaying live telemetry, dynamic MITRE heatmaps, and the generated BLUF briefings.
*   **Output**: Fully functioning Sentinel-X Tactical War Room interface.

---

## Phase 9: IBM Bob Integration (War Room Assistant)
**Goal**: Interactive terminal assistance for commanders.

### MCP Server Integration
*   **Tooling**: `src/mcp_server.py`, IBM Bob CLI.
*   **Action**: Expose tools (`correlate_threat_feeds`, `generate_bluf_briefing`, `simulate_coa_impact`) to IBM Bob via the Model Context Protocol, enabling operators to query the intelligence platform naturally from their terminal.
*   **Output**: Live terminal demo sessions showcasing natural language interaction with the system.
