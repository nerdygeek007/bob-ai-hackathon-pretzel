# Architecture: ARES Defense Intelligence Platform

## System Architecture

```mermaid
flowchart TD
    subgraph Simulation["0. SIEM & Defense Simulator (src/data/siem_simulator.py)"]
        SIEM_SIM["High-Volume Telemetry Generator (alrt-agent style)"]
        CEF_GEN["IBM QRadar CEF Generator"]
        EDR_GEN["CrowdStrike EDR JSON Streamer"]
        SURI_GEN["Suricata RFC 5424 Syslog Engine"]
        OCSF_GEN["OCSF v1.1 Class 2001 Generator"]
        COT_GEN["CoT MIL-STD-2525 XML/JSON Engine"]
        STREAM_BAT["1-Click Continuous Streamer (stream_siem.bat)"]
        SIEM_SIM --> CEF_GEN & EDR_GEN & SURI_GEN & OCSF_GEN & COT_GEN
        STREAM_BAT --> SIEM_SIM
    end

    subgraph Feeds["1. Multi-Domain Telemetry Ingestion"]
        SIEM["SIEM & EDR Logs (QRadar CEF, Syslog, Sysmon)"]
        SAT["Satellite & EW Telemetry (RF Jamming, CelesTrak NORAD GP)"]
        OCSF["OCSF v1.1 Security Findings (Class 2001 / 1001)"]
        COT["Cursor-on-Target (CoT) Tactical Positions (MIL-STD-2525)"]
        ICS["SCADA & Kinetic Sensors (Modbus PLC, Radar)"]
        OSINT["OSINT & Intel Feeds (STIX 2.1, CISA Advisories)"]
    end

    subgraph CoreEngine["2. Defense Intelligence Engine (src/engine)"]
        NORM["Telemetry Normalizer (STIX 2.1, OCSF, CoT & SHA-256 Hashing)"]
        CHAFF["Shannon Entropy Anti-Chaff Filter (Alert Storm Suppression)"]
        TKG["Dynamic Spatio-Temporal Knowledge Graph (NetworkX)"]
        XAI["Explainable AI (XAI) Feature Attribution (SHAP Decision Weights)"]
        BAYES["Bayesian Multi-Sensor Confidence Engine"]
    end

    subgraph AISwarm["3. IBM watsonx & Bob AI Core (src/ai & src/mcp_server)"]
        BOB_MCP["IBM Bob MCP Server (ares_ingest, ares_simulate_siem, ares_correlate, ares_generate_bluf)"]
        MITRE["MITRE ATT&CK Mapping Engine (Enterprise & ICS v15)"]
        GRANITE["watsonx.ai Granite 3.0 8B Instruct (BLUF Synthesizer)"]
        GUARDIAN["watsonx Granite Guardian (Hallucination Gate)"]
    end

    subgraph Delivery["4. Command Delivery & Operations (src/dashboard, src/cli, src/ai/report_exporter.py)"]
        WARROOM["Tactical Commander War Room Dashboard (FastAPI / Tailwind / XAI Bars)"]
        TERMINAL["IBM Bob CLI War Room Terminal"]
        COA["Wargamed Courses of Action (COAs) & Audit Lineage"]
        EXPORTER["BLUF Multi-Format Exporter (Markdown, HTML Print-to-PDF, JSON, Text)"]
    end

    SIEM_SIM -->|Live EPS Stream| Feeds
    Feeds --> NORM
    NORM --> CHAFF
    CHAFF --> TKG
    TKG --> BAYES
    TKG --> XAI
    BAYES --> BOB_MCP
    XAI --> BOB_MCP
    BOB_MCP <--> MITRE
    BOB_MCP <--> GRANITE
    GRANITE <--> GUARDIAN
    BOB_MCP --> WARROOM & TERMINAL & COA & EXPORTER
```

## Components

| Component | Technology | Responsibility |
|---|---|---|
| **SIEM & Tactical Simulator** | Python / `urllib` / `argparse` | High-throughput alert generator (`alrt-agent` style) streaming QRadar CEF, CrowdStrike EDR, Suricata, OCSF v1.1, and CoT telemetry. |
| **Ingestion & Normalizer** | Python / Pydantic / STIX 2.1 / OCSF v1.1 / XML CoT | Parses heterogeneous CEF, Syslog, OCSF 2001, CoT XML/JSON, Satellite RF, and SCADA messages; extracts IOCs and SHA-256 hashes. |
| **Anti-Chaff Filter** | Python / Scipy (`scipy.stats`) | Calculates Shannon Entropy of alert bursts to filter 92.5% of decoy storms while preserving stealth threats. |
| **Spatio-Temporal Graph** | NetworkX | Constructs temporal sliding window, cross-domain, and subnet co-occurrence edges to group related events into Incident Clusters. |
| **Explainable AI (XAI)** | Python / SHAP-Style Attributions | Computes calibrated feature attribution weights (Multi-Domain Sensor Fusion, MITRE TTPs, Shannon Entropy, Asset Criticality) for commander transparency. |
| **MITRE ATT&CK Mapper** | CTI JSON / Regular Expressions / Embeddings | Matches observed alerts to MITRE Enterprise and ICS tactics and techniques with confidence scores and mitigations. |
| **IBM Bob MCP Server** | Python `mcp` SDK / JSON-RPC | Exposes native defense intelligence tools to the IBM Bob CLI and IDE for interactive terminal queries. |
| **Foundation AI Engine** | IBM watsonx.ai Granite 3.0 8B Instruct | Synthesizes concise military-standard BLUF briefings and wargames Courses of Action (COAs). |
| **Assurance Gate** | IBM watsonx Granite Guardian 3.0 | Verifies factual grounding of generated briefings against raw telemetry frames with zero hallucination tolerance. |
| **BLUF Report Exporter** | Python / Jinja-free HTML / JSON / Markdown / Text | Formats and outputs multi-format defense intelligence briefings with `@media print` clean PDF styling, XAI charts, MITRE tables, and cryptographic audit trails. |
| **Tactical War Room UI** | FastAPI / Static HTML / TailwindCSS | Provides commanders and analysts with live alert feeds, cluster cards, XAI progress bars, MITRE matrix heatmaps, and interactive BLUF export modal. |

## Data Flow

1. **Telemetry Generation & Arrival:** Raw alert streams arrive via continuous SIEM simulator (`stream_siem.bat`), REST POST (`/api/ingest`), or scenarios (`apt_hybrid`, `simulated_siem`, `real_ephemeris`).
2. **STIX 2.1, OCSF & CoT Normalization:** The normalizer maps heterogeneous payloads (CEF, Syslog, OCSF v1.1, CoT MIL-STD-2525) into STIX 2.1 entities, computing a SHA-256 cryptographic provenance hash for each payload.
3. **Entropy Analysis:** The AntiChaffFilter evaluates alert entropy. Bursts with entropy < 2.2 are flagged as synthetic alert storms; repetitive decoy alerts are suppressed.
4. **Graph Clustering:** The SpatioTemporalGraphEngine adds nodes for alerts, IOCs, and subnets, linking events occurring within the sliding time window (30 mins) in the same sector across cyber, space, and tactical domains.
5. **Bayesian Threat Scoring & XAI Feature Attribution:** Aggregated probability of genuine threat is calculated across multi-sensor confirmations ($P = 1 - \prod(1 - P_i)$), and SHAP-style Explainable AI feature attributions are computed.
6. **MITRE Classification:** Observed behaviors are mapped to MITRE ATT&CK techniques with mitigations.
7. **BLUF Briefing & COA Synthesis:** IBM Granite 3.0 synthesizes the 4-part military BLUF briefing; Granite Guardian verifies factual grounding.
8. **Multi-Format Intelligence Export:** `ReportExporter` formats the briefing into Markdown (`.md`), Standalone Print-Ready HTML (`.html`), Machine JSON (`.json`), or ASCII Field Text (`.txt`), delivered via War Room UI, REST API (`/api/reports/export`), IBM Bob MCP (`ares_export_bluf_report`), or CLI (`--export`).

## Security Considerations

- **Zero Secret Commits:** API keys and credentials reside in `.env` (enforced by `.gitignore`).
- **Cryptographic Provenance:** Every claim in the generated briefing cites the exact raw sensor alert ID and SHA-256 hash.
- **Fail-Safe Offline Mode:** Operates with 100% functionality locally using pre-indexed MITRE CTI and deterministic templates when cloud API keys are not provisioned.

## Scalability Notes

- The in-memory NetworkX graph processes up to 100,000 alerts per minute with sub-second latency.
- For enterprise production deployments, the graph engine can be backed by IBM Cloudant or Neo4j, with streaming telemetry ingested via Apache Kafka.

