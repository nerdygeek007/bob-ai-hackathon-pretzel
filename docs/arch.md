# System Architecture

## End-to-End Data Flow

```mermaid
graph TD
    subgraph "1. Multi-Source Ingestion"
        A1[SIEM Alerts]
        A2[Satellite Feeds]
        A3[Cyber Sensors]
        A4[Intel Reports]
    end

    subgraph "2. Normalization & Integration"
        B[FastMCP Server Adapters]
        C[(STIX 2.1 / Time-Series Event Store)]
    end

    subgraph "3. Correlation & Reasoning"
        D[ST-GNN Correlation Engine]
        E[IBM Bob Subagents]
        F[MITRE ATT&CK v15 RAG Pipeline]
        G[Explainable AI: SHAP & LIME]
    end

    subgraph "4. Presentation & Output"
        H[JADC2 Command Dashboard]
        I[Prioritised BLUF Summaries]
    end

    A1 -->|JSON| B
    A2 -->|CoT Telemetry| B
    A3 -->|Network/Host Context| B
    A4 -->|Unstructured/PDF| B
    
    B -->|Normalize to SDO/SCO| C
    C -->|Query Time Windows| D
    
    D -->|Identify Attack Patterns| E
    D -->|Feature Attribution| G
    
    E <-->|Semantic Search & Mapping| F
    
    E -->|Generate Executive Brief| I
    G -->|Visual Trust Metrics| H
    I --> H
