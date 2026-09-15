# Solution Overview

## What We Built
**Sentinel-X** is an intelligent Threat Intelligence Correlation & Alert Prioritisation Assistant designed to transform high-volume security noise into actionable incident response. It features an intuitive, modern SaaS interface built with React 19, Tailwind CSS v4, and Recharts, providing security analysts with instant situational awareness in under 10 seconds.

## How It Works
The Sentinel-X pipeline processes incoming security feeds through 5 cohesive stages:

```
LIVE SECURITY EVENTS
        ↓
ML / CORRELATION PROCESSING
        ↓
SUSPICIOUS BEHAVIOR DETECTION
        ↓
ATTACK BEHAVIOR / VECTOR
        ↓
MITRE ATT&CK MAPPING (Intelligence Enrichment)
        ↓
RISK / PRIORITY ASSESSMENT (Explainable Policy)
        ↓
ACTIONABLE ALERT & BLUF REPORT
```

1. **Multi-Domain Ingestion & Canonical Normalization:** Ingests live streams from SIEM (OTRF Mordor Sysmon, EVTX), Satellite Telemetry (NASA JPL Telemanom, ESA OPS-SAT), and Network Sensors into unified schema models.
2. **Temporal & Asset Correlation:** Groups events by target host (e.g. `HOST-042`) and user account within a configurable time window (default: 15 minutes).
3. **MITRE ATT&CK Enrichment:** Maps observed telemetry to recognized tactics and techniques (e.g., `T1110` Brute Force, `T1003.001` LSASS Credential Dumping, `T1059.001` PowerShell, `T1071.001` C2 Beaconing) as an intelligence context layer.
4. **Transparent Risk Scoring & Policy Discrepancy:** Contrasts the raw Source Severity against the Sentinel-X Assessed Priority, presenting clear justification tags (e.g., `+Known Exploit`, `+Critical Asset`, `+Corroborated Campaign`).
5. **Operational Telemetry Isolation Policy:** Enforces strict isolation rules so that raw space telemetry deviations (e.g. thermal radiator anomalies) are tracked as operational issues and never falsely converted into cyber alarms without corroborating cyber signals.

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Modern SaaS UI Design System | Replaced cluttered cyber consoles with clean, high-contrast Dub.co-style design to eliminate analyst fatigue and reduce triage decision times. |
| Client-Side Simulation & State Engine | Enables instant, zero-dependency demonstrations and interactive rate testing without requiring complex cloud broker setups. |
| Strict Telemetry Isolation Policy | Prevents high-noise physical sensor alerts from polluting critical cyber response queues. |
| Responsive Architecture | Allows security leads to review BLUF incident summaries and critical alerts on tablets and mobile devices via responsive drawers. |

## IBM Technologies Used
- **IBM watsonx.ai & Granite Models:** Used for behavioral intent classification and generating automated executive Bottom Line Up Front (BLUF) incident briefs.
- **IBM Bob:** Utilized during architecture planning and code scaffolding for rapid component synthesis.
- **IBM Cloud:** Target cloud deployment foundation for enterprise streaming ingestion.
