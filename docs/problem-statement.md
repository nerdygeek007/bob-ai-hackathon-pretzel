# Problem Statement

## Background
Modern security operations span hybrid environments that include traditional enterprise IT (Windows event logs, Active Directory, cloud infrastructure), cyber-physical telemetry, and aerospace systems (satellite downlinks, orbital sensors, and ground station controls). Security Operations Centers (SOCs) receive upwards of 10,000 events per second from disparate logging systems.

## The Problem
SOC analysts suffer from severe alert fatigue and fragmented context:
1. **Disconnected Data Streams:** Events from SIEM tools, satellite operations, and network sensors arrive in conflicting proprietary formats without a common temporal or asset baseline.
2. **Alert Overload vs. Real Threat Detection:** Up to 85% of alerts are benign operational noise or duplicate warnings.
3. **Telemetry Misclassification:** Benign operational anomalies (such as satellite thermal fluctuations or orbital radio fade) frequently trigger high-severity cyber alarms, diverting scarce analyst attention from genuine covert lateral movement.
4. **Slow Multi-Stage Correlation:** Correlating multi-stage intrusion campaigns (such as Initial Access brute force leading to Credential Harvesting and Command & Control beaconing) takes hours of manual log queries across separate consoles.

## Who is Affected
- **Tier 1 & Tier 2 SOC Analysts:** Spending hours manually triaging low-context alerts and writing correlation queries.
- **Incident Responders:** Struggling to obtain a single coherent chronological timeline of multi-stage intrusions.
- **Aerospace & Critical Infrastructure Security Teams:** Lacking automated separation between space operational telemetry anomalies and true cyber compromise.

## Why It Matters
Delayed incident detection leads to prolonged dwell times, unauthorized credential compromise, and compromised critical infrastructure. A single missed multi-stage attack can cause devastating financial loss and operational disruption.

## Why Existing Solutions Fall Short
Traditional SIEMs are rules-heavy, alert-noisy, and lack cross-domain correlation. Legacy tools fail to provide explainable risk scoring (e.g. why an alert was prioritized) and do not understand the domain-level difference between physical sensor telemetry and genuine adversary TTPs.
