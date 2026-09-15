# 🚀 Sentinel-X: Threat Intelligence Correlation & Alert Prioritisation Assistant

> Modern SaaS platform for multi-domain threat correlation, MITRE ATT&CK mapping, and explainable alert triage.

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | Pretzel |
| **Track** | AI |
| **Team Lead** | Chaitanya Thakar — chaitanythakar851@gmail.com |
| **Members** | Visha Kardani, Maharshi Trivedi, Tirth Bhatt |

---

## 🎯 Problem Statement

Security Operations Centers (SOCs) face overwhelming alert fatigue from thousands of disconnected events streaming across SIEM, satellite telemetry, and network sensors. Analysts struggle to stitch multi-stage attack vectors quickly, often misinterpreting benign space telemetry deviations as cyber incidents and missing critical intrusions.

---

## 💡 Solution

Sentinel-X normalizes multi-domain security events into a canonical format, runs real-time behavioral correlation to detect multi-stage attack patterns, enriches events with the MITRE ATT&CK matrix, and calculates transparent risk scores. Crucially, Sentinel-X enforces an operational isolation policy that prevents raw satellite telemetry anomalies from inflating into false cyberattack alarms without corroborating cyber evidence.

---

## ✨ Key Features

- **Multi-Domain Normalization:** Canonical ingestion adapters for SIEM (OTRF Mordor, Sysmon), Satellite/Space Telemetry (NASA JPL Telemanom, ESA OPS-SAT), and Network Sensors.
- **Real-Time Correlation & Attack Stitching:** Automatically identifies multi-stage campaigns (e.g. Brute Force → Credential Access → Script Execution → C2 Beaconing).
- **MITRE ATT&CK Enrichment:** Behavioral intelligence layer mapping detections to enterprise techniques and tactics.
- **Explainable Prioritization:** Transparent discrepancy scoring contrasting Source Severity against Sentinel-X Assessed Priority with concrete rationale.
- **Interactive BLUF Reporting & Simulator:** 1-click executive Bottom Line Up Front briefs and live synthetic event streaming simulator.
- **Responsive SaaS Interface:** Modern light SaaS UI with interactive charts, slide-over detail panels, and full mobile/tablet responsiveness.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | TypeScript, JavaScript, HTML, CSS, Python |
| **Frameworks** | React 19, Vite 8, Tailwind CSS v4, Recharts |
| **IBM Technologies** | watsonx.ai, IBM Bob, IBM Cloud |
| **Deployment** | Netlify, GitHub Actions |

---

## 📁 Repository Structure

```
├── src/                  # React + Vite SaaS application
│   ├── src/
│   │   ├── components/   # UI atoms and responsive navigation
│   │   ├── pages/        # Overview, Alerts, Incidents, DataSources, Simulator, Settings
│   │   ├── store/        # Sentinel global state and simulation engine
│   │   └── data/         # Canonical mock datasets & MITRE matrices
│   └── public/           # Static assets and Netlify SPA redirect rules
├── Sentinel-files/       # Mirror workspace maintaining exact parity
├── docs/                 # Hackathon architecture and setup documentation
├── demo/                 # Live demo links and video walkthrough
└── submission.yaml       # Structured submission metadata
```

---

## ⚡ How to Run

### Quick Start (Windows Launcher)
Double-click `run.bat` in the repository root to start the development server.

### Manual Setup
```bash
# 1. Clone the repository
git clone https://github.com/nerdygeek007/bob-ai-hackathon-pretzel.git
cd bob-ai-hackathon-pretzel/src

# 2. Install dependencies
npm install

# 3. Start development server
npm run dev
# Open http://localhost:5173
```

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 🌐 Live Netlify Deployment | [https://stately-pudding-ce9c61.netlify.app](https://stately-pudding-ce9c61.netlify.app) |
| 📹 Demo Video Walkthrough | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 📊 Architecture Guide | [docs/architecture.md](docs/architecture.md) |
| 📋 Setup Guide | [docs/setup-guide.md](docs/setup-guide.md) |

---

## ⚠️ Known Limitations

- Real-time simulation uses an in-browser high-throughput synthetic generator; direct enterprise Kafka and Splunk live connector agents are planned for subsequent milestones.
- Currently optimized for desktop and mobile web; dedicated native mobile applications are not in scope for this release.

---

## 🏅 What We're Most Proud Of

The unified multi-domain correlation pipeline and modern, intuitive SaaS interface that enables a security analyst to grasp the full context of a multi-stage cyber campaign within 10 seconds without experiencing alert fatigue.
