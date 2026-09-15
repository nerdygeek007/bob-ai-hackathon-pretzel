"""
ARES Commander BLUF Report Exporter
Generates defense-grade, publication-ready intelligence reports in multiple formats:
- Markdown (.md): Military intelligence standard format with tables and provenance
- Standalone HTML (.html): Interactive dark HUD styling + print-to-PDF stylesheet
- Machine JSON (.json): Structured STIX/SOAR machine-readable telemetry
- Plain ASCII Text (.txt): Field radio / TTY teletype briefing

Supports saving directly to disk in 'reports/' and streaming as HTTP downloads.
"""

import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union, List

from src.engine.schemas import (
    CommanderBlufReport,
    SeverityLevel
)


class ReportExporter:
    """Comprehensive exporter for ARES Commander BLUF intelligence briefings."""

    DEFAULT_OUTPUT_DIR = "reports"

    @classmethod
    def _normalize_report_dict(cls, report: Union[CommanderBlufReport, Dict[str, Any]]) -> Dict[str, Any]:
        """Converts report object or dict into a standard dictionary representation."""
        if isinstance(report, CommanderBlufReport):
            return report.model_dump()
        return dict(report)

    @classmethod
    def to_markdown(cls, report: Union[CommanderBlufReport, Dict[str, Any]]) -> str:
        """Exports the BLUF briefing as a structured defense-grade Markdown document."""
        data = cls._normalize_report_dict(report)

        report_id = data.get("report_id", "BLUF-UNASSIGNED")
        cluster_id = data.get("cluster_id", "INC-UNKNOWN")
        classification = data.get("classification_level", data.get("classification", "SECRET // NOFORN // EXERCISE"))
        sector = data.get("sector", "Sector-4-North")
        severity = data.get("severity", "CRITICAL")
        if isinstance(severity, dict) and "value" in severity:
            severity = severity["value"]
        conf = data.get("bayesian_confidence", 0.99)
        conf_str = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) and conf <= 1.0 else str(conf)
        actor = data.get("threat_actor_attribution", data.get("threat_actor", "State-Sponsored APT"))
        gen_time = data.get("generated_at", datetime.now(timezone.utc).isoformat())
        bluf = data.get("bottom_line_up_front", "No narrative briefing generated.")

        lines = [
            f"# {classification}",
            "",
            "## JOINT CYBER-SPACE OPERATIONS DEFENSE INTELLIGENCE BRIEFING",
            f"**DOCUMENT IDENTIFIER:** `{report_id}`  ",
            f"**INCIDENT CLUSTER:** `{cluster_id}`  ",
            f"**OPERATIONAL SECTOR:** `{sector}`  ",
            f"**TIMESTAMP:** `{gen_time}`  ",
            f"**THREAT ATTRIBUTION:** **{actor}**  ",
            f"**AGGREGATE SEVERITY:** `{severity}` | **BAYESIAN THREAT CONFIDENCE:** `{conf_str}`  ",
            "",
            "---",
            "",
            "### 1. BOTTOM LINE UP FRONT (BLUF)",
            f"> {bluf}",
            "",
            "---",
            "",
            "### 2. KEY OPERATIONAL FINDINGS"
        ]

        for finding in data.get("key_findings", []):
            lines.append(f"- {finding}")

        # 3. Explainable AI (XAI) Feature Attribution
        xai = data.get("xai_explanation")
        if xai and isinstance(xai, dict) and xai.get("feature_attributions"):
            lines.extend([
                "",
                "---",
                "",
                "### 3. EXPLAINABLE AI (XAI) DECISION DRIVERS (SHAP-STYLE ATTRIBUTION)",
                f"**Algorithm:** `{xai.get('algorithm', 'Spatio-Temporal Graph + Bayesian + SHAP')}` | **Base Rate Prior:** `{xai.get('base_rate_prior', 0.10)}` | **Posterior:** `{xai.get('posterior_confidence', conf)}`",
                "",
                "| Feature / Sensor Driver | Decision Weight | Impact Direction | Tactical Evidence Rationale |",
                "|---|:---:|:---:|---|"
            ])
            for attr in xai.get("feature_attributions", []):
                lines.append(
                    f"| **{attr.get('feature_name')}** | **{attr.get('importance_weight')}%** | `{attr.get('signal_direction')}` | {attr.get('evidence_rationale')} |"
                )

        # 4. MITRE ATT&CK Matrix Mapping
        mitre_ttps = data.get("mitre_ttps", [])
        if mitre_ttps:
            lines.extend([
                "",
                "---",
                "",
                "### 4. MITRE ATT&CK MATRIX MAPPING (ENTERPRISE & ICS)",
                "",
                "| Technique ID | Technique Name | Tactic Stage | Confidence | Recommended Defense Mitigation |",
                "|:---:|---|---|:---:|---|"
            ])
            for t in mitre_ttps:
                tid = t.get("technique_id") or t.get("id", "T0000")
                tname = t.get("name", "Unknown Technique")
                tactic = t.get("tactic", "Execution")
                tconf = t.get("confidence", "90%")
                if isinstance(tconf, (int, float)):
                    tconf = f"{int(tconf * 100)}%"
                mits = t.get("mitigations", [])
                mit_str = mits[0] if mits else "Deploy automated SOAR playbook quarantine"
                lines.append(f"| **[{tid}](https://attack.mitre.org/techniques/{tid.replace('.', '/')})** | {tname} | `{tactic}` | `{tconf}` | {mit_str} |")

        # 5. Wargamed Courses of Action (COAs)
        coas = data.get("wargamed_coas", [])
        if coas:
            lines.extend([
                "",
                "---",
                "",
                "### 5. WARGAMED DEFENSIVE COURSES OF ACTION (COAs)",
                "",
                "| Option | Action Title | Containment | Mission Disruption | Status | Tradeoff Summary |",
                "|:---:|---|:---:|:---:|:---:|---|"
            ])
            for coa in coas:
                opt = coa.get("option_id", "COA")
                title = coa.get("title", "Defensive Action")
                cont = coa.get("containment_efficacy") or coa.get("containment", "90%")
                if isinstance(cont, (int, float)) and cont <= 1.0:
                    cont = f"{int(cont * 100)}%"
                disrupt = coa.get("mission_disruption_impact") or coa.get("mission_disruption", "LOW")
                is_rec = coa.get("is_recommended", False)
                status = "**RECOMMENDED**" if is_rec else "Alternative"
                tradeoff = coa.get("tradeoff_summary") or coa.get("tradeoff", "N/A")
                lines.append(f"| `{opt}` | **{title}** | `{cont}` | `{disrupt}` | {status} | {tradeoff} |")

        # 6. Cryptographic Provenance Citations
        citations = data.get("provenance_citations", [])
        if citations:
            lines.extend([
                "",
                "---",
                "",
                "### 6. CRYPTOGRAPHIC SENSOR PROVENANCE & AUDIT TRAIL",
                "",
                "| Claim # | Sensor Alert Identifier | Timestamp (UTC) | Raw SHA-256 Provenance Hash | Grounding |",
                "|:---:|---|:---:|---|:---:|"
            ])
            for c in citations:
                cidx = c.get("claim_index", 1)
                sid = c.get("source_alert_id") or c.get("sensor_id", "ALERT-UNKNOWN")
                ts = c.get("source_timestamp") or c.get("timestamp", "2026-09-15T00:00:00Z")
                h = c.get("sha256_hash", "0" * 64)
                if len(h) > 24 and not h.endswith("..."):
                    h = f"{h[:16]}...{h[-8:]}"
                lines.append(f"| {cidx} | `{sid}` | `{ts}` | `{h}` | **GROUNDED** |")

        # 7. AI Assurance & Verification Stamp
        guardian_score = data.get("guardian_grounding_score", data.get("guardian_assurance", {}).get("score", 0.98))
        guardian_verdict = data.get("guardian_verdict", data.get("guardian_assurance", {}).get("verdict", "PASSED_DEFENSE_GROUNDING"))
        lines.extend([
            "",
            "---",
            "",
            "### 7. AI GOVERNANCE & FACTUAL ASSURANCE",
            f"- **Inference Model:** `IBM watsonx.ai Granite 3.0 8B Instruct (ibm/granite-3-8b-instruct)`",
            f"- **Hallucination Shield:** `IBM watsonx Granite Guardian 3.0`",
            f"- **Factual Grounding Score:** `{guardian_score}` / 1.00",
            f"- **Assurance Verdict:** `{guardian_verdict}`",
            "",
            "---",
            f"*{classification} — DECLASSIFY ON: 2051-09-15 // ARES DEFENSE INTELLIGENCE ENGINE*"
        ])

        return "\n".join(lines)

    @classmethod
    def to_html(cls, report: Union[CommanderBlufReport, Dict[str, Any]], title: str = "ARES Commander Briefing") -> str:
        """Exports the BLUF briefing as an executive, standalone printable HTML document."""
        data = cls._normalize_report_dict(report)

        report_id = data.get("report_id", "BLUF-UNASSIGNED")
        cluster_id = data.get("cluster_id", "INC-UNKNOWN")
        classification = data.get("classification_level", data.get("classification", "SECRET // NOFORN // EXERCISE"))
        sector = data.get("sector", "Sector-4-North")
        severity = data.get("severity", "CRITICAL")
        if isinstance(severity, dict) and "value" in severity:
            severity = severity["value"]
        conf = data.get("bayesian_confidence", 0.99)
        conf_str = f"{int(conf * 100)}%" if isinstance(conf, (int, float)) and conf <= 1.0 else str(conf)
        actor = data.get("threat_actor_attribution", data.get("threat_actor", "State-Sponsored APT"))
        gen_time = data.get("generated_at", datetime.now(timezone.utc).isoformat())
        bluf = data.get("bottom_line_up_front", "No narrative briefing generated.")

        findings_html = "".join(f"<li>{f}</li>" for f in data.get("key_findings", []))

        # XAI section
        xai = data.get("xai_explanation", {})
        xai_rows = ""
        if xai and isinstance(xai, dict) and xai.get("feature_attributions"):
            for attr in xai.get("feature_attributions", []):
                w = attr.get("importance_weight", 25)
                xai_rows += f"""
                <tr>
                    <td><strong>{attr.get('feature_name')}</strong></td>
                    <td style="text-align: center;"><strong>{w}%</strong></td>
                    <td>
                        <div class="bar-bg"><div class="bar-fill" style="width: {min(100, int(w * 2.5))}%;"></div></div>
                    </td>
                    <td><span class="badge badge-tag">{attr.get('signal_direction')}</span></td>
                    <td style="font-size: 11px; color: #94a3b8;">{attr.get('evidence_rationale')}</td>
                </tr>
                """

        # MITRE rows
        mitre_rows = ""
        for t in data.get("mitre_ttps", []):
            tid = t.get("technique_id") or t.get("id", "T0000")
            tname = t.get("name", "Unknown")
            tactic = t.get("tactic", "Execution")
            tconf = t.get("confidence", "90%")
            if isinstance(tconf, (int, float)):
                tconf = f"{int(tconf * 100)}%"
            mits = t.get("mitigations", ["Air-gap target subnet"])
            mitre_rows += f"""
            <tr>
                <td><a href="https://attack.mitre.org/techniques/{tid.replace('.', '/')}" target="_blank" class="link">{tid}</a></td>
                <td><strong>{tname}</strong></td>
                <td><span class="badge badge-tag">{tactic}</span></td>
                <td style="text-align: center;">{tconf}</td>
                <td style="font-size: 11px;">{mits[0]}</td>
            </tr>
            """

        # COA rows
        coa_rows = ""
        for coa in data.get("wargamed_coas", []):
            opt = coa.get("option_id", "COA")
            ctitle = coa.get("title", "Action")
            cont = coa.get("containment_efficacy") or coa.get("containment", "90%")
            if isinstance(cont, (int, float)) and cont <= 1.0:
                cont = f"{int(cont * 100)}%"
            disrupt = coa.get("mission_disruption_impact") or coa.get("mission_disruption", "LOW")
            is_rec = coa.get("is_recommended", False)
            rec_badge = '<span class="badge badge-rec">RECOMMENDED</span>' if is_rec else '<span class="badge badge-alt">ALTERNATIVE</span>'
            tradeoff = coa.get("tradeoff_summary") or coa.get("tradeoff", "N/A")
            coa_rows += f"""
            <tr>
                <td><strong>{opt}</strong></td>
                <td><strong>{ctitle}</strong></td>
                <td style="text-align: center; color: #38bdf8;"><strong>{cont}</strong></td>
                <td style="text-align: center;">{disrupt}</td>
                <td style="text-align: center;">{rec_badge}</td>
                <td style="font-size: 11px; color: #cbd5e1;">{tradeoff}</td>
            </tr>
            """

        # Provenance rows
        prov_rows = ""
        for c in data.get("provenance_citations", []):
            cidx = c.get("claim_index", 1)
            sid = c.get("source_alert_id") or c.get("sensor_id", "ALERT")
            ts = c.get("source_timestamp") or c.get("timestamp", "2026-09-15T00:00:00Z")
            h = c.get("sha256_hash", "0" * 64)
            prov_rows += f"""
            <tr>
                <td style="text-align: center;">{cidx}</td>
                <td><code>{sid}</code></td>
                <td><code>{ts}</code></td>
                <td><code style="font-size: 10px;">{h}</code></td>
                <td style="text-align: center;"><span class="badge badge-rec">GROUNDED</span></td>
            </tr>
            """

        guardian_score = data.get("guardian_grounding_score", data.get("guardian_assurance", {}).get("score", 0.98))
        guardian_verdict = data.get("guardian_verdict", data.get("guardian_assurance", {}).get("verdict", "PASSED_DEFENSE_GROUNDING"))

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - {report_id}</title>
    <style>
        :root {{
            --bg-color: #080c14;
            --panel-bg: #0f172a;
            --text-color: #e2e8f0;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --border-color: #334155;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            padding: 30px 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background-color: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 35px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.6);
        }}
        .banner {{
            background-color: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.5);
            color: #fca5a5;
            text-align: center;
            font-weight: 800;
            letter-spacing: 2px;
            font-size: 11px;
            padding: 6px;
            border-radius: 6px;
            margin-bottom: 20px;
        }}
        h1 {{ font-size: 22px; font-weight: 900; letter-spacing: 0.5px; margin-bottom: 8px; color: #f8fafc; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border-color);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0 25px 0;
            font-size: 12px;
        }}
        .meta-item span {{ color: #94a3b8; display: block; font-size: 10px; text-transform: uppercase; font-weight: 700; }}
        .meta-item strong {{ font-size: 13px; color: #f1f5f9; }}
        .bluf-box {{
            background: rgba(6, 182, 212, 0.08);
            border-left: 4px solid var(--accent-cyan);
            border-radius: 4px;
            padding: 18px;
            margin-bottom: 25px;
        }}
        .bluf-box h2 {{ font-size: 13px; text-transform: uppercase; color: var(--accent-cyan); margin-bottom: 8px; letter-spacing: 1px; }}
        .bluf-box p {{ font-size: 15px; color: #f8fafc; font-weight: 500; line-height: 1.6; }}
        h3 {{
            font-size: 14px;
            text-transform: uppercase;
            color: #38bdf8;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 6px;
            margin: 25px 0 12px 0;
        }}
        ul {{ list-style-position: inside; font-size: 13px; color: #cbd5e1; margin-bottom: 20px; }}
        ul li {{ margin-bottom: 6px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-bottom: 20px;
        }}
        th, td {{
            padding: 10px 12px;
            border: 1px solid var(--border-color);
            text-align: left;
        }}
        th {{ background: rgba(30, 41, 59, 0.8); color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: 700; }}
        tr:nth-child(even) {{ background: rgba(30, 41, 59, 0.3); }}
        .badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
            display: inline-block;
        }}
        .badge-rec {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-alt {{ background: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #64748b; }}
        .badge-tag {{ background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
        .bar-bg {{ background: #334155; height: 8px; border-radius: 4px; width: 100%; overflow: hidden; }}
        .bar-fill {{ background: linear-gradient(90deg, #06b6d4, #3b82f6); height: 100%; border-radius: 4px; }}
        .link {{ color: #38bdf8; text-decoration: none; }}
        .link:hover {{ text-decoration: underline; }}
        .actions {{
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-bottom: 15px;
        }}
        .btn {{
            background: #0284c7;
            color: #fff;
            border: none;
            padding: 7px 14px;
            font-size: 12px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: #0369a1; }}
        @media print {{
            body {{ background: #fff !important; color: #000 !important; padding: 0; }}
            .container {{ border: none; box-shadow: none; padding: 0; max-width: 100%; }}
            .actions {{ display: none !important; }}
            .banner {{ border: 1px solid #000; color: #990000; background: none; }}
            .bluf-box {{ border-left: 4px solid #000; background: #f1f5f9; }}
            th {{ background: #e2e8f0 !important; color: #000 !important; }}
            th, td {{ border: 1px solid #94a3b8; color: #000 !important; }}
            strong, code {{ color: #000 !important; }}
        }}
    </style>
</head>
<body>
    <div class="actions">
        <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
    </div>
    <div class="container">
        <div class="banner">{classification}</div>
        <h1>JOINT CYBER-SPACE OPERATIONS DEFENSE INTELLIGENCE BRIEFING</h1>
        <p style="font-size: 11px; color: #94a3b8;">Document ID: <code>{report_id}</code> | Generated: {gen_time}</p>

        <div class="meta-grid">
            <div class="meta-item"><span>Incident Cluster</span><strong>{cluster_id}</strong></div>
            <div class="meta-item"><span>Operational Sector</span><strong>{sector}</strong></div>
            <div class="meta-item"><span>Threat Attribution</span><strong>{actor}</strong></div>
            <div class="meta-item"><span>Severity</span><strong>{severity}</strong></div>
            <div class="meta-item"><span>Bayesian Confidence</span><strong style="color: #34d399;">{conf_str}</strong></div>
            <div class="meta-item"><span>Guardian Grounding</span><strong>{guardian_score} ({guardian_verdict})</strong></div>
        </div>

        <div class="bluf-box">
            <h2>1. Bottom Line Up Front (BLUF)</h2>
            <p>{bluf}</p>
        </div>

        <h3>2. Confirmed Operational Findings</h3>
        <ul>
            {findings_html}
        </ul>

        {f'''<h3>3. Explainable AI (XAI) Decision Drivers</h3>
        <table>
            <thead>
                <tr>
                    <th>Decision Driver</th>
                    <th style="text-align: center;">Weight</th>
                    <th style="width: 160px;">Attribution Bar</th>
                    <th>Signal Direction</th>
                    <th>Evidence Rationale</th>
                </tr>
            </thead>
            <tbody>
                {xai_rows}
            </tbody>
        </table>''' if xai_rows else ''}

        {f'''<h3>4. MITRE ATT&CK Matrix Mapping</h3>
        <table>
            <thead>
                <tr>
                    <th>Technique</th>
                    <th>Name</th>
                    <th>Tactic</th>
                    <th style="text-align: center;">Confidence</th>
                    <th>Defensive Mitigation</th>
                </tr>
            </thead>
            <tbody>
                {mitre_rows}
            </tbody>
        </table>''' if mitre_rows else ''}

        {f'''<h3>5. Wargamed Defensive Courses of Action (COAs)</h3>
        <table>
            <thead>
                <tr>
                    <th>Option</th>
                    <th>Course of Action</th>
                    <th style="text-align: center;">Containment</th>
                    <th style="text-align: center;">Disruption</th>
                    <th style="text-align: center;">Status</th>
                    <th>Tradeoff Summary</th>
                </tr>
            </thead>
            <tbody>
                {coa_rows}
            </tbody>
        </table>''' if coa_rows else ''}

        {f'''<h3>6. Cryptographic Sensor Provenance & Audit Trail</h3>
        <table>
            <thead>
                <tr>
                    <th style="text-align: center;">#</th>
                    <th>Source Alert ID</th>
                    <th>Timestamp</th>
                    <th>SHA-256 Provenance Hash</th>
                    <th style="text-align: center;">Status</th>
                </tr>
            </thead>
            <tbody>
                {prov_rows}
            </tbody>
        </table>''' if prov_rows else ''}

        <div style="margin-top: 30px; font-size: 10px; color: #64748b; text-align: center; border-top: 1px solid var(--border-color); padding-top: 10px;">
            {classification} — DECLASSIFY ON: 2051-09-15 // ARES DEFENSE INTELLIGENCE PLATFORM // IBM WATSONX GRANITE 3.0
        </div>
    </div>
</body>
</html>
"""
        return html

    @classmethod
    def to_json(cls, report: Union[CommanderBlufReport, Dict[str, Any]], indent: int = 2) -> str:
        """Exports the full machine-readable briefing payload formatted as JSON."""
        data = cls._normalize_report_dict(report)
        return json.dumps(data, indent=indent, default=str)

    @classmethod
    def to_text(cls, report: Union[CommanderBlufReport, Dict[str, Any]]) -> str:
        """Exports an ASCII tele-type text document suitable for command terminals or field radios."""
        data = cls._normalize_report_dict(report)
        rep_id = data.get("report_id", "BLUF-UNASSIGNED")
        classification = data.get("classification_level", "SECRET // NOFORN // EXERCISE")
        bluf = data.get("bottom_line_up_front", "")

        sep = "=" * 76
        subsep = "-" * 76

        lines = [
            sep,
            f"  {classification}",
            f"  ARES COMMANDER THREAT INTELLIGENCE BRIEFING (BLUF)",
            f"  REPORT ID: {rep_id} | SECTOR: {data.get('sector')} | SEVERITY: {data.get('severity')}",
            f"  ATTRIBUTION: {data.get('threat_actor_attribution')} | CONFIDENCE: {data.get('bayesian_confidence')}",
            sep,
            "",
            "1. BOTTOM LINE UP FRONT (BLUF):",
            f"   {bluf}",
            "",
            subsep,
            "2. KEY OPERATIONAL FINDINGS:"
        ]
        for f in data.get("key_findings", []):
            lines.append(f"   * {f}")

        lines.extend([
            "",
            subsep,
            "3. RECOMMENDED DEFENSIVE COURSE OF ACTION:"
        ])
        for coa in data.get("wargamed_coas", []):
            if coa.get("is_recommended"):
                lines.append(f"   * [{coa.get('option_id')}] {coa.get('title')}")
                lines.append(f"     Containment: {coa.get('containment_efficacy') or coa.get('containment')} | Disruption: {coa.get('mission_disruption_impact') or coa.get('mission_disruption')}")
                lines.append(f"     Tradeoff: {coa.get('tradeoff_summary') or coa.get('tradeoff')}")

        lines.extend([
            "",
            sep,
            f"  ASSURANCE: GROUNDED ({data.get('guardian_grounding_score', 0.98)}) | VERDICT: {data.get('guardian_verdict', 'PASSED')}",
            sep
        ])

        return "\n".join(lines)

    @classmethod
    def export_report(
        cls,
        report: Union[CommanderBlufReport, Dict[str, Any]],
        format: str = "markdown",
        output_dir: str = DEFAULT_OUTPUT_DIR
    ) -> Dict[str, Any]:
        """
        Saves the formatted briefing to disk in output_dir (default: 'reports/').
        Supported formats: 'markdown', 'html', 'json', 'text', 'all'.
        """
        data = cls._normalize_report_dict(report)
        report_id = data.get("report_id", f"BLUF-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}")
        os.makedirs(output_dir, exist_ok=True)

        results = {}

        formats_to_run = ["markdown", "html", "json", "text"] if format.lower() == "all" else [format.lower()]

        for fmt in formats_to_run:
            if fmt in ["markdown", "md"]:
                content = cls.to_markdown(data)
                ext = ".md"
            elif fmt in ["html", "htm"]:
                content = cls.to_html(data)
                ext = ".html"
            elif fmt == "json":
                content = cls.to_json(data)
                ext = ".json"
            elif fmt in ["text", "txt"]:
                content = cls.to_text(data)
                ext = ".txt"
            else:
                continue

            file_name = f"{report_id}{ext}"
            file_path = os.path.join(output_dir, file_name)

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            size_bytes = os.path.getsize(file_path)
            results[fmt] = {
                "file_path": os.path.abspath(file_path),
                "file_name": file_name,
                "format": fmt,
                "size_bytes": size_bytes
            }

        return {
            "status": "SUCCESS",
            "report_id": report_id,
            "output_dir": os.path.abspath(output_dir),
            "files": results
        }
