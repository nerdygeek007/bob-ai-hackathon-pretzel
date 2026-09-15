"""
normalize_datasets.py

Downloads the selected static demo datasets and normalizes them into a single
fused CSV/JSON with a common schema, ready to feed into the STIX adapters and
the ATT&CK mapper. Also injects synthetic scenario timestamps/asset IDs so
records from unrelated sources can be correlated (see SCENARIOS below).

Run:
    pip install requests pandas --break-system-packages
    python normalize_datasets.py

Output:
    data/normalized/fused_dataset.csv
    data/normalized/fused_dataset.json
"""

import json
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone

import requests
import pandas as pd

RAW_DIR = Path("data/raw")
OUT_DIR = Path("data")
RAW_DIR.mkdir(parents=True, exist_ok=True)
OUT_DIR.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# 1. Source registry — direct download links confirmed working as of this
#    build. If a link breaks, this is where to fix it.
# --------------------------------------------------------------------------

SOURCES = {
    "mitre_enterprise": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "path": RAW_DIR / "enterprise-attack.json",
        "type": "json",
    },
    "mitre_ics": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        "path": RAW_DIR / "ics-attack.json",
        "type": "json",
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "path": RAW_DIR / "cisa_kev.json",
        "type": "json",
    },
    "evtx_metadata": {
        "url": "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/refs/heads/master/evtx_data.csv",
        "path": RAW_DIR / "evtx_data.csv",
        "type": "csv",
    },
    "telemanom_anomalies": {
        "url": "https://raw.githubusercontent.com/khundman/telemanom/master/labeled_anomalies.csv",
        "path": RAW_DIR / "labeled_anomalies.csv",
        "type": "csv",
    },
    "et_rules_scan": {
        "url": "https://rules.emergingthreats.net/open/suricata/rules/emerging-scan.rules",
        "path": RAW_DIR / "emerging-scan.rules",
        "type": "text",
    },
    "nasa_catalog": {
        "url": "https://data.nasa.gov/data.json",
        "path": RAW_DIR / "nasa_data.json",
        "type": "json",
    },
    # CIC-IDS2018 is not a direct https download (S3 only). Fetch it once
    # separately, then point this path at the local file:
    #   aws s3 cp --no-sign-request \
    #     "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv" \
    #     data/raw/cic_ids2018_thursday.csv
    "cic_ids2018": {
        "url": None,
        "path": RAW_DIR / "cic_ids2018_thursday.csv",
        "type": "csv",
    },
    # Splunk attack_data uses git-lfs and technique-named folders, not a
    # single flat file. Pull one technique folder manually, e.g.:
    #   git clone --filter=blob:none https://github.com/splunk/attack_data.git
    #   cd attack_data
    #   git lfs pull --include="datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log"
    # then point this path at the pulled log file:
    "splunk_attack_data": {
        "url": None,
        "path": RAW_DIR / "windows-sysmon.log",
        "type": "text",
        "technique_hint": "T1003.001",  # folder name IS the technique ID
    },
}


def download(name, spec):
    if spec["url"] is None:
        if not spec["path"].exists():
            print(f"[skip] {name}: no direct URL, fetch manually (see comment) "
                  f"and place at {spec['path']}")
        return
    if spec["path"].exists():
        print(f"[cache] {name}: already downloaded")
        return
    print(f"[download] {name}: {spec['url']}")
    resp = requests.get(spec["url"], timeout=60)
    resp.raise_for_status()
    spec["path"].write_bytes(resp.content)


# --------------------------------------------------------------------------
# 2. Scenario config — this is what makes unrelated static datasets look
#    like one integrated system's logs. Every adapter tags its output with
#    one of these scenarios: a shared asset_id, a rebased UTC time window,
#    and a shared campaign_id.
# --------------------------------------------------------------------------

SCENARIOS = [
    {
        "campaign_id": "CAMPAIGN-ALPHA",
        "asset_id": "GS-EAST-04",          # fictional ground-station asset
        "window_start": datetime(2026, 9, 10, 6, 0, tzinfo=timezone.utc),
        "window_end": datetime(2026, 9, 10, 9, 0, tzinfo=timezone.utc),
    },
    {
        "campaign_id": "CAMPAIGN-BRAVO",
        "asset_id": "SAT-ALPHA-1",         # fictional spacecraft asset
        "window_start": datetime(2026, 9, 11, 13, 0, tzinfo=timezone.utc),
        "window_end": datetime(2026, 9, 11, 15, 30, tzinfo=timezone.utc),
    },
    {
        "campaign_id": "CAMPAIGN-CHARLIE",
        "asset_id": "NET-PERIM-11",        # fictional perimeter/network asset
        "window_start": datetime(2026, 9, 12, 2, 0, tzinfo=timezone.utc),
        "window_end": datetime(2026, 9, 12, 4, 0, tzinfo=timezone.utc),
    },
]


def random_timestamp(scenario):
    span = (scenario["window_end"] - scenario["window_start"]).total_seconds()
    return scenario["window_start"] + timedelta(seconds=random.uniform(0, span))


def pick_scenario(index):
    # Round-robin so records spread across all fake incidents rather than
    # piling into one — real correlation still depends on overlapping
    # asset_id + time window, this just seeds the pool.
    return SCENARIOS[index % len(SCENARIOS)]


# --------------------------------------------------------------------------
# 3. Common normalized record schema
#    Every adapter emits dicts shaped like this. This is the schema the
#    STIX adapters (Indicator/Observed Data/Sighting) and ATT&CK
#    technique_linker.py consume downstream.
# --------------------------------------------------------------------------

FUSED_COLUMNS = [
    "record_id", "source", "timestamp", "scenario_campaign_id", "asset_id",
    "technique_id", "technique_name", "description", "confidence_hint",
    "lat", "lon", "raw_ref",
]


def make_record(record_id, source, scenario, technique_id=None,
                 technique_name=None, description="", confidence_hint="unscored",
                 lat=None, lon=None, raw_ref=""):
    return {
        "record_id": record_id,
        "source": source,
        "timestamp": random_timestamp(scenario).isoformat(),
        "scenario_campaign_id": scenario["campaign_id"],
        "asset_id": scenario["asset_id"],
        "technique_id": technique_id or "",
        "technique_name": technique_name or "",
        "description": description,
        "confidence_hint": confidence_hint,
        "lat": lat,
        "lon": lon,
        "raw_ref": raw_ref,
    }


# --------------------------------------------------------------------------
# 4. Per-source adapters
#    NOTE: evtx_data.csv and cic_ids2018 column names should be confirmed
#    by inspecting the first few rows locally (`head -1 file.csv`) before
#    relying on this — column names below are best-effort with a fallback.
# --------------------------------------------------------------------------

def adapt_evtx_metadata():
    path = SOURCES["evtx_metadata"]["path"]
    if not path.exists():
        return []
    df = pd.read_csv(path, on_bad_lines="skip", engine="python")
    technique_col = next((c for c in df.columns if "technique" in c.lower()), None)
    name_col = next((c for c in df.columns if "file" in c.lower() or "name" in c.lower()), df.columns[0])

    records = []
    for i, row in df.iterrows():
        scenario = pick_scenario(i)
        records.append(make_record(
            record_id=f"evtx-{i}",
            source="cyber_sensor:evtx",
            scenario=scenario,
            technique_id=str(row[technique_col]) if technique_col else "",
            description=f"EVTX-labeled event: {row.get(name_col, '')}",
            confidence_hint="labeled",
            raw_ref=str(row.get(name_col, "")),
        ))
    return records


def adapt_splunk_attack_data():
    spec = SOURCES["splunk_attack_data"]
    path = spec["path"]
    if not path.exists():
        return []
    technique_id = spec.get("technique_hint", "")
    records = []
    with open(path, "r", errors="ignore") as f:
        lines = [l.strip() for l in f if l.strip()][:500]  # cap for demo size
    for i, line in enumerate(lines):
        scenario = pick_scenario(i)
        records.append(make_record(
            record_id=f"splunkdata-{i}",
            source="siem:splunk_attack_data",
            scenario=scenario,
            technique_id=technique_id,
            description="Sysmon/security event from splunk/attack_data corpus",
            confidence_hint="labeled",  # folder name = ground-truth technique
            raw_ref=line[:200],
        ))
    return records


def adapt_telemanom():
    path = SOURCES["telemanom_anomalies"]["path"]
    if not path.exists():
        return []
    df = pd.read_csv(path)
    records = []
    for i, row in df.iterrows():
        scenario = pick_scenario(i)
        chan = row.get("chan_id", row.get("channel", f"CH-{i}"))
        records.append(make_record(
            record_id=f"telemanom-{i}",
            source="satellite_feed:telemanom",
            scenario=scenario,
            description=f"Anomaly on spacecraft channel {chan}",
            confidence_hint="sensor_anomaly",  # NOT a cyberattack label
            raw_ref=str(chan),
        ))
    return records


def simulate_satellite_events(n=25):
    """
    Simulated satellite/geospatial telemetry as suggested: lat/lon + event
    type JSON, tagged into the same scenario campaigns so it can correlate
    against the cyber-side records above (e.g. a ground-station asset_id
    shared with a SIEM/EVTX alert in the same time window).
    """
    event_types = [
        "gps_signal_loss", "rf_snr_drop", "unexpected_reboot",
        "unauthorized_command_attempt", "telemetry_gap", "orbit_deviation_flag",
    ]
    # Rough real-world-ish coordinate spread (ground stations / LEO passes)
    coord_pool = [
        (38.9, -77.0), (51.5, -0.1), (35.0, 139.0), (-33.9, 18.4),
        (28.6, 77.2), (55.75, 37.6), (1.3, 103.8), (-23.5, -46.6),
    ]
    records = []
    for i in range(n):
        scenario = pick_scenario(i)
        lat, lon = random.choice(coord_pool)
        records.append(make_record(
            record_id=f"simsat-{i}",
            source="satellite_feed:simulated",
            scenario=scenario,
            description=f"Simulated event: {random.choice(event_types)}",
            confidence_hint="simulated",
            lat=round(lat + random.uniform(-0.5, 0.5), 4),
            lon=round(lon + random.uniform(-0.5, 0.5), 4),
            raw_ref="synthetic",
        ))
    return records


def adapt_et_rules():
    path = SOURCES["et_rules_scan"]["path"]
    if not path.exists():
        return []
    records = []
    with open(path, "r", errors="ignore") as f:
        lines = [l for l in f if l.strip().startswith("alert")]
    for i, line in enumerate(lines):
        scenario = pick_scenario(i)
        msg = line.split('msg:"')[1].split('"')[0] if 'msg:"' in line else ""
        records.append(make_record(
            record_id=f"etrule-{i}",
            source="siem:et_rules",
            scenario=scenario,
            description=msg or "ET Open rule match",
            confidence_hint="signature_match",
            raw_ref=line.strip()[:200],
        ))
    return records


def adapt_cic_ids2018():
    path = SOURCES["cic_ids2018"]["path"]
    if not path.exists():
        print("[skip] cic_ids2018: file not present, fetch via aws s3 cp first")
        return []
    df = pd.read_csv(path, nrows=2000, on_bad_lines="skip", engine="python")
    label_col = next((c for c in df.columns if c.strip().lower() == "label"), None)
    if label_col is None:
        print("[warn] cic_ids2018: 'Label' column not found, check actual header")
        return []

    label_to_technique = {
        "FTP-BruteForce": ("T1110", "Brute Force"),
        "SSH-Bruteforce": ("T1110", "Brute Force"),
        "DoS attacks-Hulk": ("T1498", "Network Denial of Service"),
        "DoS attacks-GoldenEye": ("T1498", "Network Denial of Service"),
        "DDoS attacks-LOIC-HTTP": ("T1498", "Network Denial of Service"),
        "Bot": ("T1583", "Acquire Infrastructure"),
        "Infilteration": ("T1210", "Exploitation of Remote Services"),
    }

    records = []
    attacks_only = df[df[label_col] != "Benign"].head(500)
    for i, row in attacks_only.iterrows():
        scenario = pick_scenario(i)
        label = str(row[label_col]).strip()
        tid, tname = label_to_technique.get(label, (None, None))
        records.append(make_record(
            record_id=f"cicids-{i}",
            source="cyber_sensor:cic_ids2018",
            scenario=scenario,
            technique_id=tid,
            technique_name=tname,
            description=f"Network flow labeled '{label}'",
            confidence_hint="flow_label",
            raw_ref=label,
        ))
    return records


def adapt_kev():
    path = SOURCES["cisa_kev"]["path"]
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    vulns = data.get("vulnerabilities", [])[:100]  # trim for demo size
    records = []
    for i, v in enumerate(vulns):
        scenario = pick_scenario(i)
        records.append(make_record(
            record_id=f"kev-{v.get('cveID', i)}",
            source="intel_report:cisa_kev",
            scenario=scenario,
            description=f"{v.get('cveID')}: {v.get('vulnerabilityName', '')}",
            confidence_hint="known_exploited",
            raw_ref=v.get("cveID", ""),
        ))
    return records


def adapt_intel_pdfs():
    """
    Placeholder for manually-downloaded CISA/vendor advisory PDFs.
    Drop PDFs into data/raw/intel_pdfs/ and list their headline technique
    IDs + a one-line summary here (extracting structured text from PDFs
    reliably needs a proper PDF-parsing step — out of scope for this
    normalization pass, but the record shape is ready for it).
    """
    manual_entries = [
        # (technique_id, technique_name, description, source_ref)
        # Example — replace with what you actually pull from CISA advisories:
        # ("T1071", "Application Layer Protocol",
        #  "CISA AA24-xxx: C2 beaconing over HTTPS observed in campaign",
        #  "CISA_AA24-xxx.pdf"),
    ]
    records = []
    for i, (tid, tname, desc, ref) in enumerate(manual_entries):
        scenario = pick_scenario(i)
        records.append(make_record(
            record_id=f"intelpdf-{i}",
            source="intel_report:advisory_pdf",
            scenario=scenario,
            technique_id=tid,
            technique_name=tname,
            description=desc,
            confidence_hint="intel_confirmed",
            raw_ref=ref,
        ))
    return records


# --------------------------------------------------------------------------
# 5. Run everything, fuse, write out
# --------------------------------------------------------------------------

def main():
    random.seed(42)  # reproducible demo runs

    print("== Downloading sources ==")
    for name, spec in SOURCES.items():
        try:
            download(name, spec)
        except Exception as e:
            print(f"[error] {name}: {e}")

    print("\n== Normalizing ==")
    all_records = []
    all_records += adapt_evtx_metadata()
    all_records += adapt_splunk_attack_data()
    all_records += adapt_telemanom()
    all_records += simulate_satellite_events(n=25)
    all_records += adapt_et_rules()
    all_records += adapt_cic_ids2018()
    all_records += adapt_kev()
    all_records += adapt_intel_pdfs()

    print(f"Total normalized records: {len(all_records)}")

    all_records.sort(key=lambda r: r["timestamp"])

    df_out = pd.DataFrame(all_records, columns=FUSED_COLUMNS)
    csv_path = OUT_DIR / "fused_dataset.csv"
    json_path = OUT_DIR / "fused_dataset.json"
    df_out.to_csv(csv_path, index=False)
    df_out.to_json(json_path, orient="records", indent=2)

    print(f"\nWrote {csv_path} and {json_path}")
    print("\nRecords per scenario campaign:")
    print(df_out["scenario_campaign_id"].value_counts())
    print("\nRecords per source:")
    print(df_out["source"].value_counts())


if __name__ == "__main__":
    main()
