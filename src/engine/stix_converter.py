"""
stix_converter.py  -- Layer 3: STIX 2.1 Normalization

Converts a single normalized event (as produced by Layer 1/replayed by
Layer 2) into proper STIX 2.1 objects, and appends them to a simple
file-backed STIX object store.

Object-type decision is based on the `source` prefix set by Layer 1:
    siem:*            -> Indicator (+ optional network-traffic/file SCO)
    cyber_sensor:*     -> Indicator (+ optional network-traffic SCO)
    satellite_feed:*   -> Observed Data with custom x_ properties
    intel_report:*      -> Vulnerability (KEV) or Indicator (advisory)

Usage as a library (called by log_transmitter.py's on_event callback or
by the FastAPI /ingest/event route):

    from stix_converter import convert_event, StixStore
    store = StixStore("data/stix_store.json")
    objs = convert_event(record)
    store.add_all(objs)
"""

import json
from pathlib import Path
from datetime import datetime, timezone

import stix2


# --------------------------------------------------------------------------
# Minimal file-backed STIX object store.
# Swappable later for Neo4j/OpenTAXII without touching the converter logic
# below -- just implement the same add_all()/all_objects()/find() interface.
# --------------------------------------------------------------------------

class StixStore:
    def __init__(self, path: str = "data/stix_store.json"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._objects = {}
        if self.path.exists():
            self._load()

    def _load(self):
        raw = json.loads(self.path.read_text())
        self._objects = {obj["id"]: obj for obj in raw}

    def _persist(self):
        self.path.write_text(json.dumps(list(self._objects.values()), indent=2))

    def add(self, stix_obj):
        obj_dict = json.loads(stix_obj.serialize())
        self._objects[obj_dict["id"]] = obj_dict  # dedup by STIX id
        self._persist()

    def add_all(self, stix_objs):
        for obj in stix_objs:
            obj_dict = json.loads(obj.serialize())
            self._objects[obj_dict["id"]] = obj_dict
        self._persist()

    def all_objects(self, obj_type: str = None):
        vals = list(self._objects.values())
        if obj_type:
            vals = [o for o in vals if o.get("type") == obj_type]
        return vals

    def get(self, stix_id: str):
        return self._objects.get(stix_id)


# --------------------------------------------------------------------------
# Identity cache -- one Identity object per distinct source, created once
# and reused (STIX best practice: don't create a new Identity per event).
# --------------------------------------------------------------------------

_identity_cache = {}


def get_identity(source_name: str):
    if source_name not in _identity_cache:
        _identity_cache[source_name] = stix2.Identity(
            name=source_name,
            identity_class="system",
            description=f"Source system: {source_name}",
        )
    return _identity_cache[source_name]


# --------------------------------------------------------------------------
# Per-category converters
# --------------------------------------------------------------------------

def _pattern_from_record(record: dict) -> str:
    """
    Build a best-effort STIX pattern from whatever the record gives us.
    Falls back to a description-based custom pattern if no clean IOC
    field is available (e.g. free-text rule matches).
    """
    ref = str(record.get("raw_ref", "")).strip()
    if ref.count(".") == 3 and all(p.isdigit() for p in ref.split(".") if p):
        return f"[ipv4-addr:value = '{ref}']"
    if ref and len(ref) in (32, 40, 64):  # md5/sha1/sha256-shaped
        return f"[file:hashes.'SHA-256' = '{ref}']" if len(ref) == 64 else f"[file:hashes.MD5 = '{ref}']"
    # Fallback: encode the description as a custom observable comment
    safe_desc = record.get("description", "").replace("'", "")[:120]
    return f"[x-bob:note = '{safe_desc}']"


def convert_siem_or_sensor_event(record: dict):
    """Handles siem:* and cyber_sensor:* sources -> Indicator."""
    identity = get_identity(record["source"])
    indicator = stix2.Indicator(
        name=record.get("description", record["record_id"])[:120],
        pattern=_pattern_from_record(record),
        pattern_type="stix",
        created_by_ref=identity.id,
        valid_from=record["timestamp"].replace("+00:00", "Z"),
        confidence=_confidence_hint_to_int(record.get("confidence_hint")),
        custom_properties={
            "x_bob_asset_id": record.get("asset_id"),
            "x_bob_campaign_id": record.get("scenario_campaign_id"),
            "x_bob_technique_id": record.get("technique_id") or None,
            "x_bob_source_record_id": record["record_id"],
        },
    )
    sighting = stix2.Sighting(
        sighting_of_ref=indicator.id,
        first_seen=record["timestamp"].replace("+00:00", "Z"),
        last_seen=record["timestamp"].replace("+00:00", "Z"),
        count=1,
        where_sighted_refs=[identity.id],
    )
    return [identity, indicator, sighting]


def convert_satellite_event(record: dict):
    """Handles satellite_feed:* sources -> Observed Data (never auto-linked
    to ATT&CK -- corroborating evidence only, per project ground rules)."""
    identity = get_identity(record["source"])
    observed = stix2.ObservedData(
        first_observed=record["timestamp"].replace("+00:00", "Z"),
        last_observed=record["timestamp"].replace("+00:00", "Z"),
        number_observed=1,
        created_by_ref=identity.id,
        object_refs=[],  # no SCO refs required for a custom anomaly note
        custom_properties={
            "x_bob_asset_id": record.get("asset_id"),
            "x_bob_campaign_id": record.get("scenario_campaign_id"),
            "x_bob_description": record.get("description"),
            "x_bob_lat": record.get("lat"),
            "x_bob_lon": record.get("lon"),
            "x_bob_source_record_id": record["record_id"],
        },
    )
    return [identity, observed]


def convert_intel_event(record: dict):
    """Handles intel_report:* sources. KEV entries -> Vulnerability,
    anything else -> Indicator (e.g. manually-entered advisory findings)."""
    identity = get_identity(record["source"])
    if "kev" in record["source"]:
        vuln = stix2.Vulnerability(
            name=record.get("raw_ref") or record["record_id"],
            description=record.get("description", ""),
            created_by_ref=identity.id,
            external_references=[{
                "source_name": "cve",
                "external_id": record.get("raw_ref", ""),
            }],
            custom_properties={
                "x_bob_asset_id": record.get("asset_id"),
                "x_bob_campaign_id": record.get("scenario_campaign_id"),
            },
        )
        return [identity, vuln]

    indicator = stix2.Indicator(
        name=record.get("description", record["record_id"])[:120],
        pattern=_pattern_from_record(record),
        pattern_type="stix",
        created_by_ref=identity.id,
        valid_from=record["timestamp"].replace("+00:00", "Z"),
        confidence=_confidence_hint_to_int(record.get("confidence_hint")),
        custom_properties={
            "x_bob_asset_id": record.get("asset_id"),
            "x_bob_campaign_id": record.get("scenario_campaign_id"),
            "x_bob_technique_id": record.get("technique_id") or None,
        },
    )
    return [identity, indicator]


def _confidence_hint_to_int(hint: str) -> int:
    """Map Layer 1's qualitative confidence_hint to a STIX 0-100 confidence."""
    mapping = {
        "labeled": 90,          # ground-truth labeled by dataset author
        "known_exploited": 85,  # confirmed real-world exploitation (KEV)
        "signature_match": 55,
        "flow_label": 50,
        "sensor_anomaly": 40,
        "simulated": 30,
        "intel_confirmed": 80,
        "unscored": 50,
    }
    return mapping.get(hint, 50)


# --------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------

def convert_event(record: dict):
    """
    Entry point: takes one normalized record dict (Layer 1 schema) and
    returns a list of STIX 2.1 objects ready to be added to the store.
    """
    source = record.get("source", "")
    if source.startswith("siem:") or source.startswith("cyber_sensor:"):
        return convert_siem_or_sensor_event(record)
    if source.startswith("satellite_feed:"):
        return convert_satellite_event(record)
    if source.startswith("intel_report:"):
        return convert_intel_event(record)

    # Unknown source prefix -- don't silently drop data, store as a generic
    # Observed Data so nothing is lost, but flag it for review.
    identity = get_identity(source or "unknown")
    ts = record.get("timestamp", datetime.now(timezone.utc).isoformat()).replace("+00:00", "Z")
    observed = stix2.ObservedData(
        first_observed=ts,
        last_observed=ts,
        number_observed=1,
        created_by_ref=identity.id,
        object_refs=[],
        custom_properties={"x_bob_unclassified_source": source, **record},
    )
    return [identity, observed]


if __name__ == "__main__":
    # Quick smoke test with a synthetic record
    sample = {
        "record_id": "test-1",
        "source": "cyber_sensor:evtx",
        "timestamp": "2026-09-10T07:15:00Z",
        "scenario_campaign_id": "CAMPAIGN-ALPHA",
        "asset_id": "GS-EAST-04",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "description": "Suspicious process injection observed",
        "confidence_hint": "labeled",
        "raw_ref": "T1055_process_injection.evtx",
    }
    store = StixStore("data/stix_store_test.json")
    objs = convert_event(sample)
    store.add_all(objs)
    print(f"Wrote {len(objs)} STIX objects to data/stix_store_test.json")
    for o in objs:
        print(f"  - {o.type}: {o.id}")
