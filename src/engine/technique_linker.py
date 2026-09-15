"""
technique_linker.py  -- Layer 4: MITRE ATT&CK Mapping

Loads the MITRE ATT&CK STIX 2.1 bundles once, indexes attack-pattern
objects by technique ID and name, and links STIX Indicators (produced by
Layer 3) to the matching attack-pattern via a Relationship(uses) object.
Also resolves linked course-of-action (mitigations) and intrusion-set
(threat actor) objects for free, since MITRE's bundle already contains
those relationships.

Usage:
    linker = AttackLinker(
        enterprise_path="data/raw/enterprise-attack.json",
        ics_path="data/raw/ics-attack.json",
    )
    linker.load()

    relationship = linker.link_indicator_to_technique(indicator, "T1055")
    mitigations = linker.get_mitigations("T1055")
    tactic = linker.get_tactic("T1055")
"""

import json
from pathlib import Path

import stix2


# Small hand-built lookup for sources that AREN'T already labeled with an
# ATT&CK technique ID (CIC-IDS2018 flow labels, ET rule categories).
# Extend this as you add more unlabeled sources -- this is the "20% manual"
# part described earlier; everything else is direct lookup from already-
# labeled data (EVTX, Mordor/Security-Datasets, Splunk attack_data).
UNLABELED_SOURCE_TECHNIQUE_MAP = {
    "FTP-BruteForce": "T1110",
    "SSH-Bruteforce": "T1110",
    "DoS attacks-Hulk": "T1498",
    "DoS attacks-GoldenEye": "T1498",
    "DDoS attacks-LOIC-HTTP": "T1498",
    "Bot": "T1583",
    "Infilteration": "T1210",
}


class AttackLinker:
    def __init__(self, enterprise_path: str, ics_path: str = None):
        self.enterprise_path = Path(enterprise_path)
        self.ics_path = Path(ics_path) if ics_path else None

        self.by_technique_id = {}      # "T1055" -> attack-pattern stix2 obj
        self.by_name = {}              # lowercase name -> attack-pattern
        self.raw_objects_by_id = {}    # stix id -> raw dict (for relationship traversal)
        self._bundles = []

    def load(self):
        self._bundles.append(self._load_bundle(self.enterprise_path))
        if self.ics_path and self.ics_path.exists():
            self._bundles.append(self._load_bundle(self.ics_path))

        for bundle in self._bundles:
            for obj in bundle.get("objects", []):
                self.raw_objects_by_id[obj["id"]] = obj
                if obj.get("type") == "attack-pattern":
                    for ref in obj.get("external_references", []):
                        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack"):
                            self.by_technique_id[ref["external_id"]] = obj
                    if "name" in obj:
                        self.by_name[obj["name"].lower()] = obj

        print(f"Loaded {len(self.by_technique_id)} techniques from "
              f"{len(self._bundles)} bundle(s)")

    @staticmethod
    def _load_bundle(path: Path) -> dict:
        return json.loads(path.read_text())

    # ----------------------------------------------------------------
    # Resolution helpers
    # ----------------------------------------------------------------

    def resolve_technique_id(self, record: dict) -> str:
        """
        Given a normalized event record, return the best-guess ATT&CK
        technique ID: prefer an already-labeled technique_id (from EVTX,
        Mordor/Security-Datasets, Splunk attack_data); otherwise fall back
        to the manual label-to-technique map for CIC-IDS2018/ET-style
        unlabeled sources.
        """
        tid = record.get("technique_id")
        if tid:
            return tid
        raw_ref = record.get("raw_ref", "")
        return UNLABELED_SOURCE_TECHNIQUE_MAP.get(raw_ref)

    def get_attack_pattern(self, technique_id: str):
        return self.by_technique_id.get(technique_id)

    def get_tactic(self, technique_id: str):
        ap = self.get_attack_pattern(technique_id)
        if not ap:
            return None
        phases = ap.get("kill_chain_phases", [])
        return [p["phase_name"] for p in phases if p.get("kill_chain_name") in
                ("mitre-attack", "mitre-ics-attack")]

    def get_mitigations(self, technique_id: str):
        ap = self.get_attack_pattern(technique_id)
        if not ap:
            return []
        mitigations = []
        for obj in self.raw_objects_by_id.values():
            if (obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "mitigates"
                    and obj.get("target_ref") == ap["id"]):
                source = self.raw_objects_by_id.get(obj["source_ref"])
                if source:
                    mitigations.append({
                        "id": source.get("id"),
                        "name": source.get("name"),
                        "description": source.get("description", "")[:300],
                    })
        return mitigations

    def get_intrusion_sets(self, technique_id: str):
        """Threat actor groups (intrusion-set) known to use this technique."""
        ap = self.get_attack_pattern(technique_id)
        if not ap:
            return []
        actors = []
        for obj in self.raw_objects_by_id.values():
            if (obj.get("type") == "relationship"
                    and obj.get("relationship_type") == "uses"
                    and obj.get("target_ref") == ap["id"]):
                source = self.raw_objects_by_id.get(obj["source_ref"])
                if source and source.get("type") == "intrusion-set":
                    actors.append({"id": source["id"], "name": source.get("name")})
        return actors

    # ----------------------------------------------------------------
    # Linking (produces the graph edge that gets written to the STIX store)
    # ----------------------------------------------------------------

    def link_indicator_to_technique(self, indicator, technique_id: str):
        """
        Returns a stix2.Relationship(uses) from the given Indicator to the
        matching attack-pattern, or None if the technique isn't found in
        the loaded bundles (e.g. a bad/unknown ID -- log and skip, don't
        fabricate a link).
        """
        ap = self.get_attack_pattern(technique_id)
        if not ap:
            print(f"[warn] technique {technique_id} not found in loaded ATT&CK bundles")
            return None

        return stix2.Relationship(
            relationship_type="uses",
            source_ref=indicator.id,
            target_ref=ap["id"],
            description=f"{indicator.name} matches {technique_id} ({ap.get('name')})",
        )

    def enrich_indicator(self, indicator, record: dict, store):
        """
        Convenience wrapper: resolves the technique for this record, links
        the indicator, and writes the relationship (plus a light summary
        dict for downstream fusion/BLUF use) into the given StixStore.
        Returns the summary dict, or None if no technique could be resolved.
        """
        technique_id = self.resolve_technique_id(record)
        if not technique_id:
            return None

        relationship = self.link_indicator_to_technique(indicator, technique_id)
        if not relationship:
            return None

        store.add(relationship)
        ap = self.get_attack_pattern(technique_id)
        return {
            "technique_id": technique_id,
            "technique_name": ap.get("name"),
            "tactics": self.get_tactic(technique_id),
            "mitigations": self.get_mitigations(technique_id),
            "intrusion_sets": self.get_intrusion_sets(technique_id),
        }


if __name__ == "__main__":
    linker = AttackLinker(
        enterprise_path="data/raw/enterprise-attack.json",
        ics_path="data/raw/ics-attack.json",
    )
    linker.load()

    # Smoke test
    tid = "T1055"
    print(f"\nTechnique {tid}:")
    print("  Tactic(s):", linker.get_tactic(tid))
    print("  Mitigations:", [m["name"] for m in linker.get_mitigations(tid)][:5])
    print("  Known intrusion sets:", [a["name"] for a in linker.get_intrusion_sets(tid)][:5])
