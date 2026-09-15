"""
ARES MITRE ATT&CK Mapping Engine
Classifies normalized alerts and incident clusters into standardized MITRE ATT&CK techniques,
tactics, and sub-techniques, tying each technique to exact sensor evidence IDs.
"""

from typing import List, Dict, Any
from src.engine.schemas import IncidentCluster, MitreTechniqueMatch, NormalizedStixEntity
from src.data.mitre_attack_loader import MitreAttackKnowledgeBase


class MitreMapper:
    """Maps alert telemetry to MITRE ATT&CK techniques with confidence scores and evidence links."""

    def __init__(self):
        self.kb = MitreAttackKnowledgeBase()

    def map_cluster_techniques(self, cluster: IncidentCluster) -> List[MitreTechniqueMatch]:
        """Extracts and consolidates MITRE techniques from all alerts in an incident cluster."""
        matched_dict: Dict[str, MitreTechniqueMatch] = {}

        for alert in cluster.alerts:
            text_to_search = f"{alert.name} {alert.description} {' '.join(alert.iocs)}"
            matches = self.kb.match_technique(text_to_search)

            for m in matches:
                tid = m["technique_id"]
                if tid in matched_dict:
                    # Merge evidence and update confidence
                    matched_dict[tid].evidence_alert_ids.append(alert.original_alert_id)
                    matched_dict[tid].evidence_alert_ids = sorted(list(set(matched_dict[tid].evidence_alert_ids)))
                    matched_dict[tid].confidence = min(0.99, matched_dict[tid].confidence + 0.10)
                else:
                    matched_dict[tid] = MitreTechniqueMatch(
                        technique_id=tid,
                        name=m["name"],
                        tactic=m["tactic"],
                        confidence=m["confidence"],
                        matched_keywords=m["matched_keywords"],
                        evidence_alert_ids=[alert.original_alert_id],
                        mitigations=self._get_mitigations(tid)
                    )

        # Sort by confidence descending
        results = list(matched_dict.values())
        results.sort(key=lambda x: x.confidence, reverse=True)
        return results

    @staticmethod
    def _get_mitigations(technique_id: str) -> List[str]:
        """Provides defense mitigation recommendations for specific techniques."""
        mitigation_db = {
            "T1078": ["Enforce multi-factor authentication (MFA)", "Rotate privileged service credentials", "Disable unused accounts"],
            "T1190": ["Apply vendor security patches", "Deploy Web Application Firewall (WAF)", "Restrict public ingress ports"],
            "T1059": ["Enable PowerShell Constrained Language Mode", "Block unapproved script interpreters", "Enable script block logging"],
            "T1071": ["Block unapproved outbound HTTPS destinations", "Implement TLS/SSL inspection", "Deploy DNS sinkholing"],
            "T0814": ["Air-gap SCADA/PLC control networks", "Enforce Modbus/TCP message signing", "Isolate satellite tracking subnet"],
            "T1003": ["Enable LSA Protection (RunAsPPL)", "Restrict debug privileges (SeDebugPrivilege)", "Deploy Credential Guard"],
            "T1498": ["Enable upstream anti-DDoS scrubbing", "Implement rate limiting on edge routers"]
        }
        clean_id = technique_id.split(".")[0].upper()
        return mitigation_db.get(clean_id, ["Monitor network telemetry", "Enforce principle of least privilege"])
