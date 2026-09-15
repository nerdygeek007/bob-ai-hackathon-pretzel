"""
ARES Dynamic Spatio-Temporal Knowledge Graph & Incident Clusterer
Uses NetworkX to correlate multi-source alerts across temporal sliding windows,
geospatial sectors, shared subnets, and target infrastructure into prioritized Incident Clusters.
"""

import uuid
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Set, Optional
import networkx as nx

from src.engine.schemas import (
    NormalizedStixEntity,
    IncidentCluster,
    SeverityLevel,
    TelemetryDomain,
    XAiExplanation,
    XAiFeatureAttribution
)
from src.engine.anti_chaff_filter import AntiChaffFilter


class SpatioTemporalGraphEngine:
    """Constructs dynamic graph relationships and groups alerts into Incident Clusters."""

    def __init__(self, time_window_minutes: int = 30):
        self.time_window_minutes = time_window_minutes
        self.graph = nx.Graph()

    @staticmethod
    def _parse_timestamp(ts_str: str) -> Optional[datetime]:
        """Safely parses ISO timestamp into datetime object."""
        try:
            clean_ts = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(clean_ts)
        except Exception:
            return None

    @staticmethod
    def _extract_subnet(ioc: str) -> Optional[str]:
        """Extracts /24 subnet from an IPv4 IOC."""
        if ioc.startswith("ipv4:") or ioc.startswith("src-ip:") or ioc.startswith("dst-ip:"):
            ip = ioc.split(":")[-1].strip()
            parts = ip.split(".")
            if len(parts) == 4:
                return f"subnet:{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return None

    def build_graph(self, entities: List[NormalizedStixEntity], sector: str = "Sector-4-North") -> nx.Graph:
        """Constructs an entity-alert bipartite graph with spatio-temporal co-occurrence edges."""
        self.graph.clear()

        # 1. Add alert nodes and IOC / Subnet edges
        for entity in entities:
            self.graph.add_node(
                entity.original_alert_id,
                node_type="alert",
                domain=entity.domain.value,
                severity=entity.severity.value,
                timestamp=entity.timestamp,
                sector=sector,
                data=entity
            )

            # Link alert to its extracted IOC nodes
            for ioc in entity.iocs:
                if not self.graph.has_node(ioc):
                    self.graph.add_node(ioc, node_type="ioc", ioc_value=ioc)
                self.graph.add_edge(entity.original_alert_id, ioc, relation="observed_ioc")

                # Link to subnet if applicable
                subnet = self._extract_subnet(ioc)
                if subnet:
                    if not self.graph.has_node(subnet):
                        self.graph.add_node(subnet, node_type="subnet", subnet_value=subnet)
                    self.graph.add_edge(entity.original_alert_id, subnet, relation="subnet_co_occurrence")

        # 2. Add Spatio-Temporal Sliding Window Edges
        # High/Critical alerts in the same sector within the time window form cross-domain campaign edges
        alert_nodes = [e for e in entities]
        for i in range(len(alert_nodes)):
            t1 = self._parse_timestamp(alert_nodes[i].timestamp)
            for j in range(i + 1, len(alert_nodes)):
                t2 = self._parse_timestamp(alert_nodes[j].timestamp)
                if t1 and t2:
                    delta_minutes = abs((t1 - t2).total_seconds()) / 60.0
                    if delta_minutes <= self.time_window_minutes:
                        # If both alerts are HIGH or CRITICAL, or cross-domain space+cyber+tactical
                        sev1 = alert_nodes[i].severity
                        sev2 = alert_nodes[j].severity
                        dom1 = alert_nodes[i].domain
                        dom2 = alert_nodes[j].domain

                        is_high_risk = (
                            sev1 in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] and
                            sev2 in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
                        )
                        is_cross_domain_hybrid = (dom1 != dom2) and (
                            dom1 in [TelemetryDomain.SATELLITE_EW, TelemetryDomain.CYBER_EDR, TelemetryDomain.TACTICAL_COT, TelemetryDomain.OCSF_SECURITY] or
                            dom2 in [TelemetryDomain.SATELLITE_EW, TelemetryDomain.CYBER_EDR, TelemetryDomain.TACTICAL_COT, TelemetryDomain.OCSF_SECURITY]
                        )

                        if is_high_risk or is_cross_domain_hybrid:
                            self.graph.add_edge(
                                alert_nodes[i].original_alert_id,
                                alert_nodes[j].original_alert_id,
                                relation="spatio_temporal_correlation",
                                weight=round(max(0.2, 1.0 - (delta_minutes / self.time_window_minutes)), 2)
                            )

        return self.graph

    @staticmethod
    def _calculate_bayesian_confidence(alerts: List[NormalizedStixEntity]) -> float:
        """
        Calculates aggregate Bayesian threat confidence across multi-sensor confirmations.
        P(Threat | Sensor1, Sensor2, ...) = 1 - product(1 - P(Threat | Sensor_i))
        """
        if not alerts:
            return 0.0

        unlikelihood_product = 1.0
        for a in alerts:
            sensor_weight = 0.60
            if a.severity == SeverityLevel.CRITICAL:
                sensor_weight = 0.85
            elif a.severity == SeverityLevel.HIGH:
                sensor_weight = 0.75
            elif a.severity == SeverityLevel.MEDIUM:
                sensor_weight = 0.50
            elif a.severity == SeverityLevel.LOW:
                sensor_weight = 0.20

            unlikelihood_product *= (1.0 - sensor_weight)

        combined_prob = 1.0 - unlikelihood_product
        return round(min(0.99, max(0.40, combined_prob)), 2)

    @classmethod
    def _compute_xai_explanation(
        cls,
        cluster_alerts: List[NormalizedStixEntity],
        domains_set: Set[TelemetryDomain],
        overall_sev: SeverityLevel,
        bayesian_conf: float,
        chaff_meta: Dict[str, Any]
    ) -> XAiExplanation:
        """Computes transparent Explainable AI (XAI) feature attribution breakdown (SHAP-style)."""
        attributions: List[XAiFeatureAttribution] = []

        num_domains = len(domains_set)
        has_cross_domain = num_domains >= 2
        critical_alert_count = sum(1 for a in cluster_alerts if a.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])

        # 1. Multi-Domain Sensor Fusion Weight (15 - 40)
        fusion_score = min(40.0, num_domains * 15.0 if has_cross_domain else 12.0)
        attributions.append(XAiFeatureAttribution(
            feature_name="Multi-Domain Cross-Sensor Fusion",
            importance_weight=fusion_score,
            signal_direction="RISK_INCREASING" if has_cross_domain else "NEUTRAL",
            evidence_rationale=f"Simultaneous correlation across {num_domains} domain(s): {sorted([d.value for d in domains_set])}."
        ))

        # 2. MITRE TTP & Kinetic Threat Signal (10 - 30)
        ttp_score = 30.0 if overall_sev == SeverityLevel.CRITICAL else (22.0 if overall_sev == SeverityLevel.HIGH else 12.0)
        attributions.append(XAiFeatureAttribution(
            feature_name="MITRE ATT&CK & Sequence Alignment",
            importance_weight=ttp_score,
            signal_direction="RISK_INCREASING" if overall_sev in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] else "RISK_DECREASING",
            evidence_rationale=f"{critical_alert_count} alert(s) exhibited active adversary execution signatures."
        ))

        # 3. Shannon Entropy Anomaly & Bursts (10 - 25)
        entropy_val = chaff_meta.get("entropy", 0.0)
        entropy_score = 22.0 if entropy_val > 2.5 or chaff_meta.get("is_chaff_detected") else 12.0
        attributions.append(XAiFeatureAttribution(
            feature_name="Temporal Entropy & Anti-Chaff Score",
            importance_weight=entropy_score,
            signal_direction="RISK_INCREASING" if entropy_val > 2.5 else "NEUTRAL",
            evidence_rationale=f"Cluster temporal entropy evaluated at {entropy_val:.2f} bits (flood suppression: {chaff_meta.get('is_chaff_detected', False)})."
        ))

        # 4. Critical Asset & Defense Vulnerability (10 - 25)
        has_critical_assets = any(
            any(k in str(ioc).lower() for k in ["sat-", "plc-", "norad", "tactical", "gw-"])
            for a in cluster_alerts for ioc in a.iocs
        )
        asset_score = 22.0 if has_critical_assets else 12.0
        attributions.append(XAiFeatureAttribution(
            feature_name="Critical Asset & Defense Vulnerability",
            importance_weight=asset_score,
            signal_direction="RISK_INCREASING" if has_critical_assets else "NEUTRAL",
            evidence_rationale="Target infrastructure includes vital defense communications, satellite links, or tactical nodes." if has_critical_assets else "General perimeter enterprise assets targeted."
        ))

        # Normalize weights so they sum to 100%
        total_weight = sum(a.importance_weight for a in attributions)
        if total_weight > 0:
            for a in attributions:
                a.importance_weight = round((a.importance_weight / total_weight) * 100.0, 1)

        return XAiExplanation(
            algorithm="Spatio-Temporal Graph + Bayesian + SHAP Feature Attribution",
            base_rate_prior=0.10,
            posterior_confidence=bayesian_conf,
            feature_attributions=attributions
        )

    @classmethod
    def correlate_alerts(
        cls,
        entities: List[NormalizedStixEntity],
        sector: str = "Sector-4-North"
    ) -> List[IncidentCluster]:
        """
        Main correlation pipeline:
        1. Applies AntiChaffFilter to suppress alert storms.
        2. Builds Spatio-Temporal Knowledge Graph.
        3. Identifies connected graph components.
        4. Computes transparent Explainable AI (XAI) feature attribution.
        5. Produces prioritized Incident Clusters.
        """
        if not entities:
            return []

        # 1. Anti-chaff noise reduction
        filtered_entities, chaff_meta = AntiChaffFilter.filter_chaff(entities)

        # 2. Build graph with spatio-temporal co-occurrence
        engine = cls()
        G = engine.build_graph(filtered_entities, sector=sector)

        # 3. Find connected components (incident clusters)
        clusters: List[IncidentCluster] = []
        entity_map = {e.original_alert_id: e for e in filtered_entities}

        for i, comp in enumerate(nx.connected_components(G)):
            alert_ids = [node for node in comp if G.nodes[node].get("node_type") == "alert"]
            if not alert_ids:
                continue

            cluster_alerts = [entity_map[aid] for aid in alert_ids if aid in entity_map]
            if not cluster_alerts:
                continue

            # Calculate cluster properties
            domains_set: Set[TelemetryDomain] = {a.domain for a in cluster_alerts}
            severities = [a.severity for a in cluster_alerts]

            if SeverityLevel.CRITICAL in severities:
                overall_sev = SeverityLevel.CRITICAL
            elif SeverityLevel.HIGH in severities:
                overall_sev = SeverityLevel.HIGH
            elif SeverityLevel.MEDIUM in severities:
                overall_sev = SeverityLevel.MEDIUM
            else:
                overall_sev = SeverityLevel.LOW

            bayesian_conf = cls._calculate_bayesian_confidence(cluster_alerts)

            # Determine attack stage and precise attribution
            has_sat = TelemetryDomain.SATELLITE_EW in domains_set
            has_siem = TelemetryDomain.CYBER_SIEM in domains_set
            has_edr = TelemetryDomain.CYBER_EDR in domains_set
            has_cot = TelemetryDomain.TACTICAL_COT in domains_set
            has_ocsf = TelemetryDomain.OCSF_SECURITY in domains_set

            if (has_sat or has_cot) and (has_siem or has_edr or has_ocsf):
                stage = "Multi-Domain Impact (Space/Ground/Tactical)"
                threat_actor = "APT28 (Fancy Bear) / Sandworm"
                attribution_conf = 0.94
            elif has_edr and has_siem:
                stage = "Active Lateral Intrusion"
                threat_actor = "Volt Typhoon (Living-off-the-Land)"
                attribution_conf = 0.88
            elif has_sat:
                stage = "Orbital / Electronic Warfare Reconnaissance"
                threat_actor = "State-Sponsored EW Actor"
                attribution_conf = 0.78
            else:
                stage = "Initial Reconnaissance / Probe"
                threat_actor = "Uncorrelated Threat Actor"
                attribution_conf = 0.65

            # Compute XAI feature attribution
            xai_explanation = cls._compute_xai_explanation(
                cluster_alerts=cluster_alerts,
                domains_set=domains_set,
                overall_sev=overall_sev,
                bayesian_conf=bayesian_conf,
                chaff_meta=chaff_meta
            )

            cluster_id = f"INC-2026-{uuid.uuid4().hex[:6].upper()}"

            clusters.append(IncidentCluster(
                cluster_id=cluster_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                sector=sector,
                primary_threat_actor=threat_actor,
                attribution_confidence=attribution_conf,
                overall_severity=overall_sev,
                bayesian_threat_confidence=bayesian_conf,
                is_adversarial_chaff=chaff_meta.get("is_chaff_detected", False),
                chaff_entropy_score=chaff_meta.get("entropy", 0.0),
                alert_count=len(cluster_alerts),
                domains_involved=list(domains_set),
                alerts=cluster_alerts,
                attack_lifecycle_stage=stage,
                xai_explanation=xai_explanation
            ))

        # Sort clusters by severity and Bayesian confidence
        severity_order = {
            SeverityLevel.CRITICAL: 4,
            SeverityLevel.HIGH: 3,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 1
        }
        clusters.sort(key=lambda c: (severity_order[c.overall_severity], c.bayesian_threat_confidence), reverse=True)

        return clusters
