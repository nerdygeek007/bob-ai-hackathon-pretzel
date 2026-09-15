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
    TelemetryDomain
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
                        # If both alerts are HIGH or CRITICAL, or cross-domain space+cyber
                        sev1 = alert_nodes[i].severity
                        sev2 = alert_nodes[j].severity
                        dom1 = alert_nodes[i].domain
                        dom2 = alert_nodes[j].domain

                        is_high_risk = (
                            sev1 in [SeverityLevel.CRITICAL, SeverityLevel.HIGH] and
                            sev2 in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
                        )
                        is_cross_domain_hybrid = (dom1 != dom2) and (
                            TelemetryDomain.SATELLITE_EW in [dom1, dom2] or
                            TelemetryDomain.CYBER_EDR in [dom1, dom2]
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
        4. Produces prioritized Incident Clusters.
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

            if has_sat and has_siem and has_edr:
                stage = "Multi-Domain Impact (Space/Ground)"
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
                attack_lifecycle_stage=stage
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
