"""
ARES Anti-Chaff & Adversarial Alert Flooding Filter
Uses Information Entropy (Shannon Entropy) and Temporal Density clustering to detect
engineered decoy alert storms (chaff) and isolate stealth zero-day threats buried underneath.
"""

import math
from collections import Counter
from typing import List, Dict, Tuple, Any
from src.engine.schemas import NormalizedStixEntity, SeverityLevel


class AntiChaffFilter:
    """Detects and suppresses synthetic decoy alert storms while preserving genuine stealth threats."""

    @staticmethod
    def calculate_payload_entropy(entities: List[NormalizedStixEntity]) -> float:
        """
        Calculates Shannon entropy across the descriptions of a set of alerts.
        Low entropy (< 2.0) = highly repetitive synthetic noise (chaff).
        High entropy (> 3.5) = diverse multi-vector threat payloads.
        """
        if not entities:
            return 0.0

        # Extract message prefixes / event types
        event_types = [e.name for e in entities]
        total = len(event_types)
        counts = Counter(event_types)

        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        return round(entropy, 3)

    @classmethod
    def filter_chaff(
        cls,
        entities: List[NormalizedStixEntity],
        entropy_threshold: float = 2.2,
        burst_threshold: int = 15
    ) -> Tuple[List[NormalizedStixEntity], Dict[str, Any]]:
        """
        Processes a batch of alerts:
        1. Calculates burst size and Shannon entropy.
        2. If alert storm is detected (burst > 15, entropy < 2.2), suppresses the repetitive chaff.
        3. Identifies and extracts any high-severity stealth alerts hidden in the storm.
        """
        total_alerts = len(entities)
        if total_alerts == 0:
            return [], {"is_chaff_detected": False, "entropy": 0.0, "suppressed_count": 0}

        entropy = cls.calculate_payload_entropy(entities)
        is_chaff = total_alerts >= burst_threshold and entropy < entropy_threshold

        if not is_chaff:
            return entities, {
                "is_chaff_detected": False,
                "entropy": entropy,
                "total_analyzed": total_alerts,
                "retained_alerts": total_alerts,
                "suppressed_count": 0
            }

        # Chaff storm detected: separate repetitive noise from stealth signals
        counts = Counter(e.name for e in entities)
        dominant_event, dominant_count = counts.most_common(1)[0]

        retained = []
        suppressed_count = 0

        for e in entities:
            # Always retain CRITICAL / HIGH severity alerts
            if e.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                retained.append(e)
            # If it matches the dominant repetitive chaff event, only retain sample of 2
            elif e.name == dominant_event:
                if sum(1 for r in retained if r.name == dominant_event) < 2:
                    retained.append(e)
                else:
                    suppressed_count += 1
            else:
                retained.append(e)

        return retained, {
            "is_chaff_detected": True,
            "entropy": entropy,
            "dominant_chaff_event": dominant_event,
            "total_analyzed": total_alerts,
            "retained_alerts": len(retained),
            "suppressed_count": suppressed_count,
            "reduction_percentage": round((suppressed_count / total_alerts) * 100, 1)
        }
