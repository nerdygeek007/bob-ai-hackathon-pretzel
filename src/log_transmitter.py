"""
ARES Phase 2 — Live Log Replay Transmitter
Reads the normalised STIX 2.1 fused dataset produced by Phase 1 and replays
events one by one, simulating a live SIEM / Kafka telemetry stream.

Usage (standalone):
    python -m src.log_transmitter                          # default dataset, 1 event/sec
    python -m src.log_transmitter --speed 5                # 5 events/sec
    python -m src.log_transmitter --loop                   # loop continuously
    python -m src.log_transmitter --file path/to/data.json # custom dataset

Programmatic usage (subscribe via callback):
    from src.log_transmitter import LogTransmitter

    def handle_event(record: dict) -> None:
        print(record["x_original_alert_id"], record["x_severity"])

    transmitter = LogTransmitter(replay_speed=10)
    transmitter.run(handle_event)           # blocking, single pass
    transmitter.run(handle_event, loop=True)  # blocking, infinite loop
"""

import argparse
import json
import os
import sys
import time
from typing import Callable, Dict, Any, Iterator, List, Optional

# ---------------------------------------------------------------------------
# Default dataset path — relative to the repo root so the module works
# whether called as `python src/log_transmitter.py` or `python -m src.log_transmitter`
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATASET_PATH = os.path.join(_REPO_ROOT, "data", "fused_dataset.json")

# Fallback: if running from inside src/, look one level up
if not os.path.exists(DEFAULT_DATASET_PATH):
    DEFAULT_DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "fused_dataset.json")


class LogTransmitter:
    """
    Replays a pre-generated STIX 2.1 fused dataset as a live event stream.

    Parameters
    ----------
    dataset_path : str
        Path to the JSON file produced by Phase 1 (``data/fused_dataset.json``).
    replay_speed : float
        Number of events to emit per second.  Use a high value (e.g. 1000) for
        stress-testing; use a low value (e.g. 0.5) for human-readable terminal demos.
    """

    def __init__(
        self,
        dataset_path: str = DEFAULT_DATASET_PATH,
        replay_speed: float = 1.0,
    ) -> None:
        self.dataset_path = dataset_path
        self.replay_speed = max(0.001, replay_speed)  # guard against division by zero
        self._records: Optional[List[Dict[str, Any]]] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> List[Dict[str, Any]]:
        """Loads the dataset from disk; raises a clear error if Phase 1 hasn't run yet."""
        if not os.path.exists(self.dataset_path):
            raise FileNotFoundError(
                f"[LogTransmitter] Dataset not found at '{self.dataset_path}'.\n"
                "Run Phase 1 first:  python -m src.engine.normalizer"
            )
        with open(self.dataset_path, "r", encoding="utf-8") as fh:
            records = json.load(fh)
        if not isinstance(records, list) or not records:
            raise ValueError(
                f"[LogTransmitter] '{self.dataset_path}' must contain a non-empty JSON array."
            )
        return records

    def _iter_events(self) -> Iterator[Dict[str, Any]]:
        """Yields every event in the dataset exactly once (sorted by x_timestamp)."""
        if self._records is None:
            self._records = self._load()
        # Re-sort each pass in case the file was regenerated with new timestamps
        yield from sorted(self._records, key=lambda r: r.get("x_timestamp", r.get("created", "")))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def stream(self, loop: bool = False) -> Iterator[Dict[str, Any]]:
        """
        Generator that yields one event dict at a time, respecting ``replay_speed``.

        Parameters
        ----------
        loop : bool
            When True, the generator never raises StopIteration — it restarts
            from the beginning of the dataset after each full pass (useful for
            long-running server processes or stress-test loops).

        Yields
        ------
        dict
            A STIX 2.1-shaped record with all ``x_*`` custom extension fields.
        """
        delay = 1.0 / self.replay_speed  # seconds between events

        while True:
            for record in self._iter_events():
                yield record
                time.sleep(delay)

            if not loop:
                break

            # Reload from disk on each loop so an updated dataset is picked up
            self._records = None
            print("[LogTransmitter] ↺  Dataset pass complete — restarting loop…", flush=True)

    def run(
        self,
        on_event: Callable[[Dict[str, Any]], None],
        loop: bool = False,
    ) -> None:
        """
        Blocking entry point that calls ``on_event(record)`` for every emitted event.

        Intended as the subscriber interface for a FastAPI background task or any
        downstream consumer (correlation engine, dashboard SSE endpoint, etc.).

        Parameters
        ----------
        on_event : Callable[[dict], None]
            Callback invoked with each emitted event dict.
        loop : bool
            When True, replays the dataset continuously until interrupted.
        """
        total = 0
        print(
            f"[LogTransmitter] Starting replay — "
            f"speed={self.replay_speed} events/sec, loop={loop}",
            flush=True,
        )
        try:
            for record in self.stream(loop=loop):
                on_event(record)
                total += 1
        except KeyboardInterrupt:
            print(f"\n[LogTransmitter] Interrupted after {total} events.", flush=True)
        else:
            print(f"[LogTransmitter] ✓ Replay complete — {total} events transmitted.", flush=True)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _default_printer(record: Dict[str, Any]) -> None:
    """Simple default callback: prints a one-liner summary to stdout."""
    ts = record.get("x_timestamp", record.get("created", "?"))[:19]
    severity = record.get("x_severity", "?").ljust(8)
    domain = record.get("x_domain", "?").ljust(15)
    alert_id = record.get("x_original_alert_id", record.get("id", "?"))
    name = record.get("name", "")[:60]
    print(f"[{ts}] {severity} | {domain} | {alert_id} | {name}", flush=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ARES Phase 2 — Live Log Replay Transmitter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--file",
        default=DEFAULT_DATASET_PATH,
        metavar="PATH",
        help="Path to fused_dataset.json  (default: data/fused_dataset.json)",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        metavar="N",
        help="Events to emit per second  (default: 1.0)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Replay the dataset continuously until Ctrl-C",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    transmitter = LogTransmitter(dataset_path=args.file, replay_speed=args.speed)
    transmitter.run(on_event=_default_printer, loop=args.loop)
