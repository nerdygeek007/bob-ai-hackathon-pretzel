"""
ARES SIEM & Multi-Source Telemetry Simulator (alrt-agent style)
Generates high-volume, realistic heterogeneous security and defense telemetry streams:
- IBM QRadar CEF (Common Event Format)
- CrowdStrike Falcon / Carbon Black EDR Process Events
- Suricata RFC 5424 Syslog
- OCSF v1.1 Class 2001 (Security Finding) / 1001 (Detection Finding) JSON
- Cursor-on-Target (CoT) MIL-STD-2525 XML & JSON Tactical Telemetry
- Spacecraft Anomaly & RF Jamming Telemetry

Supports:
- Batch export to JSON/file
- Real-time continuous streaming at configurable Events Per Second (EPS)
- Live HTTP POST ingestion directly to ARES API (/api/ingest)
"""

import argparse
import json
import random
import sys
import time
import uuid
import urllib.request
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from src.engine.schemas import (
    RawTelemetryAlert,
    TelemetryDomain,
    OCSFSecurityFinding,
    CoTTelemetry
)


class SiemSimulator:
    """High-throughput multi-format SIEM and defense telemetry generator."""

    def __init__(self, sector: str = "Sector-4-North"):
        self.sector = sector
        self._target_hosts = [
            "SRV-DC-01.local", "GW-04-SATCOM", "PLC-GROUND-02", "UAV-GCS-09",
            "WORKSTATION-OPS-44", "DB-TELEMETRY-CLUSTER", "S4-RADAR-STATION"
        ]
        self._adversary_ips = [
            "198.51.100.44", "203.0.113.88", "192.0.2.140", "45.133.1.99",
            "185.220.101.5", "103.208.220.12"
        ]
        self._internal_ips = [
            "10.4.10.15", "10.4.10.45", "10.4.20.100", "10.4.50.12",
            "192.168.10.5", "172.16.4.22"
        ]
        self._cves = ["CVE-2024-38812", "CVE-2023-48795", "CVE-2023-38606", "CVE-2022-22965"]
        self._processes = ["powershell.exe", "cmd.exe", "rundll32.exe", "whoami.exe", "vssadmin.exe", "mimikatz.exe"]

    def generate_qradar_cef(self, is_malicious: bool = True) -> RawTelemetryAlert:
        """Generates an IBM QRadar CEF formatted log."""
        ts = datetime.now(timezone.utc).isoformat()
        alert_id = f"QRADAR-{uuid.uuid4().hex[:8].upper()}"
        src_ip = random.choice(self._adversary_ips) if is_malicious else random.choice(self._internal_ips)
        dst_ip = random.choice(self._internal_ips)
        target = random.choice(self._target_hosts)

        if is_malicious:
            event_code = random.choice(["AUTH_BURST_FAIL", "PRIVILEGE_ESCALATION", "UNAUTHORIZED_MODBUS", "PORT_SCAN_AGGRESSIVE"])
            sev = random.choice([7, 8, 9, 10])
            msg = f"Potential coordinated attack detected from {src_ip} against {target}. Repeated administrative login anomalies and RPC probes."
        else:
            event_code = "ROUTINE_ADMIN_SESSION"
            sev = random.choice([1, 2, 3])
            msg = f"Authorized user session heartbeat verified on {target} from {src_ip}."

        raw_cef = (
            f"CEF:0|IBM|QRadar|7.5.0|{event_code}|{msg}|{sev}|"
            f"src={src_ip} dst={dst_ip} dhost={target} msg={msg} proto=TCP spt={random.randint(1024, 65535)} dpt=445"
        )

        return RawTelemetryAlert(
            alert_id=alert_id,
            timestamp=ts,
            domain=TelemetryDomain.CYBER_SIEM,
            source_name="IBM QRadar SIEM",
            event_code=event_code,
            raw_payload=raw_cef,
            source_ip=src_ip,
            destination_ip=dst_ip,
            target_entity=target,
            sector=self.sector
        )

    def generate_edr_process(self, is_malicious: bool = True) -> RawTelemetryAlert:
        """Generates an EDR process execution log (CrowdStrike / Carbon Black style)."""
        ts = datetime.now(timezone.utc).isoformat()
        alert_id = f"EDR-{uuid.uuid4().hex[:8].upper()}"
        host = random.choice(self._target_hosts)
        pid = random.randint(1000, 9999)

        if is_malicious:
            proc = random.choice(self._processes)
            cmd = f"{proc} -enc aQB3AHIAIABzAGw... -ExecutionPolicy Bypass -NoProfile -dump lsass"
            cve = random.choice(self._cves)
            event_code = "SUSPICIOUS_PROCESS_SPAWN"
            payload = {
                "sensor": "CrowdStrike Falcon Sensor",
                "event_type": "ProcessCreation",
                "host": host,
                "pid": pid,
                "parent_pid": pid - 12,
                "process_name": proc,
                "command_line": cmd,
                "sha256": uuid.uuid4().hex + uuid.uuid4().hex,
                "related_cve": cve,
                "verdict": "MALICIOUS_INJECTION"
            }
        else:
            proc = "svchost.exe"
            cmd = "svchost.exe -k netsvcs -p -s BITS"
            event_code = "BENIGN_SERVICE_START"
            payload = {
                "sensor": "CrowdStrike Falcon Sensor",
                "event_type": "ProcessCreation",
                "host": host,
                "pid": pid,
                "parent_pid": 648,
                "process_name": proc,
                "command_line": cmd,
                "verdict": "VERIFIED_SYSTEM"
            }

        return RawTelemetryAlert(
            alert_id=alert_id,
            timestamp=ts,
            domain=TelemetryDomain.CYBER_EDR,
            source_name="CrowdStrike EDR",
            event_code=event_code,
            raw_payload=json.dumps(payload),
            target_entity=host,
            sector=self.sector
        )

    def generate_suricata_syslog(self, is_malicious: bool = True) -> RawTelemetryAlert:
        """Generates a Suricata RFC 5424 Syslog intrusion alert."""
        ts = datetime.now(timezone.utc).isoformat()
        alert_id = f"SURI-{uuid.uuid4().hex[:8].upper()}"
        src_ip = random.choice(self._adversary_ips) if is_malicious else random.choice(self._internal_ips)
        dst_ip = random.choice(self._internal_ips)

        if is_malicious:
            sid = random.choice([2013028, 2024101, 2018959])
            sig = "ET TROJAN Cobalt Strike Beaconing Traffic Detected via HTTP POST /submit.php"
            event_code = "SURICATA_ET_ALERT"
            prio = 1
        else:
            sid = 2200029
            sig = "SURICATA SURICATA STREAM ESTABLISHED SYNACK resend"
            event_code = "SURICATA_INFO"
            prio = 4

        syslog = f"<134>1 {ts} s4-sensor-01 suricata 4821 - [Classification: Network Anomaly] [Priority: {prio}] {{{sig}}} [gid: 1] [sid: {sid}] {{{src_ip}:49152 -> {dst_ip}:8080}}"

        return RawTelemetryAlert(
            alert_id=alert_id,
            timestamp=ts,
            domain=TelemetryDomain.CYBER_SIEM,
            source_name="Suricata IDS",
            event_code=event_code,
            raw_payload=syslog,
            source_ip=src_ip,
            destination_ip=dst_ip,
            sector=self.sector
        )

    def generate_ocsf_finding(self, is_malicious: bool = True) -> Dict[str, Any]:
        """Generates an Open Cybersecurity Schema Framework (OCSF v1.1) Class 2001 Finding."""
        ts = datetime.now(timezone.utc).isoformat()
        uid = f"OCSF-{uuid.uuid4().hex[:8].upper()}"
        host = random.choice(self._target_hosts)
        src_ip = random.choice(self._adversary_ips) if is_malicious else random.choice(self._internal_ips)

        finding = {
            "class_uid": 2001,
            "activity_id": 1,
            "severity_id": 5 if is_malicious else 2,
            "time": ts,
            "finding_info": {
                "uid": uid,
                "title": "Adversary Lateral Movement & C2 Beaconing" if is_malicious else "Normal Configuration Inspection",
                "desc": f"Observed abnormal communications directed to C2 node from {host} ({src_ip})." if is_malicious else "Routine policy audit passed."
            },
            "device": {
                "hostname": host,
                "ip": src_ip
            },
            "observables": [
                {"type": "ipv4", "value": src_ip},
                {"type": "defense-asset", "value": host},
                {"type": "cve", "value": random.choice(self._cves) if is_malicious else "NONE"}
            ],
            "metadata": {
                "version": "1.1.0",
                "product": {"name": "ARES SIEM Ingestion", "vendor_name": "IBM Bob"},
                "event_code": "OCSF_SEC_2001"
            }
        }
        return finding

    def generate_cot_track(self, is_malicious: bool = True) -> Dict[str, Any]:
        """Generates a Cursor-on-Target (CoT) MIL-STD-2525 tactical track event."""
        ts = datetime.now(timezone.utc).isoformat()
        uid = f"SAT-{random.randint(10, 99)}-TACTICAL" if is_malicious else f"FRIENDLY-RADAR-{random.randint(1, 10)}"
        cot_type = "a-h-G" if is_malicious else "a-f-G"
        lat = round(random.uniform(32.0, 54.0), 4)
        lon = round(random.uniform(10.0, 45.0), 4)

        detail = {
            "contact": {"callsign": uid, "status": "COMPROMISED" if is_malicious else "NOMINAL"},
            "jamming": {"band": "Ku-Band", "snr_drop": "-18dB"} if is_malicious else {"status": "clear"}
        }

        return {
            "uid": uid,
            "type": cot_type,
            "how": "m-g",
            "time": ts,
            "start": ts,
            "stale": ts,
            "lat": lat,
            "lon": lon,
            "hae": 550000.0 if "SAT" in uid else 200.0,
            "ce": 15.0,
            "le": 10.0,
            "detail": detail
        }

    def generate_event(self, scenario: str = "apt_hybrid") -> Dict[str, Any]:
        """Generates a single event according to the chosen scenario."""
        r = random.random()

        if scenario == "benign":
            generator_choice = random.choice([
                lambda: self.generate_qradar_cef(is_malicious=False).model_dump(),
                lambda: self.generate_edr_process(is_malicious=False).model_dump(),
                lambda: self.generate_suricata_syslog(is_malicious=False).model_dump(),
                lambda: self.generate_ocsf_finding(is_malicious=False),
                lambda: self.generate_cot_track(is_malicious=False)
            ])
            return generator_choice()

        if scenario == "chaff_flood":
            # 85% high-entropy noise bursts + 15% stealth attack
            if r < 0.85:
                return self.generate_qradar_cef(is_malicious=False).model_dump()
            else:
                return self.generate_edr_process(is_malicious=True).model_dump()

        # Default: apt_hybrid
        # Mix of QRadar CEF, CrowdStrike EDR, Suricata, OCSF finding, and CoT tactical track
        generators = [
            lambda: self.generate_qradar_cef(is_malicious=True).model_dump(),
            lambda: self.generate_edr_process(is_malicious=True).model_dump(),
            lambda: self.generate_suricata_syslog(is_malicious=True).model_dump(),
            lambda: self.generate_ocsf_finding(is_malicious=True),
            lambda: self.generate_cot_track(is_malicious=True),
            lambda: self.generate_qradar_cef(is_malicious=False).model_dump()  # background noise
        ]
        return random.choice(generators)()

    def generate_batch(self, count: int = 50, scenario: str = "apt_hybrid") -> List[Dict[str, Any]]:
        """Generates a batch of N heterogeneous simulated alerts."""
        return [self.generate_event(scenario=scenario) for _ in range(count)]

    def stream(
        self,
        eps: float = 10.0,
        duration_seconds: Optional[float] = None,
        push_api: Optional[str] = None,
        scenario: str = "apt_hybrid"
    ):
        """Continuously streams events at the specified Events Per Second (EPS)."""
        interval = 1.0 / max(0.1, eps)
        start_time = time.time()
        sent_count = 0

        print(f"[*] Starting ARES SIEM Telemetry Stream: {eps} EPS | Scenario: '{scenario}' | Sector: {self.sector}")
        if push_api:
            print(f"[*] Live Forwarding Target: {push_api}")

        try:
            while True:
                if duration_seconds and (time.time() - start_time) >= duration_seconds:
                    break

                event = self.generate_event(scenario=scenario)
                sent_count += 1

                # Display or push
                if push_api:
                    self._push_to_api(push_api, event)
                    if sent_count % int(max(1, eps)) == 0:
                        sys.stdout.write(f"\r[+] Streamed {sent_count} telemetry alerts to {push_api}...")
                        sys.stdout.flush()
                else:
                    print(json.dumps(event))

                time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] SIEM Stream terminated by operator.")

        print(f"\n[+] Finished streaming. Total alerts generated: {sent_count}")

    @staticmethod
    def _push_to_api(api_url: str, event: Dict[str, Any]):
        """Posts an event payload to the ingestion API."""
        try:
            # Wrap as alert or list if needed
            body = json.dumps([event]).encode("utf-8")
            req = urllib.request.Request(
                api_url,
                data=body,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                pass
        except Exception as e:
            # Non-blocking error output
            pass


def main():
    parser = argparse.ArgumentParser(description="ARES SIEM & Tactical Telemetry Simulator (alrt-agent)")
    parser.add_argument("--mode", choices=["batch", "stream"], default="batch", help="Execution mode")
    parser.add_argument("--scenario", choices=["apt_hybrid", "chaff_flood", "benign"], default="apt_hybrid", help="Threat scenario")
    parser.add_argument("--sector", default="Sector-4-North", help="Operational sector")
    parser.add_argument("--count", type=int, default=25, help="Event count for batch mode")
    parser.add_argument("--eps", type=float, default=10.0, help="Events per second for stream mode")
    parser.add_argument("--duration", type=float, default=None, help="Duration in seconds for stream mode")
    parser.add_argument("--push-api", default=None, help="HTTP URL of ingestion API (e.g. http://127.0.0.1:8000/api/ingest)")
    parser.add_argument("--output", default=None, help="File path to save batch JSON output")

    args = parser.parse_args()

    sim = SiemSimulator(sector=args.sector)

    if args.mode == "batch":
        events = sim.generate_batch(count=args.count, scenario=args.scenario)
        out_json = json.dumps(events, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out_json)
            print(f"[+] Saved {len(events)} simulated alerts to {args.output}")
        else:
            print(out_json)
    else:
        sim.stream(
            eps=args.eps,
            duration_seconds=args.duration,
            push_api=args.push_api,
            scenario=args.scenario
        )


if __name__ == "__main__":
    main()
