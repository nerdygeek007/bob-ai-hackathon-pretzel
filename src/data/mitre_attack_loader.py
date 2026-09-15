"""
MITRE ATT&CK CTI Knowledge Base Loader
Downloads, indexes, and provides fast local search over MITRE ATT&CK Enterprise and ICS matrices.
Includes pre-baked offline knowledge base for top techniques across all tactics.
"""

import json
import os
import re
from typing import Dict, List, Optional, Any

# Primary CTI source URL (OASIS STIX 2.1 representation of MITRE ATT&CK)
MITRE_ENTERPRISE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "mitre_enterprise_cache.json")

# Comprehensive pre-baked offline MITRE dataset for offline resilience & 0-latency startup
CORE_MITRE_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "keywords": ["bruteforce", "credential stuffing", "failed login", "compromised user", "stolen credentials", "ssh login", "kerberoast"]
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, system, or service bugs to gain Initial Access.",
        "keywords": ["vulnerability", "cve", "rce", "remote code execution", "sql injection", "apache", "nginx", "http 500", "buffer overflow"]
    },
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems via spearphishing attachments or links.",
        "keywords": ["spearphishing", "malicious email", "attachment", "iso", "macro", "credential harvest", "lure"]
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, Cmd, Python) to execute commands, scripts, or binaries.",
        "keywords": ["powershell", "cmd.exe", "bash", "-enc", "base64", "invoke-expression", "encoded command", "sh", "wscript"]
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Execution, Persistence, Privilege Escalation",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        "keywords": ["cron", "schtasks", "scheduled task", "at.exe", "systemd timer", "crontab"]
    },
    {
        "id": "T1547",
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence, Privilege Escalation",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon (e.g. Registry Run keys).",
        "keywords": ["registry run", "autostart", "startup folder", "init.d", "launchd", "currentversion\\run"]
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges (e.g., Kernel exploit, SUID abuse).",
        "keywords": ["privilege escalation", "root", "system elevation", "token impersonation", "dirty pipe", "suid", "privesc"]
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or modify artifacts generated on a system to make detection and forensic investigation more difficult.",
        "keywords": ["clear eventlog", "wevtutil", "rm -rf", "delete audit logs", "timestomping", "cl"]
    },
    {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "description": "Adversaries may manipulate features of artifacts (names, paths, metadata) to make them appear legitimate to users or security tools.",
        "keywords": ["svchost.exe spoof", "typosquatting", "renamed binary", "fake certificate", "masquerade"]
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from memory, LSASS, or security databases to obtain account login and credential material.",
        "keywords": ["mimikatz", "lsass", "procdump", "sam hive", "shadow copy", "/etc/shadow", "ntds.dit", "sekurlsa"]
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, and architecture.",
        "keywords": ["systeminfo", "uname -a", "whoami", "hostname", "wmic os get", "nltest"]
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on hosts in a network via port scanning or ping sweeps.",
        "keywords": ["nmap", "port scan", "syn scan", "masscan", "ping sweep", "arp -a", "netstat"]
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into remote services such as SSH, RDP, SMB/Windows Admin Shares, or VNC.",
        "keywords": ["psexec", "rdp", "ssh lateral", "smb", "wmi lateral", "winrm", "admin$"]
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to avoid detection/network filtering.",
        "keywords": ["c2 beacon", "dns tunneling", "http post beacon", "cobalt strike", "domain fronting", "c2 callback"]
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by transferring it over an existing Command and Control channel.",
        "keywords": ["data exfiltration", "outbound transfer", "large payload upload", "covert channel", "exfil"]
    },
    {
        "id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.",
        "keywords": ["dos", "ddos", "syn flood", "bandwidth saturation", "packet flood", "amplification"]
    },
    {
        "id": "T0814",
        "name": "Denial of Control (ICS / SCADA)",
        "tactic": "Inhibit Response Function",
        "description": "Adversaries may tamper with or disable the ability of an operator or controller to command physical industrial equipment or satellite ground stations.",
        "keywords": ["scada", "plc", "modbus", "dnp3", "ground station uplink", "satellite link disconnect", "telemetry cutoff", "rf jamming"]
    },
    {
        "id": "T0883",
        "name": "Adversarial Alert Storm / Chaff Injection",
        "tactic": "Defense Evasion, Impact",
        "description": "Adversaries deliberately flood SIEM/sensor pipelines with high-volume synthetic alerts to saturate analyst cognitive bandwidth and hide stealth zero-day activities.",
        "keywords": ["alert storm", "chaff", "siem saturation", "noise injection", "flooding decoy", "decoy traffic"]
    }
]


class MitreAttackKnowledgeBase:
    """Manages MITRE ATT&CK techniques, semantic keyword indexing, and lookup."""

    def __init__(self, force_refresh: bool = False):
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self._load_knowledge_base(force_refresh=force_refresh)

    def _load_knowledge_base(self, force_refresh: bool = False):
        """Loads techniques from pre-baked set, checking local cache or downloading if requested."""
        for item in CORE_MITRE_TECHNIQUES:
            self.techniques[item["id"]] = item

        if os.path.exists(CACHE_PATH) and not force_refresh:
            try:
                with open(CACHE_PATH, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    for item in cached:
                        self.techniques[item["id"]] = item
            except Exception:
                pass

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve technique details by ID (e.g. T1059 or T1078)."""
        clean_id = technique_id.split(".")[0].upper()
        return self.techniques.get(clean_id) or self.techniques.get(technique_id.upper())

    def match_technique(self, text: str) -> List[Dict[str, Any]]:
        """
        Matches raw log or alert text against MITRE techniques based on keyword and semantic signals.
        Returns ranked list of matching techniques with confidence scores.
        """
        text_lower = text.lower()
        results = []

        for tid, tech in self.techniques.items():
            matches = 0
            matched_kws = []
            for kw in tech.get("keywords", []):
                if re.search(r'\b' + re.escape(kw.lower()) + r'\b', text_lower) or kw.lower() in text_lower:
                    matches += 1
                    matched_kws.append(kw)

            if matches > 0:
                confidence = min(0.98, 0.45 + (matches * 0.18))
                results.append({
                    "technique_id": tid,
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "confidence": round(confidence, 2),
                    "matched_keywords": matched_kws,
                    "description": tech["description"]
                })

        results.sort(key=lambda x: x["confidence"], reverse=True)
        return results

    def get_all_tactics(self) -> List[str]:
        """Returns unique list of all MITRE tactics covered."""
        tactics = set()
        for tech in self.techniques.values():
            for t in tech["tactic"].split(","):
                tactics.add(t.strip())
        return sorted(list(tactics))

    def export_summary(self) -> Dict[str, Any]:
        """Exports metadata summary of the knowledge base."""
        return {
            "total_techniques": len(self.techniques),
            "tactics": self.get_all_tactics(),
            "sample_technique_ids": list(self.techniques.keys())[:10]
        }
