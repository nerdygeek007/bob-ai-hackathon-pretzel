"""
ARES Training & In-Context Dataset Builder
Generates structured JSONL fine-tuning data, few-shot prompt libraries,
and quantitative evaluation benchmark pairs for IBM watsonx.ai Granite 3.0 and IBM Bob.
"""

import json
import os
from typing import List, Dict, Any

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "processed")


def build_training_datasets():
    """Builds and serializes all training and evaluation artifacts."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    # 1. Granite 3.0 Fine-Tuning JSONL Format (Chat Completion format)
    training_samples = [
        {
            "messages": [
                {
                    "role": "system",
                    "content": "You are ARES, an elite Defense Threat Intelligence Assistant powered by IBM Granite 3.0. Extract MITRE ATT&CK techniques and synthesize military BLUF briefings with zero hallucinations."
                },
                {
                    "role": "user",
                    "content": "Analyze alert: CEF:0|IBM|QRadar|AUTH_FAIL_BURST|1420 failed SSH logins on Gateway-04 followed by powershell.exe -enc Base64 payload."
                },
                {
                    "role": "assistant",
                    "content": json.dumps({
                        "tactic": "Initial Access & Execution",
                        "techniques": [
                            {"id": "T1078", "name": "Valid Accounts", "confidence": 0.95},
                            {"id": "T1059.001", "name": "PowerShell", "confidence": 0.98}
                        ],
                        "severity": "CRITICAL",
                        "bluf": "Compromise of Gateway-04 via SSH credential stuffing followed by execution of an encoded PowerShell payload.",
                        "recommended_action": "Revoke gateway credentials, terminate SSH sessions, and isolate host PID."
                    }, indent=2)
                }
            ]
        },
        {
            "messages": [
                {
                    "role": "system",
                    "content": "You are ARES, an elite Defense Threat Intelligence Assistant powered by IBM Granite 3.0."
                },
                {
                    "role": "user",
                    "content": "Analyze alert: High-power RF carrier jamming on 14.2 GHz. SNR dropped by 18.4 dB. Transponder lock lost on SAT-DEF-09."
                },
                {
                    "role": "assistant",
                    "content": json.dumps({
                        "tactic": "Inhibit Response Function",
                        "techniques": [
                            {"id": "T0814", "name": "Denial of Control / RF Jamming", "confidence": 0.91}
                        ],
                        "severity": "CRITICAL",
                        "bluf": "Electronic warfare RF jamming detected on 14.2 GHz uplink causing loss of telemetry lock on SAT-DEF-09.",
                        "recommended_action": "Switch ground station uplink to secondary encrypted LEO constellation and trigger frequency hopping."
                    }, indent=2)
                }
            ]
        },
        {
            "messages": [
                {
                    "role": "system",
                    "content": "You are ARES, an elite Defense Threat Intelligence Assistant powered by IBM Granite 3.0."
                },
                {
                    "role": "user",
                    "content": "Analyze alert: FW_DROP: Inbound TCP SYN probe dropped from 192.0.2.14 on port 1014. Repeated 5000 times."
                },
                {
                    "role": "assistant",
                    "content": json.dumps({
                        "tactic": "Reconnaissance / Adversarial Chaff",
                        "techniques": [
                            {"id": "T1046", "name": "Network Service Discovery", "confidence": 0.70},
                            {"id": "T0883", "name": "Adversarial Alert Storm", "confidence": 0.85}
                        ],
                        "severity": "LOW",
                        "is_chaff": True,
                        "bluf": "Repetitive port scanning activity identified as automated reconnaissance or decoy chaff. Suppressed from high-priority queue.",
                        "recommended_action": "Apply dynamic edge firewall drop rule; maintain telemetry baseline monitoring."
                    }, indent=2)
                }
            ]
        }
    ]

    jsonl_path = os.path.join(PROCESSED_DIR, "training_data_granite_finetune.jsonl")
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for s in training_samples:
            f.write(json.dumps(s) + "\n")

    # 2. Few-Shot In-Context Prompt Library
    few_shot_path = os.path.join(PROCESSED_DIR, "few_shot_examples.json")
    with open(few_shot_path, "w", encoding="utf-8") as f:
        json.dump(training_samples, f, indent=2)

    # 3. Quantitative Evaluation Benchmark Pairs
    eval_benchmark = [
        {
            "test_id": "TEST-CYBER-001",
            "input_payload": "CEF:0|IBM|QRadar|AUTH_FAIL_BURST|1420 failed logins from 198.51.100.44",
            "expected_techniques": ["T1078"],
            "expected_severity": "HIGH",
            "is_threat": True
        },
        {
            "test_id": "TEST-SAT-002",
            "input_payload": "RF carrier jamming detected on 14.2 GHz. Transponder lock lost.",
            "expected_techniques": ["T0814"],
            "expected_severity": "CRITICAL",
            "is_threat": True
        },
        {
            "test_id": "TEST-BENIGN-003",
            "input_payload": "INFO: Scheduled weekly authorized vulnerability scanner 10.3.0.254 scanned 50 hosts.",
            "expected_techniques": [],
            "expected_severity": "LOW",
            "is_threat": False
        },
        {
            "test_id": "TEST-EDR-004",
            "input_payload": "powershell.exe -enc Base64 payload spawned by svc_satcomm with LSASS dump.",
            "expected_techniques": ["T1059", "T1003"],
            "expected_severity": "CRITICAL",
            "is_threat": True
        }
    ]

    eval_path = os.path.join(PROCESSED_DIR, "eval_benchmark.json")
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(eval_benchmark, f, indent=2)

    return {
        "jsonl_training_file": jsonl_path,
        "few_shot_file": few_shot_path,
        "eval_benchmark_file": eval_path,
        "training_samples_count": len(training_samples),
        "benchmark_cases_count": len(eval_benchmark)
    }


if __name__ == "__main__":
    res = build_training_datasets()
    print("=== ARES Training & Benchmark Datasets Built ===")
    print(f"Fine-tuning JSONL: {res['jsonl_training_file']} ({res['training_samples_count']} samples)")
    print(f"Eval Benchmark:    {res['eval_benchmark_file']} ({res['benchmark_cases_count']} cases)")
