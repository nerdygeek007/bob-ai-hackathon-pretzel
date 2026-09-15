"""
MITRE ATT&CK RAG Agent
======================
Embeds MITRE ATT&CK v15 Enterprise techniques into a ChromaDB vector store
and exposes a FastAPI endpoint at POST /api/mitre/map.

Environment variables required (set in .env or your deployment environment):
    WATSONX_API_KEY      – IBM watsonx.ai API key
    WATSONX_PROJECT_ID   – watsonx.ai project ID
    WATSONX_URL          – watsonx.ai inference URL
                           (default: https://us-south.ml.cloud.ibm.com)
    CHROMADB_PATH        – directory for persistent ChromaDB storage
                           (default: ./chroma_mitre_db)

Run:
    uvicorn mitre_rag_agent:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

import chromadb
import httpx
from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(name)s | %(message)s")
logger = logging.getLogger("mitre_rag_agent")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WATSONX_API_KEY = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
WATSONX_URL = os.getenv("WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
CHROMADB_PATH = os.getenv("CHROMADB_PATH", "./chroma_mitre_db")

# Model used for LLM re-ranking/selection.  Change to any model available in
# your watsonx.ai project (e.g. "ibm/granite-3-3-8b-instruct").
WATSONX_MODEL_ID = os.getenv("WATSONX_MODEL_ID", "ibm/granite-3-3-8b-instruct")

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AlertCluster(BaseModel):
    """Input payload for the /api/mitre/map endpoint."""
    cluster_id: str = Field(..., description="Unique ID of the alert cluster / incident")
    summary: str = Field(..., description="Correlated alert summary text (free-form prose)")
    alert_titles: List[str] = Field(default_factory=list, description="Short alert titles in the cluster")
    indicators: List[str] = Field(default_factory=list, description="IOCs, hostnames, IPs, hashes, etc.")
    tactic_hint: Optional[str] = Field(None, description="Optional tactic hint (e.g. 'Lateral Movement')")


class MitreMappingResult(BaseModel):
    """Output schema – one mapped technique."""
    technique_id: str
    technique_name: str
    tactic: str
    confidence_score: int = Field(..., ge=0, le=100)
    evidence: List[str]


# ---------------------------------------------------------------------------
# Inline MITRE ATT&CK v15 seed data
# ---------------------------------------------------------------------------
# This is a representative subset of Enterprise techniques.  Replace with a
# full JSON dump from https://github.com/mitre/cti  (enterprise-attack.json)
# for production use.

MITRE_SEED: List[dict] = [
    {"id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution", "description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system."},
    {"id": "T1059.003", "name": "Command and Scripting Interpreter: Windows Command Shell", "tactic": "Execution", "description": "Adversaries may abuse the Windows command shell for execution. The Windows command shell (cmd) is the primary command prompt on Windows systems."},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."},
    {"id": "T1110.003", "name": "Brute Force: Password Spraying", "tactic": "Credential Access", "description": "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials."},
    {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user."},
    {"id": "T1021.006", "name": "Remote Services: Windows Remote Management", "tactic": "Lateral Movement", "description": "Adversaries may use Valid Accounts to interact with remote systems using Windows Remote Management (WinRM)."},
    {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion", "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges."},
    {"id": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task", "tactic": "Persistence", "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code."},
    {"id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "tactic": "Persistence", "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key."},
    {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "description": "Adversaries may communicate using application layer protocols associated with web traffic (HTTP/HTTPS) to avoid detection."},
    {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration", "description": "Adversaries may steal data by exfiltrating it over an existing command-and-control channel."},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact", "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources."},
    {"id": "T1566.001", "name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access", "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems."},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands to cause unintended or unanticipated behavior."},
    {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit."},
    {"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory", "tactic": "Credential Access", "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS)."},
    {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system."},
    {"id": "T1518.001", "name": "Software Discovery: Security Software Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment."},
    {"id": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools", "tactic": "Defense Evasion", "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities."},
    {"id": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion", "description": "Adversaries may clear Windows Event Logs to hide the activity of an intrusion."},
    {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery", "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture."},
    {"id": "T1016", "name": "System Network Configuration Discovery", "tactic": "Discovery", "description": "Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access."},
    {"id": "T1049", "name": "System Network Connections Discovery", "tactic": "Discovery", "description": "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems."},
    {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "description": "Adversaries may transfer tools or other files from an external system into a compromised environment."},
    {"id": "T1136.001", "name": "Create Account: Local Account", "tactic": "Persistence", "description": "Adversaries may create a local account to maintain access to victim systems."},
]


# ---------------------------------------------------------------------------
# Vector DB helpers
# ---------------------------------------------------------------------------

_chroma_client: Optional[chromadb.PersistentClient] = None
_collection = None
_embed_fn = None


def _get_embed_fn():
    global _embed_fn
    if _embed_fn is None:
        _embed_fn = SentenceTransformerEmbeddingFunction(
            model_name="all-MiniLM-L6-v2"
        )
    return _embed_fn


def _get_collection():
    global _chroma_client, _collection
    if _collection is not None:
        return _collection

    Path(CHROMADB_PATH).mkdir(parents=True, exist_ok=True)
    _chroma_client = chromadb.PersistentClient(path=CHROMADB_PATH)
    _collection = _chroma_client.get_or_create_collection(
        name="mitre_attack_v15",
        embedding_function=_get_embed_fn(),
        metadata={"hnsw:space": "cosine"},
    )

    # Seed only if the collection is empty
    if _collection.count() == 0:
        logger.info("Seeding ChromaDB with %d MITRE techniques…", len(MITRE_SEED))
        _collection.add(
            ids=[t["id"] for t in MITRE_SEED],
            documents=[f"{t['name']}. {t['description']}" for t in MITRE_SEED],
            metadatas=[{"name": t["name"], "tactic": t["tactic"]} for t in MITRE_SEED],
        )
        logger.info("ChromaDB seeding complete.")

    return _collection


def _query_vector_db(query_text: str, n_results: int = 5) -> List[dict]:
    """Return top-n technique candidates from ChromaDB."""
    collection = _get_collection()
    results = collection.query(query_texts=[query_text], n_results=n_results)
    candidates = []
    for idx, doc_id in enumerate(results["ids"][0]):
        meta = results["metadatas"][0][idx]
        candidates.append({
            "id": doc_id,
            "name": meta["name"],
            "tactic": meta["tactic"],
            "description": results["documents"][0][idx],
            "distance": results["distances"][0][idx],
        })
    return candidates


# ---------------------------------------------------------------------------
# watsonx.ai LLM re-ranker
# ---------------------------------------------------------------------------

def _watsonx_select(summary: str, candidates: List[dict]) -> Optional[dict]:
    """
    Ask watsonx.ai to pick the best-matching technique from the candidate list.
    Returns the chosen candidate dict with an added 'llm_confidence' int (0–100).
    Falls back to the top vector-similarity hit when the API is not configured.
    """
    if not WATSONX_API_KEY or not WATSONX_PROJECT_ID:
        logger.warning("watsonx.ai credentials not set – using top vector similarity result.")
        return None

    candidate_text = "\n".join(
        f"[{i+1}] {c['id']} – {c['name']} ({c['tactic']}): {c['description'][:200]}"
        for i, c in enumerate(candidates)
    )
    prompt = (
        "You are a cybersecurity analyst expert in MITRE ATT&CK.\n"
        f"Given this alert cluster summary:\n\"{summary}\"\n\n"
        f"Select the SINGLE most relevant technique from the list below and respond "
        f"with ONLY a JSON object: "
        '{"index": <1-5>, "confidence": <0-100>, "reasoning": "<one sentence>"}\n\n'
        f"Candidates:\n{candidate_text}\n\nYour answer:"
    )

    try:
        token_resp = httpx.post(
            "https://iam.cloud.ibm.com/identity/token",
            data={"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": WATSONX_API_KEY},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        token_resp.raise_for_status()
        iam_token = token_resp.json()["access_token"]

        gen_resp = httpx.post(
            f"{WATSONX_URL}/ml/v1/text/generation?version=2024-05-01",
            headers={"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"},
            json={
                "model_id": WATSONX_MODEL_ID,
                "project_id": WATSONX_PROJECT_ID,
                "input": prompt,
                "parameters": {"max_new_tokens": 120, "temperature": 0.0},
            },
            timeout=30,
        )
        gen_resp.raise_for_status()
        raw = gen_resp.json()["results"][0]["generated_text"].strip()
        # Extract the JSON object from the LLM's response
        start = raw.find("{")
        end = raw.rfind("}") + 1
        parsed = json.loads(raw[start:end])
        chosen_idx = int(parsed.get("index", 1)) - 1
        confidence = int(parsed.get("confidence", 70))
        chosen = candidates[max(0, min(chosen_idx, len(candidates) - 1))].copy()
        chosen["llm_confidence"] = confidence
        chosen["llm_reasoning"] = parsed.get("reasoning", "")
        return chosen
    except Exception as exc:  # noqa: BLE001
        logger.error("watsonx.ai call failed: %s – falling back to vector similarity.", exc)
        return None


# ---------------------------------------------------------------------------
# Core mapping function
# ---------------------------------------------------------------------------

def map_cluster_to_mitre(alert_cluster: dict) -> MitreMappingResult:
    """
    Map an alert cluster to a single MITRE ATT&CK technique.

    Parameters
    ----------
    alert_cluster : dict  (matches AlertCluster schema)

    Returns
    -------
    MitreMappingResult
    """
    cluster = AlertCluster(**alert_cluster)

    # Build a rich query string from all available signal
    query_parts = [cluster.summary]
    if cluster.alert_titles:
        query_parts.append("Alerts: " + "; ".join(cluster.alert_titles))
    if cluster.indicators:
        query_parts.append("IOCs: " + ", ".join(cluster.indicators))
    if cluster.tactic_hint:
        query_parts.append(f"Suspected tactic: {cluster.tactic_hint}")
    query_text = " | ".join(query_parts)

    candidates = _query_vector_db(query_text, n_results=5)
    if not candidates:
        raise ValueError("Vector DB returned no candidates – ensure the collection is seeded.")

    chosen = _watsonx_select(cluster.summary, candidates)
    if chosen is None:
        # Fall back: use the candidate with the lowest cosine distance
        chosen = candidates[0]
        confidence = max(10, int((1.0 - chosen["distance"]) * 100))
    else:
        confidence = chosen.get("llm_confidence", 70)

    evidence: List[str] = []
    if cluster.summary:
        evidence.append(f"Summary match: {cluster.summary[:120]}")
    if cluster.alert_titles:
        evidence.extend([f"Alert: {t}" for t in cluster.alert_titles[:3]])
    if cluster.indicators:
        evidence.extend([f"IOC observed: {ioc}" for ioc in cluster.indicators[:3]])
    if chosen.get("llm_reasoning"):
        evidence.append(f"LLM rationale: {chosen['llm_reasoning']}")

    return MitreMappingResult(
        technique_id=chosen["id"],
        technique_name=chosen["name"],
        tactic=chosen["tactic"],
        confidence_score=max(0, min(100, confidence)),
        evidence=evidence or ["No additional evidence captured."],
    )


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="MITRE ATT&CK RAG Agent",
    description="Maps alert clusters to MITRE ATT&CK v15 techniques via vector search + watsonx.ai.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Pre-warm the vector DB on startup so the first request is fast."""
    try:
        _get_collection()
        logger.info("ChromaDB collection ready (%d techniques).", _get_collection().count())
    except Exception as exc:  # noqa: BLE001
        logger.error("Startup ChromaDB init failed: %s", exc)


@app.post("/api/mitre/map", response_model=MitreMappingResult, tags=["MITRE"])
async def api_map_mitre(cluster: AlertCluster):
    """
    Map an alert cluster to the most relevant MITRE ATT&CK technique.

    Returns a single technique with a confidence score and supporting evidence.
    """
    try:
        result = map_cluster_to_mitre(cluster.dict())
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unhandled error in /api/mitre/map")
        raise HTTPException(status_code=500, detail="Internal mapping error.") from exc


@app.get("/api/mitre/health", tags=["Health"])
async def health():
    """Liveness probe."""
    try:
        count = _get_collection().count()
        return {"status": "ok", "techniques_indexed": count}
    except Exception as exc:  # noqa: BLE001
        return {"status": "degraded", "error": str(exc)}
