"""
ARES Live IBM Bob Agent Runner
Dispatches real-time threat intelligence correlation & reasoning tasks to IBM Bob CLI.
Leverages the user's live BOB_API_KEY, consumes Bobcoins, and logs sessions to bob_sessions/.
"""

import os
import sys
import json
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.ai.watsonx_client import _load_dotenv

BOBSHELL_DIST = r"D:\Dev\npm-global\node_modules\bobshell\dist\bob.js"


def run_bob_task(prompt: str, max_turns: int = 1) -> Dict[str, Any]:
    """Executes a live task on IBM Bob CLI using the user's BOB_API_KEY."""
    _load_dotenv()
    env = os.environ.copy()
    api_key = env.get("BOB_API_KEY", "")

    if not api_key:
        return {
            "success": False,
            "error": "BOB_API_KEY not found in .env or environment.",
            "output": ""
        }

    cmd = [
        "node",
        BOBSHELL_DIST,
        "run",
        "--trust",
        "--accept-license",
        "--max-turns",
        str(max_turns),
        prompt
    ]

    try:
        res = subprocess.run(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=90,
            cwd=PROJECT_ROOT
        )

        output_text = res.stdout.strip()
        stderr_text = res.stderr.strip()

        # Save session transcript to bob_sessions/
        session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        log_dir = os.path.join(PROJECT_ROOT, "bob_sessions")
        os.makedirs(log_dir, exist_ok=True)
        session_file = os.path.join(log_dir, f"bob_live_run_{session_id}.txt")
        with open(session_file, "w", encoding="utf-8") as f:
            f.write(f"=== IBM BOB LIVE TASK EXECUTION ===\n")
            f.write(f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
            f.write(f"Prompt: {prompt}\n")
            f.write(f"Return Code: {res.returncode}\n")
            f.write(f"--- STDOUT ---\n{output_text}\n")
            if stderr_text:
                f.write(f"--- STDERR ---\n{stderr_text}\n")

        return {
            "success": res.returncode == 0,
            "session_file": session_file,
            "output": output_text,
            "stderr": stderr_text
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "output": ""
        }


if __name__ == "__main__":
    test_prompt = (
        "You are ARES, an elite Defense Intelligence Assistant. "
        "Summarize the threat posture for an APT28 hybrid space/ground intrusion in Sector 4."
    )
    print("[ARES] Dispatching live task to IBM Bob with live BOB_API_KEY...")
    result = run_bob_task(test_prompt)
    if result["success"]:
        print("[SUCCESS] IBM Bob responded successfully!")
        print(f"[LOG] Saved transcript to: {result['session_file']}")
        print("\n--- IBM BOB RESPONSE ---")
        print(result["output"])
    else:
        print(f"[FAIL] {result.get('error', result.get('stderr'))}")
