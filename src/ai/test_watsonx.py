"""
Test script for IBM watsonx.ai & Granite 3.0 Live Integration
"""

from src.ai.watsonx_client import WatsonxClient

def main():
    print("============================================================")
    print("  Project ARES: IBM watsonx.ai & Granite 3.0 Live Diagnostics")
    print("============================================================")

    client = WatsonxClient()
    status = client.get_status()

    print("\n[AI CLIENT CONFIGURATION]")
    for k, v in status.items():
        print(f"  - {k}: {v}")

    print("\n[TESTING GRANITE 3.0 INFERENCE (MAX 60 TOKENS)]")
    prompt = "Explain Zero-Trust defense in 1 concise sentence."
    res = client.generate_text(prompt, max_tokens=60, force_live=True)
    print("\n[RESULT]")
    print(res)
    print("\n============================================================")

if __name__ == "__main__":
    main()
