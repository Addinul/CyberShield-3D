"""Replay sample Wazuh alerts into the orchestrator, as the webhook would.

Usage: python replay.py fixtures/ssh_bruteforce_session.json [--url http://127.0.0.1:8000] [--gap 0.3]
The token is read from INGEST_TOKEN, like the orchestrator.
"""
import argparse
import json
import os
import time
import urllib.request


def main():
    p = argparse.ArgumentParser()
    p.add_argument("fixture")
    p.add_argument("--url", default="http://127.0.0.1:8000")
    p.add_argument("--gap", type=float, default=0.3, help="seconds between alerts")
    args = p.parse_args()
    with open(args.fixture) as f:
        alerts = json.load(f)
    for a in alerts:
        req = urllib.request.Request(
            f"{args.url}/ingest/wazuh",
            data=json.dumps(a).encode(),
            headers={"Content-Type": "application/json", "X-CyberShield-Token": os.environ["INGEST_TOKEN"]},
            method="POST",
        )
        with urllib.request.urlopen(req) as r:
            print(a["rule"]["id"], a["rule"]["description"][:60], "->", r.read().decode())
        time.sleep(args.gap)


if __name__ == "__main__":
    main()
