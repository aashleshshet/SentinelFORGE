"""Replay JSON through the authenticated API, never execute command-line telemetry."""

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("file", type=Path)
parser.add_argument("--url", default="http://127.0.0.1:8000")
args = parser.parse_args()
token = os.environ.get("SF_TOKEN")
if not token:
    parser.error("Set SF_TOKEN to a collector or admin token from .env")
data = json.loads(args.file.read_text())
events = data["events"] if isinstance(data, dict) else data
for offset in range(0, len(events), 200):
    request = urllib.request.Request(
        args.url.rstrip("/") + "/api/ingest",
        data=json.dumps({"events": events[offset : offset + 200]}).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        result = json.load(response)
        print(json.dumps({k: v for k, v in result.items() if k != "results"}))
