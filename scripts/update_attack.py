"""Explicit operator-initiated STIX import, restricted to the official MITRE source."""

import hashlib
import json
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TARGETS = {"T1110.001", "T1059.001", "T1059.004", "T1053.005", "T1136.001", "T1548.003", "T1571"}
root = Path(__file__).resolve().parents[1]
with urllib.request.urlopen(URL, timeout=60) as response:
    raw = response.read(100_000_000)
bundle = json.loads(raw)
objects = [
    o
    for o in bundle["objects"]
    if o.get("type") == "attack-pattern"
    and not o.get("revoked")
    and not o.get("x_mitre_deprecated")
    and any(r.get("external_id") in TARGETS for r in o.get("external_references", []))
]
found = {
    r["external_id"]
    for o in objects
    for r in o.get("external_references", [])
    if r.get("external_id") in TARGETS
}
if found != TARGETS:
    raise SystemExit(f"Missing active techniques: {TARGETS - found}")
output = {
    "type": "bundle",
    "id": bundle["id"],
    "objects": objects,
    "sentinelforge_provenance": {
        "source": URL,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "note": "Selected original MITRE attack-pattern objects; see NOTICE for attribution.",
    },
}
(root / "data/attack.json").write_text(json.dumps(output, indent=2) + "\n")
print(f"Imported {len(objects)} MITRE ATT&CK techniques")
