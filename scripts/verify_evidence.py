import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("report", type=Path)
args = parser.parse_args()
report = json.loads(args.report.read_text())
actual = hashlib.sha256(
    json.dumps(report["snapshot"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
).hexdigest()
if actual != report["sha256"]:
    raise SystemExit("FAIL: evidence hash mismatch")
print("PASS: evidence SHA-256 matches the exported snapshot")
