"""Read generated local credentials without echoing them; verify deployed demo persistence."""

import json
import urllib.request
from pathlib import Path

line = next(line for line in Path(".env").read_text().splitlines() if line.startswith("SF_IDENTITIES="))
identities = json.loads(line.partition("=")[2].strip("'"))
token = next(p["token"] for p in identities if p["role"] == "admin")
headers = {"Authorization": "Bearer " + token}
request = urllib.request.Request("http://127.0.0.1:8000/api/demo", method="POST", headers=headers)
with urllib.request.urlopen(request, timeout=30) as response:
    result = json.load(response)
assert result["rejected"] == 0 and result["alerts_created"] == 7, result
with urllib.request.urlopen(
    urllib.request.Request("http://127.0.0.1:8000/api/stats", headers=headers), timeout=10
) as response:
    result = json.load(response)
assert result["alerts"] == 7 and result["open_cases"] > 0, result
print("PASS: deployed API ingests demo, emits seven alerts and persists cases")
