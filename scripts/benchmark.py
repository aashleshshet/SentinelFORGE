"""CPU + normalization + seven rules + SQL persistence + TestClient overhead; not a network load test."""

import argparse
import json
import platform
import statistics
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sentinelforge.api import create_app
from sentinelforge.config import ROOT, Settings

parser = argparse.ArgumentParser()
parser.add_argument("--events", type=int, default=1000)
parser.add_argument("--runs", type=int, default=3)
parser.add_argument("--output", type=Path, default=ROOT / "docs/benchmark-results.json")
args = parser.parse_args()
if args.events < 1 or args.runs < 1:
    parser.error("events and runs must be positive")
results = []
for run in range(args.runs):
    with tempfile.TemporaryDirectory() as tmp:
        token = "benchmark-only-ephemeral-token-not-for-deployment"
        app = create_app(
            Settings(
                database_url="sqlite:///" + str(Path(tmp) / "benchmark.db"),
                rate_limit=100000,
                identities=[{"name": "benchmark", "role": "admin", "token": token}],
            )
        )
        batch_latencies = []
        with TestClient(app) as client:
            client.get("/api/health")
            start = time.perf_counter()
            for offset in range(0, args.events, 100):
                events = [
                    {
                        "source": "synthetic",
                        "sensor": "bench",
                        "payload": {
                            "host": f"host-{i % 100}",
                            "timestamp": "2026-11-15T09:00:00Z",
                            "kind": "process",
                            "process": "/usr/bin/id",
                            "command": "id",
                            "external_id": f"{run}-{i}",
                        },
                    }
                    for i in range(offset, min(offset + 100, args.events))
                ]
                batch_start = time.perf_counter()
                response = client.post(
                    "/api/ingest", headers={"Authorization": "Bearer " + token}, json={"events": events}
                )
                batch_latencies.append((time.perf_counter() - batch_start) * 1000)
                result = response.json()
                assert (
                    response.status_code == 200
                    and result["accepted"] == len(events)
                    and not result["rejected"]
                ), result
            duration = time.perf_counter() - start
        app.state.engine.dispose()
        results.append(
            {
                "events": args.events,
                "seconds": round(duration, 4),
                "events_per_second": round(args.events / duration, 2),
                "batch_latency_ms_median": round(statistics.median(batch_latencies), 3),
                "batch_latency_ms_max": round(max(batch_latencies), 3),
            }
        )
output = {
    "environment": {
        "python": platform.python_version(),
        "os": platform.system(),
        "machine": platform.machine(),
        "database": "SQLite file, WAL",
    },
    "workload": "Unique benign process events, batches of 100, seven active rules, one client, commit per batch",
    "scope": "In-process HTTP + validation + normalization + detection + DB; excludes network, live sensors and alert-heavy state growth",
    "median_events_per_second": round(statistics.median(r["events_per_second"] for r in results), 2),
    "runs": results,
}
args.output.write_text(json.dumps(output, indent=2) + "\n")
print(json.dumps(output, indent=2))
