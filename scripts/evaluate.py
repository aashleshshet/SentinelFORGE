"""Scenario-level classification and end-to-end in-process latency; intentionally reports misses."""

import argparse
import json
import platform
import statistics
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sentinelforge.api import create_app
from sentinelforge.config import ROOT, Settings

TOKEN = "evaluation-only-ephemeral-token-not-for-deployment"


def settings():
    return Settings(
        database_url="sqlite:///:memory:",
        rate_limit=100000,
        identities=[{"name": "evaluation", "role": "admin", "token": TOKEN}],
    )


def run():
    scenarios = json.loads((ROOT / "data/evaluation.json").read_text())
    outcomes, latencies = [], []
    for scenario in scenarios:
        app = create_app(settings())
        with TestClient(app) as client:
            start = time.perf_counter()
            response = client.post(
                "/api/ingest",
                headers={"Authorization": "Bearer " + TOKEN},
                json={"events": scenario["events"]},
            )
            elapsed = (time.perf_counter() - start) * 1000
            result = response.json()
            assert response.status_code == 200 and result["rejected"] == 0, result
            predicted = result["alerts_created"] > 0
            truth = scenario["suspicious"]
            category = ("TP" if predicted else "FN") if truth else ("FP" if predicted else "TN")
            outcomes.append(
                {
                    "id": scenario["id"],
                    "label": truth,
                    "alerted": predicted,
                    "classification": category,
                    "events": len(scenario["events"]),
                    "reason": scenario["reason"],
                    "ingest_ms": round(elapsed, 3),
                }
            )
            if predicted:
                latencies.append(elapsed)
        app.state.engine.dispose()
    counts = {key: sum(o["classification"] == key for o in outcomes) for key in ("TP", "FP", "TN", "FN")}
    tp, fp, tn, fn = (counts[k] for k in ("TP", "FP", "TN", "FN"))
    return {
        "dataset": "data/evaluation.json",
        "unit": "scenario; any generated alert is a positive prediction",
        "environment": {
            "python": platform.python_version(),
            "platform": platform.system(),
            "machine": platform.machine(),
            "database": "SQLite in memory",
        },
        "confusion_matrix": counts,
        "precision": tp / (tp + fp),
        "recall": tp / (tp + fn),
        "false_positive_rate": fp / (fp + tn),
        "latency_ms": {
            "definition": "HTTP TestClient ingestion to committed response, alerting scenarios only; no network transit or event-observation delay",
            "median": round(statistics.median(latencies), 3),
            "maximum": round(max(latencies), 3),
        },
        "limitations": [
            "Synthetic toy corpus; not representative of deployment traffic",
            "Fixtures overlap rule development; no independent holdout",
            "Scenario-level classification can credit any rule; per-rule tests separately enforce rule identity",
            "No production baseline, live sensor, distributed or PostgreSQL benchmark",
        ],
        "scenarios": outcomes,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "docs/evaluation-results.json")
    args = parser.parse_args()
    result = run()
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k not in ("scenarios", "limitations")}, indent=2))
