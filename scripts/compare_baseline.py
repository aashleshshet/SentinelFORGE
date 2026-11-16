"""Run frozen experiment inputs through an archived historical detector.

The historical backend has no context API. Context is explicitly unsupported in
this reference run, not provisioned, relabeled or treated as current ablation.
"""

import argparse
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def worker(args):
    sys.path.insert(0, str(args.checkout / "backend"))
    from evaluate import breakdowns, environment, legacy_expected
    from evaluation_metrics import classify, input_audit, summarize, target_status
    from fastapi.testclient import TestClient
    from sentinelforge.api import create_app
    from sentinelforge.config import Settings
    from sentinelforge.rules import load_rules

    raw = args.dataset.read_bytes()
    data = json.loads(raw)
    scenarios = data if isinstance(data, list) else data["scenarios"]
    rules = load_rules(args.checkout / "rules")
    token = "baseline-evaluation-only-not-for-deployment"
    headers = {"Authorization": "Bearer " + token}
    outcomes = []
    for scenario in scenarios:
        outcome = {
            "id": scenario["id"],
            "label": scenario["suspicious"],
            "alerted": None,
            "classification": "ERROR",
            "errors": [],
            "alerts": [],
            "alert_count": 0,
            "emitted_rule_ids": [],
            "expected_rule_ids": scenario.get("expected_rule_ids", legacy_expected(scenario)),
            "sources": sorted({e.get("source", "unknown") for e in scenario["events"]}),
            "operator_context_supported": False,
            "operator_context_present": bool(scenario.get("context")),
            "ingestion": {"accepted": 0, "duplicates": 0, "rejected": 0},
        }
        defaults = {
            name: field.get_default(call_default_factory=True)
            for name, field in Settings.model_fields.items()
        }
        defaults.update(
            database_url="sqlite:///:memory:",
            local_mode=False,
            public_demo=False,
            rate_limit=100000,
            identities=[{"name": "evaluation", "role": "admin", "token": token}],
        )
        app = create_app(Settings(_env_file=None, **defaults))
        try:
            with TestClient(app) as client:
                response = client.post("/api/ingest", headers=headers, json={"events": scenario["events"]})
                if response.status_code != 200:
                    outcome["errors"].append(f"HTTP {response.status_code}")
                else:
                    result = response.json()
                    outcome["ingestion"] = {
                        key: result[key] for key in ("accepted", "duplicates", "rejected")
                    }
                    if result["rejected"]:
                        outcome["errors"].append(f"Rejected {result['rejected']} records")
                    alerts = client.get("/api/alerts?limit=200", headers=headers).json()["items"]
                    outcome["alerts"] = alerts
                    outcome["alert_count"] = len(alerts)
                    outcome["emitted_rule_ids"] = sorted({a["rule_id"] for a in alerts})
                    if not outcome["errors"]:
                        outcome["alerted"] = bool(alerts)
                        outcome["classification"] = classify(outcome["label"], outcome["alerted"])
        except Exception as error:
            outcome["errors"].append(f"{type(error).__name__}: {error}")
        finally:
            app.state.engine.dispose()
        outcomes.append(outcome)
    summary = summarize(outcomes)
    sources, per_rule = breakdowns(outcomes, rules)
    report = {
        "comparison": "Archived baseline detector on the frozen event inputs; operator context unsupported by historical backend",
        "source_revision": args.revision,
        "dataset": str(args.dataset),
        "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "source_file_sha256": {
            str(p.relative_to(args.checkout)): hashlib.sha256(p.read_bytes()).hexdigest()
            for group in ["backend/sentinelforge/*.py", "rules/*.yml", "requirements.lock"]
            for p in sorted(args.checkout.glob(group))
        },
        "environment": environment(),
        "active_rule_count": len(rules),
        "valid": not any(o["errors"] for o in outcomes),
        **summary,
        "targets": target_status(summary),
        "input_audit": input_audit([{k: v for k, v in s.items() if k != "context"} for s in scenarios]),
        "by_source": sources,
        "by_rule": per_rule,
        "scenarios": outcomes,
        "limitations": [
            "Synthetic co-designed inputs, not independent deployment validation",
            "Additional operator context is a new capability and is not available in this historical reference",
            "No scenario metadata or labels enter detector requests",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {"dataset": args.dataset.name, "matrix": report["confusion_matrix"], "valid": report["valid"]}
        )
    )
    return 0 if report["valid"] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="78b7bd5c7e17f95993772204d7eaf66a6eec424f")
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.dataset = args.dataset.resolve()
    args.output = args.output.resolve()
    if args.checkout:
        return worker(args)
    sha = subprocess.check_output(
        ["git", "rev-parse", "--verify", args.revision + "^{commit}"], cwd=ROOT, text=True
    ).strip()
    archive = subprocess.check_output(["git", "archive", sha], cwd=ROOT)
    with tempfile.TemporaryDirectory(prefix="sentinelforge-baseline-") as directory:
        with tarfile.open(fileobj=io.BytesIO(archive)) as source:
            source.extractall(directory, filter="data")
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--checkout",
                directory,
                "--revision",
                sha,
                "--dataset",
                str(args.dataset),
                "--output",
                str(args.output),
            ],
            cwd=directory,
            env={key: value for key, value in os.environ.items() if not key.startswith("SF_")},
        )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
