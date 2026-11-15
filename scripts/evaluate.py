"""Reproducible scenario classification; intent labels never enter detector requests."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import sqlite3
import statistics
import subprocess
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient
from sentinelforge.api import create_app
from sentinelforge.config import ROOT, Settings
from sentinelforge.rules import load_rules
from sentinelforge.schemas import now, utc

if __package__:
    from .evaluation_metrics import canonical_hash, classify, input_audit, summarize, target_status
else:
    from evaluation_metrics import canonical_hash, classify, input_audit, summarize, target_status

TOKEN = "evaluation-only-ephemeral-token-not-for-deployment"
HEADERS = {"Authorization": "Bearer " + TOKEN}
DEFAULT_DATASET = ROOT / "data/evaluation.json"


def settings():
    # Supplying every field prevents ambient .env/SF_* settings from changing the experiment.
    defaults = {
        name: field.get_default(call_default_factory=True) for name, field in Settings.model_fields.items()
    }
    defaults.update(
        database_url="sqlite:///:memory:",
        local_mode=False,
        public_demo=False,
        rate_limit=100000,
        identities=[{"name": "evaluation", "role": "admin", "token": TOKEN}],
    )
    return Settings(_env_file=None, **defaults)


def revision():
    def git(*arguments):
        try:
            return subprocess.check_output(
                ["git", *arguments], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            return None

    return {"commit": git("rev-parse", "HEAD"), "working_tree_dirty": bool(git("status", "--porcelain"))}


def provenance(path, raw, config, clock):
    paths = [
        *sorted((ROOT / "backend/sentinelforge").glob("*.py")),
        *sorted((ROOT / "scripts").glob("*.py")),
        *sorted(config.rules_path.glob("*.yml")),
        ROOT / "requirements.lock",
        ROOT / "requirements-runtime.lock",
        ROOT / "pyproject.toml",
    ]
    hashes = {
        str(file.relative_to(ROOT)): hashlib.sha256(file.read_bytes()).hexdigest()
        for file in paths
        if file.exists()
    }
    # Store non-secret effective settings, not the user's environment or credentials.
    effective = config.model_dump(mode="json", exclude={"identities"})
    effective["identities"] = [{"name": "evaluation", "role": "admin"}]
    return {
        "source_revision": revision(),
        "dataset_sha256": hashlib.sha256(raw).hexdigest(),
        "dataset_path": str(path),
        "source_file_sha256": hashes,
        "source_tree_sha256": canonical_hash(hashes),
        "effective_configuration": effective,
        "configuration_sha256": canonical_hash(effective),
        "processing_time": clock,
        "clock_policy": "One explicitly recorded UTC time for every scenario; never selected from a label",
    }


def environment():
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "database": "SQLite in memory",
        "sqlite": sqlite3.sqlite_version,
        "packages": {
            name: importlib.metadata.version(name)
            for name in ("fastapi", "sqlalchemy", "pydantic", "httpx", "PyYAML")
        },
    }


def legacy_expected(scenario):
    # Reporting-only fixture contract expectations. Intent-only cases have no rule contract.
    for fixture in json.loads((ROOT / "data/rule-fixtures.json").read_text()):
        if scenario.get("id") == fixture["slug"] + "-positive":
            return [fixture["id"]]
        if scenario.get("id") == fixture["slug"] + "-negative":
            return []
    return None


def validate_scenario(scenario, known_ids):
    errors = []
    if not isinstance(scenario, dict):
        return ["Scenario must be an object"]
    if not isinstance(scenario.get("id"), str) or not scenario["id"].strip():
        errors.append("Scenario id must be a nonempty string")
    if type(scenario.get("suspicious")) is not bool:
        errors.append("suspicious must be a boolean label")
    if not isinstance(scenario.get("events"), list) or not scenario["events"]:
        errors.append("events must be a nonempty array")
    expected = scenario.get("expected_rule_ids")
    if expected is not None and (
        not isinstance(expected, list)
        or any(not isinstance(rule, str) or rule not in known_ids for rule in expected)
    ):
        errors.append("expected_rule_ids must contain known rule IDs")
    if "context" in scenario and not isinstance(scenario["context"], dict):
        errors.append("context must be an object")
    return errors


def provision_context(client, context):
    """Only operator API payloads cross this boundary; arbitrary paths/settings cannot be supplied."""
    if set(context) - {"bindings", "approvals", "indicators"}:
        raise ValueError("Unknown operator context directive")
    binding_ids, receipts = {}, []
    for category in ("bindings", "approvals", "indicators"):
        entries = context.get(category, [])
        if not isinstance(entries, list):
            raise ValueError(f"context.{category} must be an array")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"context.{category} entry must be an object")
            body = entry.copy()
            key = body.pop("key", None) if category == "bindings" else None
            if category == "bindings" and (not isinstance(key, str) or not key or key in binding_ids):
                raise ValueError("Binding requires a unique logical key")
            if category == "approvals":
                binding_key = body.pop("binding_key", None)
                if binding_key not in binding_ids:
                    raise ValueError("Approval references an unknown binding_key")
                body["binding_id"] = binding_ids[binding_key]
            response = client.post("/api/context/" + category, headers=HEADERS, json=body)
            if response.status_code not in (200, 201):
                raise ValueError(
                    f"Operator context {category} rejected: HTTP {response.status_code}; {response.text[:1000]}"
                )
            result = response.json()
            if category == "bindings":
                binding_ids[key] = result["id"]
            receipts.append({"kind": category, "status": response.status_code, "id": result.get("id")})
    return receipts


def paginated(client, path):
    items = []
    while True:
        response = client.get(path, params={"limit": 200, "offset": len(items)}, headers=HEADERS)
        response.raise_for_status()
        page = response.json()
        items.extend(page["items"])
        if len(items) >= page["total"]:
            return items
        if not page["items"]:
            raise ValueError(f"{path} pagination stopped before the declared total")


def run_scenario(scenario, config, clock, known_ids):
    if not isinstance(scenario, dict):
        scenario = {"id": "invalid-row", "suspicious": None, "events": []}
    events = scenario.get("events", [])
    expected = scenario.get("expected_rule_ids", legacy_expected(scenario))
    outcome = {
        "id": scenario.get("id"),
        "label": scenario.get("suspicious"),
        "reason": scenario.get("reason"),
        "origin_template": scenario.get("origin_template"),
        "session_id": scenario.get("session_id"),
        "events": len(events) if isinstance(events, list) else 0,
        "sources": sorted({str(e.get("source", "unknown")) for e in events if isinstance(e, dict)})
        if isinstance(events, list)
        else [],
        "expected_rule_ids": expected,
        "emitted_rule_ids": [],
        "alert_count": 0,
        "alerts": [],
        "suppressions": [],
        "suppression_count": 0,
        "context_receipts": [],
        "alerted": None,
        "classification": "ERROR",
        "ingestion": {"accepted": 0, "duplicates": 0, "rejected": 0, "results": []},
        "errors": validate_scenario(scenario, known_ids),
        "ingest_ms": None,
    }
    if outcome["errors"]:
        return outcome
    app = None
    try:
        # The clock is a declared experiment dependency, not telemetry or evaluator labels.
        app = create_app(config, clock=lambda: clock)
        with TestClient(app) as client:
            outcome["context_receipts"] = provision_context(client, scenario.get("context", {}))
            start = time.perf_counter()
            for offset in range(0, len(events), 200):
                batch = events[offset : offset + 200]
                response = client.post("/api/ingest", headers=HEADERS, json={"events": batch})
                if response.status_code != 200:
                    outcome["errors"].append(f"Ingestion HTTP {response.status_code}: {response.text[:1000]}")
                    break
                result = response.json()
                for key in ("accepted", "duplicates", "rejected"):
                    outcome["ingestion"][key] += result[key]
                outcome["ingestion"]["results"].extend(result["results"])
                if result["rejected"]:
                    outcome["errors"].append(f"Ingestion rejected {result['rejected']} event(s)")
            outcome["ingest_ms"] = round((time.perf_counter() - start) * 1000, 3)
            if sum(outcome["ingestion"][key] for key in ("accepted", "duplicates", "rejected")) != len(
                events
            ):
                outcome["errors"].append("Ingestion outcomes do not account for every submitted event")
            alerts = paginated(client, "/api/alerts")
            outcome["alerts"] = [
                {key: alert[key] for key in ("id", "rule_id", "event_ids", "explanation")} for alert in alerts
            ]
            outcome["alert_count"] = len(alerts)
            outcome["emitted_rule_ids"] = sorted({alert["rule_id"] for alert in alerts})
            outcome["suppressions"] = paginated(client, "/api/context/suppressions")
            outcome["suppression_count"] = len(outcome["suppressions"])
            if not outcome["errors"]:
                outcome["alerted"] = bool(alerts)
                outcome["classification"] = classify(outcome["label"], outcome["alerted"])
    except Exception as error:
        # A measurement artifact must survive parser, transport, configuration and detector failures.
        outcome["errors"].append(f"{type(error).__name__}: {str(error)[:1000]}")
    finally:
        if app is not None:
            app.state.engine.dispose()
    outcome["rule_contract_match"] = (
        sorted(expected) == outcome["emitted_rule_ids"]
        if expected is not None and not outcome["errors"]
        else None
    )
    return outcome


def breakdowns(outcomes, rules):
    sources = sorted({source for outcome in outcomes for source in outcome["sources"]})
    by_source = {source: summarize([o for o in outcomes if source in o["sources"]]) for source in sources}
    by_rule = {}
    for rule in rules:
        known = [o for o in outcomes if isinstance(o["expected_rule_ids"], list)]
        rows = [
            {
                "label": rule.id in o["expected_rule_ids"],
                "alerted": rule.id in o["emitted_rule_ids"] if not o["errors"] else None,
            }
            for o in known
        ]
        by_rule[rule.id] = {
            "title": rule.meta["title"],
            "slug": rule.extension["slug"],
            "unit": "Scenario/rule contract, expected ID membership versus emitted ID membership",
            "scenarios_without_expectation": len(outcomes) - len(known),
            "emitted_alert_count": sum(a["rule_id"] == rule.id for o in outcomes for a in o["alerts"]),
            **summarize(rows),
        }
    return by_source, by_rule


def run(dataset=DEFAULT_DATASET):
    path = Path(dataset)
    errors, raw, scenarios, metadata, outcomes, rules = [], b"", [], {}, [], []
    config = settings()
    clock = now()
    manifest = None
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
        if isinstance(data, list):
            scenarios = data
            metadata = {
                "name": "legacy-v1" if path.name in ("evaluation.json", "legacy-v1.json") else path.stem,
                "partition": "development",
                "provenance": "Synthetic development regression; no independent validation",
            }
        elif isinstance(data, dict) and isinstance(data.get("scenarios"), list):
            metadata = {key: value for key, value in data.items() if key != "scenarios"}
            scenarios = data["scenarios"]
            if metadata.get("evaluation_time"):
                clock = utc(metadata["evaluation_time"])
        else:
            raise ValueError("Dataset must be a scenario array or versioned object with scenarios array")
        if not scenarios:
            errors.append("Dataset is empty")
        manifest_path = path.parent / "manifest.json"
        if manifest_path.exists():
            manifest_raw = manifest_path.read_bytes()
            manifest_data = json.loads(manifest_raw)
            expected_hash = manifest_data.get("files", {}).get(path.name)
            manifest = {
                "path": str(manifest_path),
                "sha256": hashlib.sha256(manifest_raw).hexdigest(),
                "metadata": manifest_data,
                "dataset_hash_matches": expected_hash == hashlib.sha256(raw).hexdigest(),
                "release_acceptance_designated": manifest_data.get("acceptance_dataset") == path.name,
            }
            if expected_hash is not None and not manifest["dataset_hash_matches"]:
                errors.append("Dataset content differs from frozen manifest hash")
        ids = [s.get("id") for s in scenarios if isinstance(s, dict)]
        if len({str(value) for value in ids}) != len(ids):
            errors.append("Duplicate scenario IDs")
        rules = load_rules(config.rules_path)
        known_ids = {rule.id for rule in rules}
        outcomes = [run_scenario(scenario, config, clock, known_ids) for scenario in scenarios]
        errors.extend(f"{outcome['id']}: {error}" for outcome in outcomes for error in outcome["errors"])
    except Exception as error:
        errors.append(f"{type(error).__name__}: {str(error)[:1000]}")
        # Failures before execution still retain every supplied scenario and class denominator.
        outcomes = [
            {
                "id": s.get("id") if isinstance(s, dict) else None,
                "label": s.get("suspicious") if isinstance(s, dict) else None,
                "alerted": None,
                "classification": "ERROR",
                "errors": [str(error)[:1000]],
                "expected_rule_ids": None,
                "emitted_rule_ids": [],
                "alert_count": 0,
                "alerts": [],
                "sources": [],
                "ingest_ms": None,
            }
            for s in scenarios
        ]
    summary = summarize(outcomes)
    if errors:
        for name in ("precision", "recall", "accuracy", "false_positive_rate"):
            summary[name] = None
            summary["uncertainty"]["intervals"][name].update(
                lower=None, upper=None, unavailable_reason="evaluation integrity error"
            )
    by_source, by_rule = breakdowns(outcomes, rules)
    latencies = [o["ingest_ms"] for o in outcomes if o["alerted"] is True and o["ingest_ms"] is not None]
    return {
        "schema_version": 2,
        "dataset": str(path),
        "dataset_metadata": metadata,
        "unit": "Scenario; any emitted alert predicts suspicious. No label or scenario metadata is sent to detection.",
        "valid": not errors,
        "errors": errors,
        "environment": environment(),
        "provenance": provenance(path, raw, config, clock),
        "dataset_manifest": manifest,
        "active_rule_count": len(rules),
        **summary,
        "targets": {**target_status(summary), "required": False},
        "input_audit": input_audit(scenarios),
        "by_source": by_source,
        "by_rule": by_rule,
        "rule_contracts": {
            "evaluated": sum(o.get("rule_contract_match") is not None for o in outcomes),
            "matched": sum(o.get("rule_contract_match") is True for o in outcomes),
            "mismatches": [o["id"] for o in outcomes if o.get("rule_contract_match") is False],
            "note": "Separate contract observations; an intent TP does not prove the expected rule fired",
        },
        "totals": {
            "alerts": sum(o["alert_count"] for o in outcomes),
            "suppressions": sum(o.get("suppression_count", 0) for o in outcomes),
            "ingestion": {
                key: sum(o.get("ingestion", {}).get(key, 0) for o in outcomes)
                for key in ("accepted", "duplicates", "rejected")
            },
        },
        "breakdown_note": "Source groups may overlap for multi-source scenarios; rule results measure contract correctness separately from intent classification.",
        "latency_ms": {
            "definition": "HTTP TestClient ingestion to committed response, alerting scenarios only; excludes operator context provisioning, network transit and observation delay",
            "median": round(statistics.median(latencies), 3) if latencies else None,
            "maximum": max(latencies) if latencies else None,
        },
        "limitations": [
            "Synthetic experiments, not deployment efficacy or representative prevalence",
            "Generated variants are correlated; nominal binomial intervals are not an independence claim",
            "Any rejected/failed scenario invalidates headline metrics; no implicit benign prediction",
            "No population FPR below 5% is established by these point estimates",
        ],
        "scenarios": outcomes,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=ROOT / "work/evaluation.json")
    parser.add_argument(
        "--require-targets",
        action="store_true",
        help="Fail unless every strict point-estimate target passes; report is always written",
    )
    args = parser.parse_args(argv)
    result = run(args.dataset)
    result["targets"]["required"] = args.require_targets
    result["command"] = [sys.executable, "scripts/evaluate.py", *(argv if argv is not None else sys.argv[1:])]
    code = 2 if not result["valid"] else 1 if args.require_targets and not result["targets"]["passed"] else 0
    result["exit_code"] = code
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "dataset",
                    "valid",
                    "confusion_matrix",
                    "denominators",
                    "precision",
                    "recall",
                    "accuracy",
                    "false_positive_rate",
                    "targets",
                    "errors",
                    "exit_code",
                )
            },
            indent=2,
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
