"""Corpus integrity tests do not run or tune the held-out detector outcomes."""

import hashlib
import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("corpus", ROOT / "scripts/build_evaluation_corpus.py")
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)


def test_frozen_plan_hashes_and_regeneration():
    docs = corpus.build_documents()
    manifest = json.loads((corpus.DESTINATION / "manifest.json").read_text())
    assert manifest["acceptance_dataset"] == "holdout.json"
    for partition, doc in docs.items():
        expected_count, positive_count = corpus.PLAN[partition]
        assert len(doc["scenarios"]) == expected_count
        assert sum(s["suspicious"] for s in doc["scenarios"]) == positive_count
        encoded = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        saved = (corpus.DESTINATION / f"{partition}.json").read_text()
        assert saved == encoded
        assert hashlib.sha256(saved.encode()).hexdigest() == manifest["files"][f"{partition}.json"]
        assert len({s["id"] for s in doc["scenarios"]}) == expected_count
        assert doc["selection_plan"]["chosen_before_target_results"] is True
        assert "synthetic" in doc["provenance"].lower()


def test_declared_split_has_no_exact_identity_overlap_and_publishes_near_candidates():
    docs = corpus.build_documents()
    report = corpus.audit_partitions(docs)
    saved = json.loads((corpus.DESTINATION / "leakage-audit.json").read_text())
    assert report == saved
    for field in (
        "cross_partition_exact_structure",
        "cross_partition_template_collisions",
        "cross_partition_session_collisions",
        "cross_partition_host_collisions",
    ):
        assert report[field] == []
    # This overlap is retained and explicitly disqualifies an independent-holdout claim.
    assert len(report["cross_partition_near_candidates"]) == 1
    assert report["cross_partition_near_candidates"][0]["jaccard_token_bigram_similarity"] >= 0.8
    dates = [doc["evaluation_time"][:10] for doc in docs.values()]
    assert len(set(dates)) == len(dates)


def test_leakage_guard_detects_copied_scenario_after_bookkeeping_changes():
    docs = corpus.build_documents()
    copied = deepcopy(docs["development"]["scenarios"][0])
    copied["id"] = "renamed-example"
    copied["session_id"] = "renamed-session"
    copied["origin_template"] = "renamed-template"
    for event in copied["events"]:
        event["sensor"] = "new-sensor"
        event["payload"]["Computer"] = "different-host"
        event["payload"]["UtcTime"] = "2030-01-01T00:00:00Z"
        event["payload"]["User"] = "different-user"
        event["payload"]["RecordID"] = "different-record"
    docs["holdout"]["scenarios"].append(copied)
    report = corpus.audit_partitions(docs)
    assert any("renamed-example" in row["scenarios"] for row in report["cross_partition_exact_structure"])
    assert any("renamed-example" in row["scenarios"] for row in report["cross_partition_near_candidates"])


def test_leakage_guard_detects_template_session_and_host_reuse():
    docs = corpus.build_documents()
    first = docs["development"]["scenarios"][0]
    copied = deepcopy(first)
    copied["events"][0]["payload"]["CommandLine"] = "changed command with retained origin"
    docs["validation"]["scenarios"].append(copied)
    report = corpus.audit_partitions(docs)
    assert report["cross_partition_template_collisions"]
    assert report["cross_partition_session_collisions"]
    assert report["cross_partition_host_collisions"]


def test_scenario_metadata_and_operator_context_are_not_telemetry():
    for doc in corpus.build_documents().values():
        for scenario in doc["scenarios"]:
            assert isinstance(scenario["suspicious"], bool)
            assert scenario["reason"]
            assert isinstance(scenario["expected_rule_ids"], list)
            for event in scenario["events"]:
                assert not {"suspicious", "reason", "expected_rule_ids", "origin_template", "context"} & set(
                    event
                )
                payload = event["payload"]
                if isinstance(payload, dict):
                    assert not {
                        "suspicious",
                        "reason",
                        "expected_rule_ids",
                        "origin_template",
                        "context",
                    } & set(payload)
            context = scenario["context"]
            keys = {binding["key"] for binding in context.get("bindings", [])}
            for approval in context.get("approvals", []):
                assert approval["binding_key"] in keys
                assert len(approval["command_sha256"]) == 64
            for indicator in context.get("indicators", []):
                assert "synthetic" in indicator["provenance"]
                assert indicator["valid_from"] <= indicator["valid_until"]


def test_cli_writes_once_and_detects_tampered_freeze(tmp_path):
    command = [
        sys.executable,
        str(ROOT / "scripts/build_evaluation_corpus.py"),
        "--output-dir",
        str(tmp_path),
    ]
    initial = subprocess.run(command, capture_output=True, text=True)
    assert initial.returncode == 0, initial.stderr
    check = subprocess.run([*command, "--check"], capture_output=True, text=True)
    assert check.returncode == 0, check.stderr
    refused = subprocess.run(command, capture_output=True, text=True)
    assert refused.returncode != 0 and "Frozen corpus exists" in refused.stderr
    manifest = tmp_path / "manifest.json"
    data = json.loads(manifest.read_text())
    data["files"]["holdout.json"] = "0" * 64
    manifest.write_text(json.dumps(data))
    tampered = subprocess.run([*command, "--check"], capture_output=True, text=True)
    assert tampered.returncode != 0 and "Frozen hash mismatch" in tampered.stderr
