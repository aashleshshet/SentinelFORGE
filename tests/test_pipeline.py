import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest
from conftest import headers
from sentinelforge.config import ROOT
from sentinelforge.engine import digest

FIXTURES = json.loads((ROOT / "data/rule-fixtures.json").read_text())


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f["slug"])
@pytest.mark.parametrize("kind,expected", [("positive", 1), ("negative", 0)])
def test_rule_contract(client, fixture, kind, expected):
    response = client.post("/api/ingest", json={"events": fixture[kind]}, headers=headers("collector"))
    assert response.status_code == 200, response.text
    assert response.json()["rejected"] == 0
    alerts = client.get("/api/alerts", headers=headers()).json()["items"]
    matched = [a for a in alerts if a["rule_id"] == fixture["id"]]
    assert len(matched) == expected
    if expected:
        assert matched[0]["techniques"] == [fixture["technique"]]
        assert matched[0]["event_ids"]
        assert matched[0]["correlation_reason"]


def test_full_demo_is_idempotent_and_all_sources_are_ingested(client):
    result = client.post("/api/demo", headers=headers()).json()
    assert result["rejected"] == 0
    assert result["alerts_created"] == 7
    second = client.post("/api/demo", headers=headers()).json()
    assert second["accepted"] == 0
    assert second["duplicates"] == result["accepted"]
    stats = client.get("/api/stats", headers=headers()).json()
    assert stats["alerts"] == sum(stats["severity"].values()) == 7
    assert {s["source"] for s in stats["sources"] if s["count"]} == {
        "linux_auth",
        "auditd",
        "sysmon",
        "wazuh",
        "zeek",
        "synthetic",
    }
    assert all(t.get("name") != "Metadata unavailable" for t in stats["techniques"])


def test_out_of_order_threshold_and_suppression(client):
    failures = FIXTURES[0]["positive"]
    for item in reversed(failures):
        assert client.post("/api/ingest", json={"events": [item]}, headers=headers()).json()["rejected"] == 0
    alerts = client.get("/api/alerts", headers=headers()).json()["items"]
    assert len(alerts) == 1 and len(alerts[0]["event_ids"]) == 5
    extra = deepcopy(failures[-1])
    extra["payload"] = extra["payload"].replace("09:00:04", "09:00:05")
    assert (
        client.post("/api/ingest", json={"events": [extra]}, headers=headers()).json()["alerts_created"] == 0
    )
    assert len(client.get("/api/alerts", headers=headers()).json()["items"][0]["event_ids"]) == 6


def test_window_and_source_ip_separation(client):
    failures = deepcopy(FIXTURES[0]["positive"])
    failures[-1]["payload"] = failures[-1]["payload"].replace("09:00:04", "09:05:01")
    assert (
        client.post("/api/ingest", json={"events": failures}, headers=headers()).json()["alerts_created"] == 0
    )
    new = deepcopy(failures[-1])
    new["payload"] = new["payload"].replace("09:05:01", "09:00:04").replace("192.0.2.45", "192.0.2.46")
    assert client.post("/api/ingest", json={"events": [new]}, headers=headers()).json()["alerts_created"] == 0


def test_partial_batch_rejects_ambiguous_timestamp_and_unknown_fields(client):
    good = deepcopy(FIXTURES[3]["positive"][0])
    bad = deepcopy(good)
    bad["payload"]["timestamp"] = "2026-11-15T09:00:00"
    result = client.post(
        "/api/ingest", json={"events": [good, bad, {"source": "unsupported"}]}, headers=headers()
    ).json()
    assert (result["accepted"], result["rejected"]) == (1, 2)
    assert all("payload" not in r for r in result["results"])


def test_timezone_and_fingerprint(client):
    item = deepcopy(FIXTURES[3]["positive"][0])
    item["payload"]["timestamp"] = "2026-11-15T14:30:00+05:30"
    result = client.post("/api/ingest", json={"events": [item]}, headers=headers()).json()
    row = client.get("/api/events/" + result["results"][0]["event_id"], headers=headers()).json()
    assert row["timestamp"] == "2026-11-15T09:00:00.000000+00:00"
    assert row["fingerprint"] == digest({"normalized": row["data"], "payload": row["raw"]["payload"]})


def test_concurrent_duplicate_ingest(client):
    item = FIXTURES[3]["positive"][0]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(
            pool.map(
                lambda _: client.post("/api/ingest", json={"events": [item]}, headers=headers()).json(),
                range(8),
            )
        )
    assert sum(r["accepted"] for r in results) == 1
    assert sum(r["duplicates"] for r in results) == 7
    assert client.get("/api/alerts", headers=headers()).json()["total"] == 1


def test_host_user_correlation_and_closed_case(client):
    a = deepcopy(FIXTURES[3]["positive"][0])
    a["payload"].update(user="corp\\alice", host="host-a")
    b = deepcopy(a)
    b["payload"].update(host="host-b", timestamp="2026-11-15T09:01:00Z")
    client.post("/api/ingest", json={"events": [a, b]}, headers=headers())
    cases = client.get("/api/cases", headers=headers()).json()["items"]
    assert len(cases) == 1 and cases[0]["hosts"] == ["host-a", "host-b"]
    assert (
        "Same user" in client.get("/api/alerts", headers=headers()).json()["items"][0]["correlation_reason"]
    )
    client.patch("/api/cases/" + cases[0]["id"], json={"status": "closed"}, headers=headers())
    c = deepcopy(a)
    c["payload"]["timestamp"] = "2026-11-15T09:02:00Z"
    client.post("/api/ingest", json={"events": [c]}, headers=headers())
    assert client.get("/api/cases", headers=headers()).json()["total"] == 2


def test_generic_user_does_not_join_unrelated_hosts(client):
    events = []
    for host in ["host-a", "host-b"]:
        item = deepcopy(FIXTURES[3]["positive"][0])
        item["payload"].update(host=host, user="root")
        events.append(item)
    client.post("/api/ingest", json={"events": events}, headers=headers())
    assert client.get("/api/cases", headers=headers()).json()["total"] == 2


def test_case_window_boundary(client):
    a = deepcopy(FIXTURES[3]["positive"][0])
    b = deepcopy(a)
    b["payload"]["timestamp"] = "2026-11-15T09:15:01Z"
    client.post("/api/ingest", json={"events": [a, b]}, headers=headers())
    assert client.get("/api/cases", headers=headers()).json()["total"] == 2
