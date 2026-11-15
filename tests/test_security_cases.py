from conftest import configuration, headers
from fastapi.testclient import TestClient
from sentinelforge.api import create_app
from sentinelforge.db import Evidence
from sentinelforge.engine import digest


def seed(client):
    assert client.post("/api/demo", headers=headers()).status_code == 200
    return client.get("/api/cases", headers=headers()).json()["items"][0]["id"]


def test_authentication_and_role_boundaries(client):
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/events", headers=headers("collector")).status_code == 403
    assert client.post("/api/demo", headers=headers("viewer")).status_code == 403
    assert client.post("/api/ingest", json={"events": [{}]}, headers=headers("analyst")).status_code == 403
    case_id = seed(client)
    assert (
        client.patch(
            "/api/cases/" + case_id, json={"status": "closed"}, headers=headers("viewer")
        ).status_code
        == 403
    )
    assert client.post(f"/api/cases/{case_id}/evidence", headers=headers("viewer")).status_code == 403


def test_notes_assignment_checklist_and_audit(client):
    case_id = seed(client)
    path = "/api/cases/" + case_id
    assert (
        client.patch(path, json={"assignee": "does-not-exist"}, headers=headers("analyst")).status_code == 422
    )
    assert (
        client.patch(
            path, json={"assignee": "analyst", "status": "investigating"}, headers=headers("analyst")
        ).status_code
        == 200
    )
    note = '<script>alert("untrusted")</script>'
    assert client.post(path + "/notes", json={"text": note}, headers=headers("analyst")).status_code == 201
    assert client.post(path + "/notes", json={"text": "   "}, headers=headers("analyst")).status_code == 422
    assert (
        client.put(
            path + "/checklist", json={"key": "validate_signal", "complete": True}, headers=headers("analyst")
        ).status_code
        == 200
    )
    details = client.get(path, headers=headers()).json()
    assert details["notes"][0]["text"] == note
    assert details["checklist"]["validate_signal"] is True
    actions = client.get("/api/audit", params={"case_id": case_id}, headers=headers("analyst")).json()[
        "items"
    ]
    assert {a["action"] for a in actions} >= {"note.add", "case.update", "checklist.update"}


def test_preserved_evidence_remains_unchanged_and_hashes_verify(client):
    case_id = seed(client)
    evidence = client.post(f"/api/cases/{case_id}/evidence", headers=headers("analyst")).json()
    client.post(
        f"/api/cases/{case_id}/notes", json={"text": "Added after preservation"}, headers=headers("analyst")
    )
    report = client.get("/api/evidence/" + evidence["id"] + "/export", headers=headers("analyst")).json()
    assert digest(report["snapshot"]) == report["sha256"]
    assert report["snapshot"]["case"]["notes"] == []
    assert report["snapshot"]["events"][0]["raw"]
    with client.app.state.sessions() as db:
        row = db.get(Evidence, evidence["id"])
        row.snapshot = {"tampered": True}
        db.commit()
    assert client.get("/api/evidence/" + evidence["id"] + "/export", headers=headers()).status_code == 409


def test_simulation_requires_separate_admin_and_is_audited(client):
    case_id = seed(client)
    body = {"action": "simulate_isolation", "reason": "Investigate suspicious execution on this host"}
    row = client.post(f"/api/cases/{case_id}/responses", json=body, headers=headers()).json()
    assert client.post("/api/responses/" + row["id"] + "/approve", headers=headers()).status_code == 403
    assert (
        client.post("/api/responses/" + row["id"] + "/approve", headers=headers("analyst")).status_code == 403
    )
    result = client.post("/api/responses/" + row["id"] + "/approve", headers=headers("second"))
    assert result.status_code == 200 and result.json()["status"] == "simulated"
    assert (
        client.post("/api/responses/" + row["id"] + "/approve", headers=headers("second")).status_code == 409
    )
    assert (
        client.post(
            f"/api/cases/{case_id}/responses", json={**body, "action": "real_isolation"}, headers=headers()
        ).status_code
        == 422
    )
    audit = client.get("/api/audit", params={"case_id": case_id}, headers=headers()).json()["items"]
    assert any(a["action"] == "response.simulated" and "no endpoint" in a["detail"]["outcome"] for a in audit)


def test_limits_and_security_headers():
    with TestClient(create_app(configuration(rate_limit=2, max_body_bytes=1024))) as client:
        assert client.get("/api/me", headers=headers()).status_code == 200
        response = client.get("/api/me", headers=headers())
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["cache-control"] == "no-store"
        assert client.get("/api/me", headers=headers()).status_code == 429
        assert client.post("/oversize", content=b"x" * 1025).status_code == 413


def test_local_ioc_no_external_disclosure(client):
    body = {"value": "192.0.2.10", "label": "Lab marker", "source": "Operator fixture"}
    assert client.put("/api/iocs", json=body, headers=headers("analyst")).status_code == 403
    assert client.put("/api/iocs", json=body, headers=headers()).status_code == 200
    result = client.get("/api/iocs/lookup", params={"value": body["value"]}, headers=headers()).json()
    assert result["match"]["label"] == "Lab marker" and result["external_requests"] == 0
    assert (
        client.get("/api/iocs/lookup", params={"value": "https://example.com"}, headers=headers()).status_code
        == 422
    )


def test_pagination_search_and_error_statuses(client):
    seed(client)
    response = client.get("/api/events?limit=2&offset=2", headers=headers()).json()
    assert len(response["items"]) == 2 and response["total"] > 2
    assert client.get("/api/events?q=%25", headers=headers()).json()["total"] == 0
    assert client.get("/api/events?limit=99999", headers=headers()).status_code == 422
    assert client.get("/api/cases/not-real", headers=headers()).status_code == 404
    assert client.get("/api/events/not-real", headers=headers()).status_code == 404
