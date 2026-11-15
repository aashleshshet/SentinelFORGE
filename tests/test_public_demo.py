import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sentinelforge.config import Settings
from sentinelforge.engine import digest
from sentinelforge.public_demo import create_public_app
from sqlalchemy import text
from sqlalchemy.exc import OperationalError


def test_public_demo_reads_and_exports_across_instances(monkeypatch):
    monkeypatch.setenv("SF_DATABASE_URL", "sqlite:///operator-data-must-never-be-opened.db")
    monkeypatch.setenv("SF_LOCAL_MODE", "true")
    monkeypatch.setenv(
        "SF_IDENTITIES", '[{"name":"operator","role":"admin","token":"not-a-public-demo-credential-12345"}]'
    )
    first, second = create_public_app(), create_public_app()
    with TestClient(first) as a, TestClient(second) as b:
        assert a.get("/api/me").json() == {
            "name": "demo-visitor",
            "role": "viewer",
            "local": False,
            "demo": True,
        }
        stats = a.get("/api/stats").json()
        assert (stats["events"], stats["alerts"], stats["open_cases"]) == (18, 7, 2)
        cases = a.get("/api/cases").json()["items"]
        assert cases == b.get("/api/cases").json()["items"]
        detail = b.get("/api/cases/" + cases[0]["id"]).json()
        assert detail["timeline"] and detail["notes"] and detail["evidence"]
        evidence_id = detail["evidence"][0]["id"]
        report = b.get(f"/api/evidence/{evidence_id}/export")
        assert report.status_code == 200
        assert digest(report.json()["snapshot"]) == report.json()["sha256"]
        assert b.get("/api/events/" + detail["timeline"][0]["id"]).status_code == 200
        assert a.get("/api/alerts?severity=critical").json()["total"] == 1
        assert a.get("/api/events?source=wazuh").json()["total"] == 1
        assert len(a.get("/api/rules").json()["items"]) == 7
    with first.state.engine.begin() as connection, pytest.raises(OperationalError, match="readonly"):
        connection.execute(text("DELETE FROM events"))
    first.state.engine.dispose()
    second.state.engine.dispose()


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/ingest"),
        ("POST", "/api/demo"),
        ("PATCH", "/api/cases/example"),
        ("POST", "/api/cases/example/notes"),
        ("PUT", "/api/cases/example/checklist"),
        ("POST", "/api/cases/example/evidence"),
        ("POST", "/api/cases/example/responses"),
        ("POST", "/api/responses/example/approve"),
        ("PUT", "/api/iocs"),
    ],
)
def test_public_demo_rejects_every_mutation(method, path):
    app = create_public_app()
    with TestClient(app) as client:
        response = client.request(method, path, json={}, headers={"Authorization": "Bearer anything"})
        assert response.status_code == 403
        assert "read-only" in response.json()["detail"]
        assert client.get("/api/stats").json()["events"] == 18
    app.state.engine.dispose()


@pytest.mark.parametrize(
    "overrides",
    [
        {"database_url": "sqlite:///real.db"},
        {"local_mode": True},
        {"identities": [{"name": "admin", "role": "admin", "token": "must-not-enable-admin-in-public-demo"}]},
    ],
)
def test_public_mode_cannot_expose_operator_workspace(overrides):
    values = {
        "public_demo": True,
        "database_url": "sqlite:///:memory:",
        "identities": [],
        "local_mode": False,
    }
    with pytest.raises(ValidationError, match="Public demo requires"):
        Settings(_env_file=None, **(values | overrides))
