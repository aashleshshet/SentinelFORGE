import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sentinelforge.api import create_app
from sentinelforge.config import Settings


def test_local_mode_without_credentials():
    app = create_app(Settings(local_mode=True, identities=[], database_url="sqlite:///:memory:"))
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        assert client.get("/api/me").json() == {"name": "__local__", "role": "admin", "local": True}
        result = client.post("/api/demo").json()
        assert result["alerts_created"] == 7
        case_id = client.get("/api/cases").json()["items"][0]["id"]
        assert client.patch("/api/cases/" + case_id, json={"assignee": "__local__"}).status_code == 200
        assert client.get("/api/me", headers={"Authorization": "Bearer invalid"}).status_code == 401
        assert client.post("/api/demo", headers={"Origin": "https://evil.example"}).status_code == 403
        assert client.get("/api/events", headers={"Host": "evil.example"}).status_code == 403
        assert client.get("/api/events", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
        assert client.post("/api/demo", headers={"Origin": "http://127.0.0.1:9999"}).status_code == 403


def test_remote_peer_cannot_use_local_mode():
    app = create_app(Settings(local_mode=True, identities=[], database_url="sqlite:///:memory:"))
    with TestClient(app, base_url="http://127.0.0.1", client=("198.51.100.1", 12345)) as client:
        assert client.get("/api/events", headers={"X-Forwarded-For": "127.0.0.1"}).status_code == 403


def test_no_silent_auth_bypass_when_local_mode_is_off():
    with pytest.raises(ValidationError):
        Settings(local_mode=False, identities=[])
