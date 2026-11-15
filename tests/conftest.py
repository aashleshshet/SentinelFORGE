import os

import pytest
from fastapi.testclient import TestClient
from sentinelforge.api import create_app
from sentinelforge.config import Settings
from sentinelforge.db import Base

TOKENS = {
    name: name + "-" + "test-only-token-not-for-deployment-" * 2
    for name in ("lead", "second", "analyst", "viewer", "collector")
}


def configuration(url="sqlite:///:memory:", **kwargs):
    return Settings(
        database_url=url,
        identities=[
            {"name": name, "role": role, "token": TOKENS[name]}
            for name, role in [
                ("lead", "admin"),
                ("second", "admin"),
                ("analyst", "analyst"),
                ("viewer", "viewer"),
                ("collector", "ingest"),
            ]
        ],
        **kwargs,
    )


@pytest.fixture
def client():
    app = create_app(configuration(os.environ.get("SF_TEST_DATABASE_URL", "sqlite:///:memory:")))
    Base.metadata.drop_all(app.state.engine)
    Base.metadata.create_all(app.state.engine)
    with TestClient(app) as test_client:
        yield test_client
    app.state.engine.dispose()


def headers(name="lead"):
    return {"Authorization": "Bearer " + TOKENS[name]}
