import pytest
from conftest import configuration
from fastapi.testclient import TestClient
from sentinelforge.api import create_app


@pytest.mark.parametrize("route,title", [("how-it-works", "How It Works"), ("what-it-is", "What It Is")])
def test_public_guide_is_exact_route_and_does_not_bypass_api_auth(tmp_path, route, title):
    (tmp_path / route).mkdir()
    (tmp_path / route / "index.html").write_text(f"<title>{title}</title>")
    (tmp_path / "index.html").write_text("<title>Workspace</title>")
    app = create_app(configuration(frontend_path=tmp_path))
    with TestClient(app) as client:
        for path in (f"/{route}", f"/{route}/"):
            response = client.get(path)
            assert response.status_code == 200
            assert title in response.text
            assert response.headers["x-content-type-options"] == "nosniff"
        assert client.get("/api/stats").status_code == 401
        assert client.get(f"/api/{route}").status_code == 404
        assert client.get("/assets/not-present.js").status_code == 404
        assert client.get(f"/{route}/not-present").status_code == 404
        assert client.post(f"/{route}").status_code == 405
    app.state.engine.dispose()
