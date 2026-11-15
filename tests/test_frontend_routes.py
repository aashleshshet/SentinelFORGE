from conftest import configuration
from fastapi.testclient import TestClient
from sentinelforge.api import create_app


def test_public_guide_is_exact_route_and_does_not_bypass_api_auth(tmp_path):
    (tmp_path / "how-it-works").mkdir()
    (tmp_path / "how-it-works/index.html").write_text("<title>How It Works</title>")
    (tmp_path / "index.html").write_text("<title>Workspace</title>")
    app = create_app(configuration(frontend_path=tmp_path))
    with TestClient(app) as client:
        for path in ("/how-it-works", "/how-it-works/"):
            response = client.get(path)
            assert response.status_code == 200
            assert "How It Works" in response.text
            assert response.headers["x-content-type-options"] == "nosniff"
        assert client.get("/api/stats").status_code == 401
        assert client.get("/api/how-it-works").status_code == 404
        assert client.get("/assets/not-present.js").status_code == 404
        assert client.get("/how-it-works/not-present").status_code == 404
        assert client.post("/how-it-works").status_code == 405
    app.state.engine.dispose()
