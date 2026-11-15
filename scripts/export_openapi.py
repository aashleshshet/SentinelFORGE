import json
from pathlib import Path

from sentinelforge.api import create_app
from sentinelforge.config import Settings

app = create_app(
    Settings(
        database_url="sqlite:///:memory:",
        identities=[
            {"name": "schema-export", "role": "viewer", "token": "schema-export-unused-credential-000000000"}
        ],
    )
)
Path("docs/openapi.json").write_text(json.dumps(app.openapi(), indent=2) + "\n")
app.state.engine.dispose()
