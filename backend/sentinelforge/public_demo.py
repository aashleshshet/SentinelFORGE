"""Isolated, immutable synthetic data for the public portfolio deployment."""

import hashlib
import json

from .config import ROOT
from .db import Base


def source_digest():
    digest = hashlib.sha256()
    for path in [ROOT / "data/demo.json", *sorted((ROOT / "rules").glob("*.yml"))]:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def load_snapshot(engine):
    snapshot = json.loads((ROOT / "data/public-demo.json").read_text())
    if snapshot["source_sha256"] != source_digest():
        raise RuntimeError("Public demo is stale; run python scripts/build_public_demo.py")
    with engine.begin() as connection:
        for table in Base.metadata.sorted_tables:
            rows = snapshot["tables"][table.name]
            if rows:
                connection.execute(table.insert(), rows)
        # The server exposes only reads; the database enforces this independently.
        connection.exec_driver_sql("PRAGMA query_only=ON")


def create_public_app():
    from .api import create_app
    from .config import Settings

    # Never inherit local credentials, a workspace DB URL, or telemetry file paths.
    return create_app(
        Settings(
            _env_file=None,
            public_demo=True,
            local_mode=False,
            identities=[],
            database_url="sqlite:///:memory:",
            rules_path=ROOT / "rules",
            attack_path=ROOT / "data/attack.json",
            frontend_path=ROOT / "frontend/dist",
            rate_limit=240,
            max_body_bytes=1_048_576,
        )
    )
