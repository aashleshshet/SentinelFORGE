"""Rebuild the public snapshot exclusively from the bundled synthetic replay.

Runs the real ingestion, detection, correlation and evidence-preservation API.
It never opens the operator's database or reads credentials from .env.
"""

import argparse
import itertools
import json
import sys
from pathlib import Path
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5

from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from sentinelforge.api import create_app  # noqa: E402
from sentinelforge.config import ROOT, Settings  # noqa: E402
from sentinelforge.db import Base  # noqa: E402
from sentinelforge.public_demo import source_digest  # noqa: E402


def build_snapshot():
    fixed_time = "2026-11-15T09:10:00.000000+00:00"
    counter = itertools.count()
    token = "synthetic-snapshot-builder-unused-outside-memory"
    settings = Settings(
        _env_file=None,
        local_mode=False,
        public_demo=False,
        database_url="sqlite:///:memory:",
        identities=[{"name": "demo-analyst", "role": "admin", "token": token}],
    )
    defaults = []
    try:
        # Keep generated IDs and bookkeeping timestamps identical across rebuilds.
        for table in Base.metadata.tables.values():
            for column in table.columns:
                if column.name in {"created_at", "received_at"} and column.default:
                    defaults.append((column.default, column.default.arg))
                    column.default.arg = lambda _ctx: fixed_time
        with (
            patch(
                "sentinelforge.db.uuid4",
                side_effect=lambda: uuid5(NAMESPACE_URL, f"sentinelforge-demo-{next(counter)}"),
            ),
            patch("sentinelforge.api.now", return_value=fixed_time),
        ):
            app = create_app(settings)
            with TestClient(app) as client:
                headers = {"Authorization": "Bearer " + token}
                replay = client.post("/api/demo", headers=headers)
                replay.raise_for_status()
                assert replay.json()["accepted"] == 18 and replay.json()["alerts_created"] == 7
                cases = client.get("/api/cases", headers=headers).json()["items"]
                for case in cases:
                    note = client.post(
                        f"/api/cases/{case['id']}/notes",
                        headers=headers,
                        json={
                            "text": "Synthetic training investigation: correlate the source events, validate the command context and review the rule's false-positive considerations before escalating."
                        },
                    )
                    note.raise_for_status()
                    evidence = client.post(f"/api/cases/{case['id']}/evidence", headers=headers)
                    evidence.raise_for_status()
                with app.state.engine.connect() as connection:
                    tables = {
                        table.name: [dict(row) for row in connection.execute(select(table)).mappings()]
                        for table in Base.metadata.sorted_tables
                    }
            app.state.engine.dispose()
        return {"schema_version": 1, "synthetic": True, "source_sha256": source_digest(), "tables": tables}
    finally:
        for default, original in defaults:
            default.arg = original


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = json.dumps(build_snapshot(), indent=2, sort_keys=True) + "\n"
    path = ROOT / "data/public-demo.json"
    if args.check:
        if not path.exists() or path.read_text() != output:
            raise SystemExit("Public snapshot differs; rebuild it with scripts/build_public_demo.py")
        print("Public synthetic snapshot is reproducible")
    else:
        path.write_text(output)
        print("Built public synthetic snapshot: 18 events, 7 alerts, 2 cases")
