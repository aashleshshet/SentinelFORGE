"""Vercel entrypoint. The regular authenticated/local launchers are unchanged."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))
from sentinelforge.public_demo import create_public_app  # noqa: E402

app = create_public_app()
