"""Token-free local workspace; binds loopback and ignores forwarded client addresses."""

import argparse
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "backend"))
import uvicorn  # noqa: E402
from sentinelforge.api import create_app  # noqa: E402
from sentinelforge.config import Settings  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8000)
args = parser.parse_args()
if not (root / "frontend/dist/index.html").exists():
    raise SystemExit("Build the dashboard first: pnpm --dir frontend run build")
settings = Settings(local_mode=True)
print(f"SentinelForge local workspace: http://127.0.0.1:{args.port} (no token needed)")
uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port, proxy_headers=False, access_log=False)
