"""Generate local secrets without printing them or replacing existing configuration."""

import json
import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
identities = [
    {"name": name, "role": role, "token": secrets.token_urlsafe(36)}
    for name, role in [
        ("lead", "admin"),
        ("analyst", "analyst"),
        ("reviewer", "viewer"),
        ("collector", "ingest"),
    ]
]
content = (
    "SF_IDENTITIES='" + json.dumps(identities) + "'\nPOSTGRES_PASSWORD=" + secrets.token_urlsafe(36) + "\n"
)
try:
    descriptor = os.open(root / ".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    print("Existing .env preserved. Tokens are available there; do not commit this file.")
else:
    with os.fdopen(descriptor, "w") as file:
        file.write(content)
    print(
        "Created .env with unique tokens for lead, analyst, reviewer and collector. Open locally to sign in."
    )
