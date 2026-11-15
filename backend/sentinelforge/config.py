from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Identity(BaseModel):
    name: str = Field(pattern=r"^[a-zA-Z0-9_.@-]{1,80}$")
    role: Literal["viewer", "analyst", "admin", "ingest"]
    token: SecretStr = Field(min_length=32)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SF_", env_file=".env", extra="ignore")
    local_mode: bool = False
    database_url: str = "sqlite:///./sentinelforge.db"
    identities: list[Identity] = Field(default_factory=list)
    rules_path: Path = ROOT / "rules"
    attack_path: Path = ROOT / "data" / "attack.json"
    frontend_path: Path = ROOT / "frontend" / "dist"
    rate_limit: int = Field(default=120, ge=1)
    max_body_bytes: int = Field(default=1_048_576, ge=1024)

    @model_validator(mode="after")
    def check_identities(self):
        if not self.identities and not self.local_mode:
            raise ValueError("SF_IDENTITIES must contain at least one identity; run scripts/setup.py")
        if any(i.name == "__local__" for i in self.identities):
            raise ValueError("__local__ is a reserved identity name")
        for attr in ("name", "token"):
            values = [
                getattr(i, attr).get_secret_value() if attr == "token" else i.name for i in self.identities
            ]
            if len(values) != len(set(values)):
                raise ValueError(f"Duplicate identity {attr}")
        return self
