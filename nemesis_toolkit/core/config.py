"""Application configuration.

Settings are loaded, in increasing order of priority, from:

1. ``~/.toolconfig.yaml`` (or ``$NEMESIS_CONFIG_FILE``)
2. a local ``.env`` file
3. ``NEMESIS_*`` environment variables
4. explicit constructor arguments

API keys are optional. Modules that need a missing key report a clear
configuration finding instead of crashing.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


def _default_data_dir() -> Path:
    """Return a per-user data directory without requiring an extra dependency."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "nemesis"


def _config_file() -> Path:
    configured = os.environ.get("NEMESIS_CONFIG_FILE")
    return Path(configured).expanduser() if configured else Path.home() / ".toolconfig.yaml"


class Settings(BaseSettings):
    """Runtime settings for every module."""

    model_config = SettingsConfigDict(
        env_prefix="NEMESIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Explicit configuration flag for repeat use against approved assets.
    # The CLI still prints the authorization banner and --confirm-authorized
    # always works. Only enable this in a config file you control.
    authorized_by_default: bool = False
    respect_robots: bool = False
    requests_per_second: float = Field(default=20.0, gt=0)
    timeout: float = Field(default=10.0, gt=0)
    max_retries: int = Field(default=2, ge=0, le=8)
    concurrency: int = Field(default=50, ge=1, le=500)

    data_dir: Path = Field(default_factory=_default_data_dir)
    db_path: Path | None = None
    audit_log_path: Path | None = None
    run_log_path: Path | None = None

    # Optional API credentials.
    securitytrails_api_key: str | None = None
    virustotal_api_key: str | None = None
    shodan_api_key: str | None = None
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    hibp_api_key: str | None = None
    serpapi_key: str | None = None
    google_cse_api_key: str | None = None
    google_cse_cx: str | None = None
    ipinfo_token: str | None = None

    # Optional local MaxMind databases. Download these yourself from MaxMind.
    geoip_db_path: Path | None = None
    geoip_asn_db_path: Path | None = None

    # Polite crawling / scanning defaults.
    crawl_max_pages: int = Field(default=30, ge=1, le=1000)
    crawl_depth: int = Field(default=2, ge=0, le=10)
    user_agents: list[str] = Field(
        default_factory=lambda: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        ]
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        config_path = _config_file()
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings, dotenv_settings]
        if config_path.exists():
            sources.append(YamlConfigSettingsSource(settings_cls, yaml_file=config_path))
        sources.append(file_secret_settings)
        return tuple(sources)

    def resolved_paths(self) -> dict[str, Path]:
        """Resolve default paths and create their parent directories."""
        data_dir = Path(self.data_dir).expanduser().resolve()
        values = {
            "data_dir": data_dir,
            "db_path": Path(self.db_path).expanduser().resolve()
            if self.db_path
            else data_dir / "nemesis.db",
            "audit_log_path": Path(self.audit_log_path).expanduser().resolve()
            if self.audit_log_path
            else data_dir / "audit.jsonl",
            "run_log_path": Path(self.run_log_path).expanduser().resolve()
            if self.run_log_path
            else data_dir / "runs.log",
            "config_path": _config_file().expanduser(),
        }
        data_dir.mkdir(parents=True, exist_ok=True)
        for key in ("db_path", "audit_log_path", "run_log_path"):
            values[key].parent.mkdir(parents=True, exist_ok=True)
        return values

    @property
    def database(self) -> Path:
        return self.resolved_paths()["db_path"]

    @property
    def audit_log(self) -> Path:
        return self.resolved_paths()["audit_log_path"]

    @property
    def run_log(self) -> Path:
        return self.resolved_paths()["run_log_path"]

    def api_key(self, name: str) -> str | None:
        """Return an API key by friendly name, treating blanks as missing."""
        value = getattr(self, name, None)
        if isinstance(value, str):
            value = value.strip()
        return value or None

    def public_dict(self) -> dict[str, Any]:
        """Configuration summary with credentials redacted."""
        data = self.model_dump(mode="json")
        for key in list(data):
            if key.endswith(("_api_key", "_api_secret", "_token", "_key")):
                data[key] = "***configured***" if data[key] else None
        if data.get("user_agents"):
            data["user_agents"] = [f"{len(data['user_agents'])} configured user agents"]
        return data


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance."""
    return Settings()


def reload_settings() -> Settings:
    """Clear and reload cached settings (useful for tests and config edits)."""
    get_settings.cache_clear()
    return get_settings()
