"""Configuration and tunables for dfir-memdump."""

import os
from pathlib import Path
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


DATA_DIR = Path(__file__).parent.parent / "data"


class Settings(BaseSettings):
    # Volatility3 binary location
    vol3_path: str = Field(
        default="vol",
        description="Path to vol3 binary or 'vol' if on PATH",
    )

    # VirusTotal (optional — VT lookups disabled if absent)
    vt_api_key: SecretStr = Field(
        default=SecretStr(""),
        alias="VT_API_KEY",
        description="VirusTotal API key. Free tier: 4 req/min",
    )
    vt_rate_limit_per_minute: int = Field(default=4, description="VT API calls per minute")

    # YARA
    yara_rules_dir: Path = Field(
        default=DATA_DIR / "yara",
        description="Directory containing .yar YARA rule files",
    )
    yara_compiled_path: Path = Field(
        default=DATA_DIR / "yara" / "compiled.yarac",
        description="Pre-compiled YARA ruleset (faster startup)",
    )

    # Threat intel feeds
    feodo_feed_url: str = Field(
        default="https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json",
    )
    feodo_cache_path: Path = Field(default=DATA_DIR / "feodo_cache.json")
    feodo_cache_ttl_hours: int = Field(default=6)
    lolbas_path: Path = Field(default=DATA_DIR / "lolbas.json")

    # Analysis tunables
    entropy_threshold: float = Field(
        default=4.5,
        description="Flag cmdline tokens with Shannon entropy above this value",
    )
    max_processes_to_hash: int = Field(
        default=50,
        description="Max number of process images to hash for VT lookups",
    )
    plugin_timeout_seconds: int = Field(
        default=300,
        description="Timeout for each Volatility3 plugin invocation",
    )

    # Output
    report_output_dir: Path = Field(default=Path("./reports"))

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"
        populate_by_name = True

    def has_vt(self) -> bool:
        return bool(self.vt_api_key.get_secret_value())


settings = Settings()
