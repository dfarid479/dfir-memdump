"""
BasePlugin abstract class.

Each concrete plugin wraps one Volatility3 plugin invocation:
  1. Invoke vol3 via subprocess with --renderer json
  2. Parse the JSON rows into typed Pydantic models
  3. Return the list of models to the runner
"""

from __future__ import annotations

import json
import logging
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TypeVar, Generic, Type

from pydantic import BaseModel

from dfir_memdump.config import settings
from dfir_memdump.exceptions import PluginError, Vol3NotFoundError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class BasePlugin(ABC, Generic[T]):
    """Abstract base for all Volatility3 plugin wrappers."""

    plugin_name: str        # e.g. "windows.pslist.PsList"
    output_model: Type[T]   # The Pydantic model rows are parsed into

    def __init__(self, image_path: Path | None = None, profile: str | None = None):
        """Store image_path and profile so run() can be called with no arguments."""
        self._image_path = Path(image_path) if image_path else None
        self._profile    = profile

    def run(self, image_path: Path | None = None, profile: str | None = None) -> list[T]:
        """Invoke vol3, parse output, return typed model list.

        Args can be supplied at call time or at __init__ time — call-time takes precedence.
        """
        resolved_path    = image_path or self._image_path
        resolved_profile = profile    or self._profile
        if resolved_path is None:
            raise ValueError(f"{self.__class__.__name__}.run() requires an image_path")
        raw = self._invoke_vol3(resolved_path, resolved_profile)
        try:
            return self._parse(raw)
        except Exception as exc:
            raise PluginError(self.plugin_name, f"Parse error: {exc}") from exc

    @abstractmethod
    def _parse(self, raw_output: str) -> list[T]:
        """Parse the vol3 JSON output string into model instances."""

    def _invoke_vol3(self, image_path: Path, profile: str | None = None) -> str:  # noqa: E501
        """Run vol3 as a subprocess and return stdout as a string."""
        cmd = [settings.vol3_path, "--renderer", "json", "-f", str(image_path)]
        if profile:
            cmd += ["--profile", profile]
        cmd.append(self.plugin_name)

        logger.debug("Running: %s", " ".join(cmd))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=settings.plugin_timeout_seconds,
            )
        except FileNotFoundError:
            raise Vol3NotFoundError(
                f"vol3 binary not found at '{settings.vol3_path}'. "
                "Install Volatility3 or set VOL3_PATH in .env"
            )
        except subprocess.TimeoutExpired:
            raise PluginError(self.plugin_name, f"Timed out after {settings.plugin_timeout_seconds}s")

        if result.returncode != 0:
            raise PluginError(
                self.plugin_name,
                f"Non-zero exit {result.returncode}: {result.stderr[:500]}"
            )

        return result.stdout

    @staticmethod
    def _parse_json_rows(raw: str) -> list[dict]:
        """
        Parse vol3 JSON renderer output.

        Vol3's --renderer json outputs:
          {"columns": [...], "rows": [[v1, v2, ...], ...]}
        We zip columns and rows into a list of dicts.
        """
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PluginError("json_parse", f"Invalid JSON from vol3: {exc}") from exc

        if isinstance(data, list):
            # Some versions output a list of row dicts directly
            return data

        columns = data.get("columns", [])
        rows    = data.get("rows", [])

        if not columns:
            return []

        return [dict(zip(columns, row)) for row in rows]
