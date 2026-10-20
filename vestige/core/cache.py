"""Small on-disk response cache with TTL.

Only successful, explicitly cacheable GET responses are stored. Keys are derived from the
*redacted* URL so API keys never influence (or appear in) cache entries.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from vestige.core.redact import redact_url


def default_cache_dir() -> Path:
    env = os.environ.get("VESTIGE_CACHE_DIR")
    if env:
        return Path(env)
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "vestige" / "cache"
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "vestige"


class ResponseCache:
    def __init__(self, directory: Path | None = None, *, enabled: bool = True, clock=time.time):
        self.dir = Path(directory) if directory else default_cache_dir()
        self.enabled = enabled
        self._clock = clock

    @staticmethod
    def make_key(url: str, params: dict[str, Any] | None = None) -> str:
        from urllib.parse import urlencode
        full = url + (("&" if "?" in url else "?") + urlencode(sorted((params or {}).items())) if params else "")
        return hashlib.sha256(redact_url(full).encode()).hexdigest()

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def get(self, key: str, ttl: float) -> dict | None:
        if not self.enabled:
            return None
        p = self._path(key)
        try:
            entry = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(entry, dict) or self._clock() - float(entry.get("ts", 0)) > ttl:
            return None
        return entry

    def put(self, key: str, status: int, content_type: str, text: str) -> None:
        if not self.enabled:
            return
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            tmp = self._path(key).with_suffix(".tmp")
            tmp.write_text(json.dumps({"ts": self._clock(), "status": status,
                                       "content_type": content_type, "text": text}), encoding="utf-8")
            os.replace(tmp, self._path(key))
        except OSError:
            pass  # cache is best-effort

    def clear(self) -> int:
        n = 0
        if self.dir.is_dir():
            for f in self.dir.glob("*.json"):
                try:
                    f.unlink()
                    n += 1
                except OSError:
                    pass
        return n
