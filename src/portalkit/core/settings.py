"""用户设置（UI_UX_SPEC §8：检查频率限制可选值、开关默认保守）。"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, replace
from pathlib import Path

ALLOWED_INTERVALS_S = (30, 60, 120)


@dataclass(frozen=True)
class Settings:
    auto_auth: bool = True          # 在已信任网络自动认证（首次信任时显式同意）
    notify_on_error: bool = True    # 异常/需要操作系统通知
    check_interval_s: int = 120     # 低频兜底检查；仅允许 30/60/120（防过短轮询）
    launch_at_login: bool = False


class SettingsStore:
    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (
            Path.home() / "Library" / "Application Support" / "PortalKit" / "settings.json"
        )
        self._lock = threading.Lock()
        self._settings = self._load()

    def _load(self) -> Settings:
        if not self._path.exists():
            return Settings()
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            interval = int(raw.get("check_interval_s", 120))
            if interval not in ALLOWED_INTERVALS_S:
                interval = 120
            return Settings(
                auto_auth=bool(raw.get("auto_auth", True)),
                notify_on_error=bool(raw.get("notify_on_error", True)),
                check_interval_s=interval,
                launch_at_login=bool(raw.get("launch_at_login", False)),
            )
        except (OSError, ValueError, TypeError):
            return Settings()

    def get(self) -> Settings:
        with self._lock:
            return self._settings

    def update(self, **changes) -> Settings:
        with self._lock:
            if "check_interval_s" in changes and changes["check_interval_s"] not in ALLOWED_INTERVALS_S:
                raise ValueError(f"check_interval_s 仅允许 {ALLOWED_INTERVALS_S}")
            self._settings = replace(self._settings, **changes)
            self._save()
            return self._settings

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(asdict(self._settings), fh, ensure_ascii=False, indent=2)
