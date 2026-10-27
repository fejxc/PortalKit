"""本地使用统计（纯本地计数，不上传）：今天的认证/检查概况。

动机（PM 反馈）：用户无法回答"这软件帮我干了多少活、干得好不好"。
按天聚合：认证提交按结果码计数、耗时样本（保留最近 N 个）、检查次数。
所有方法吞掉磁盘 IO 异常——统计失败绝不能影响认证主链路。
"""

from __future__ import annotations

import json
import os
import threading
from datetime import date
from pathlib import Path

from portalkit.models import utc_now_iso

_OK_CODES = {"success", "already_authenticated"}


class LocalStats:
    def __init__(self, path: Path | None = None, max_durations: int = 10) -> None:
        self._path = path
        self._max_durations = max_durations
        self._lock = threading.Lock()
        self._data = self._load()

    # ------------------------------------------------------------- io

    def _load(self) -> dict:
        if self._path is None or not self._path.exists():
            return self._blank()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self._blank()
        if data.get("date") != date.today().isoformat():
            return self._blank()  # 按天聚合：跨天即重置
        return data

    @staticmethod
    def _blank() -> dict:
        return {"date": date.today().isoformat(), "checks": 0, "auth": {}, "durations_ms": []}

    def _save(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, ensure_ascii=False)
        except OSError:
            pass  # 统计持久化失败不影响主链路

    # ------------------------------------------------------------ record

    def record_check(self) -> None:
        with self._lock:
            if self._data.get("date") != date.today().isoformat():
                self._data = self._blank()
            self._data["checks"] = int(self._data.get("checks", 0)) + 1
            self._save()

    def record_auth(self, code: str, elapsed_ms: int) -> None:
        with self._lock:
            if self._data.get("date") != date.today().isoformat():
                self._data = self._blank()
            auth = self._data.setdefault("auth", {})
            auth[code] = int(auth.get(code, 0)) + 1
            durations: list[int] = self._data.setdefault("durations_ms", [])
            durations.append(int(elapsed_ms))
            del durations[:-self._max_durations]
            self._save()

    # ----------------------------------------------------------- summary

    def summary_today(self) -> str:
        """一行中文概况，供诊断窗口/CLI 展示。无数据时返回空串。"""
        with self._lock:
            data = self._data if self._data.get("date") == date.today().isoformat() else self._blank()
        auth = data.get("auth", {})
        total = sum(auth.values())
        if total == 0 and int(data.get("checks", 0)) == 0:
            return ""
        ok = sum(n for code, n in auth.items() if code in _OK_CODES)
        fail = total - ok
        durations = data.get("durations_ms", [])
        parts = [f"今日检查 {data.get('checks', 0)} 次"]
        if total:
            parts.append(f"自动认证 {total} 次（成功 {ok} · 失败 {fail}）")
            if durations:
                avg_s = sum(durations) / len(durations) / 1000
                parts.append(f"平均耗时 {avg_s:.1f}s")
        return " · ".join(parts)
