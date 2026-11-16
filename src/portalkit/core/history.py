"""会话历史：精选会话事件的本地留存（回答"昨晚到底掉没掉线"）。

与 events.jsonl（全量调试日志，大小轮转，高频 state 事件约只能回溯数天）
互补：这里只记用户回头要查的**会话级**事件——认证成功 / 认证失败（含
结果码）/ 疑似互踢 / 会话刷新——每天通常 <20 条，按 90 天 + 条数上限
双限裁剪，体量恒定（约几百 KB 封顶）。

字段纪律：只存 kind/code/adapter/host 与时间戳，**无自由文本**——
门户原文可能携带敏感值，历史文件不做二次脱敏的前提是从源头不收。

写入方：Engine（引擎锁内，单线程）。读取方：诊断窗口 / CLI（只读，
直接实例化同一路径即可，IO 异常全部吞掉——历史功能绝不能影响认证）。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from portalkit.models import utc_now_iso

# 事件种类（固定枚举；新增种类需同步诊断文案 _HISTORY_KIND_CN）
KIND_AUTH_SUCCESS = "auth_success"
KIND_AUTH_FAIL = "auth_fail"
KIND_KICK_SUSPECTED = "kick_suspected"
KIND_SESSION_REFRESHED = "session_refreshed"
_KINDS = {KIND_AUTH_SUCCESS, KIND_AUTH_FAIL, KIND_KICK_SUSPECTED, KIND_SESSION_REFRESHED}

RETENTION_DAYS = 90
MAX_EVENTS = 5000


@dataclass(frozen=True)
class HistoryEvent:
    ts: str  # UTC ISO
    kind: str
    code: str = ""  # auth_fail 的 AuthCode；其余为空
    adapter: str = ""
    host: str = ""

    def to_dict(self) -> dict:
        return {"ts": self.ts, "kind": self.kind, "code": self.code,
                "adapter": self.adapter, "host": self.host}


def _local_date(ts: str) -> date:
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return date.today()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().date()


class SessionHistory:
    """追加式 JSONL（history.jsonl）。record 线程安全；读方法只读。"""

    def __init__(self, path: Path | None, *,
                 retention_days: int = RETENTION_DAYS,
                 max_events: int = MAX_EVENTS) -> None:
        self._path = path
        self._retention_days = retention_days
        self._max_events = max_events
        self._lock = threading.Lock()

    # ------------------------------------------------------------- write

    def record(self, kind: str, *, code: str = "", adapter: str = "", host: str = "") -> None:
        if kind not in _KINDS:
            raise ValueError(f"unknown history kind: {kind}")
        event = HistoryEvent(utc_now_iso(), kind, code=code, adapter=adapter, host=host)
        with self._lock:
            self._append(event)

    def _append(self, event: HistoryEvent) -> None:
        if self._path is None:
            return
        try:
            events = self._load()
            events.append(event)
            events = self._prune(events)
            self._path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                for item in events:
                    fh.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            pass  # 历史写入失败绝不影响认证主链路

    def _prune(self, events: list[HistoryEvent]) -> list[HistoryEvent]:
        if not events:
            return events
        cutoff = datetime.now(timezone.utc) - timedelta(days=self._retention_days)
        kept = [e for e in events if _parse_ts(e.ts) >= cutoff]
        if len(kept) > self._max_events:
            kept = kept[-self._max_events:]
        return kept

    # -------------------------------------------------------------- read

    def _load(self) -> list[HistoryEvent]:
        if self._path is None or not self._path.exists():
            return []
        events: list[HistoryEvent] = []
        try:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        for line in lines:
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("kind") in _KINDS:
                events.append(HistoryEvent(
                    ts=str(item.get("ts", "")), kind=str(item["kind"]),
                    code=str(item.get("code", "") or ""),
                    adapter=str(item.get("adapter", "") or ""),
                    host=str(item.get("host", "") or ""),
                ))
        return events

    def events(self, days: int = 7) -> list[HistoryEvent]:
        """最近 N 天事件（含今天，时间正序）。"""
        cutoff = date.today() - timedelta(days=max(0, days) - 1)
        return [e for e in self._load() if _local_date(e.ts) >= cutoff]

    def tail(self, n: int = 40) -> list[HistoryEvent]:
        return self._load()[-max(1, n):]

    def daily_summary(self, days: int = 7) -> list[tuple[date, dict[str, int]]]:
        """按天聚合计数：[(day, {"auth_success": n, "auth_fail": n, ...}), ...]。

        失败细分码并入 auth_fail 键名（"auth_fail:account_locked"），展示侧
        自行决定折叠粒度。今天在最上，无数据的天不列（避免 90 行空行）。
        """
        cutoff = date.today() - timedelta(days=max(1, days) - 1)
        by_day: dict[date, dict[str, int]] = {}
        for event in self._load():
            day = _local_date(event.ts)
            if day < cutoff:
                continue
            key = event.kind if event.kind != KIND_AUTH_FAIL or not event.code \
                else f"{event.kind}:{event.code}"
            bucket = by_day.setdefault(day, {})
            bucket[key] = bucket.get(key, 0) + 1
        return sorted(by_day.items(), key=lambda kv: kv[0], reverse=True)


def _parse_ts(ts: str) -> datetime:
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return datetime.now(timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
