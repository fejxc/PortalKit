"""会话历史：记录、留存裁剪、按天汇总与明细读取。"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from portalkit.core.history import (
    KIND_AUTH_FAIL,
    KIND_AUTH_SUCCESS,
    KIND_KICK_SUSPECTED,
    KIND_SESSION_REFRESHED,
    HistoryEvent,
    SessionHistory,
)


def test_record_and_reload(tmp_path):
    path = tmp_path / "history.jsonl"
    history = SessionHistory(path)
    history.record(KIND_AUTH_SUCCESS, adapter="zstu", host="p.example")
    history.record(KIND_AUTH_FAIL, code="auth_quota", adapter="zstu")
    history.record(KIND_KICK_SUSPECTED)

    reloaded = SessionHistory(path)
    events = reloaded.events(days=7)
    assert [e.kind for e in events] == [KIND_AUTH_SUCCESS, KIND_AUTH_FAIL, KIND_KICK_SUSPECTED]
    assert events[1].code == "auth_quota"
    assert events[0].host == "p.example"


def test_unknown_kind_rejected(tmp_path):
    history = SessionHistory(tmp_path / "history.jsonl")
    try:
        history.record("something_else")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown kind must raise")


def test_corrupt_lines_tolerated(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(
        "not json\n"
        + json.dumps({"ts": "2026-11-16T00:00:00+00:00", "kind": "nope"}) + "\n"
        + json.dumps({"ts": "2026-11-16T00:00:01+00:00", "kind": "auth_success"}) + "\n",
        encoding="utf-8",
    )
    events = SessionHistory(path).events(days=1)
    assert len(events) == 1 and events[0].kind == KIND_AUTH_SUCCESS


def test_daily_summary_counts_fail_codes(tmp_path):
    path = tmp_path / "history.jsonl"
    history = SessionHistory(path)
    history.record(KIND_AUTH_SUCCESS)
    history.record(KIND_AUTH_SUCCESS)
    history.record(KIND_AUTH_FAIL, code="auth_quota")
    history.record(KIND_AUTH_FAIL, code="auth_quota")
    history.record(KIND_AUTH_FAIL, code="account_locked")
    history.record(KIND_KICK_SUSPECTED)
    history.record(KIND_SESSION_REFRESHED)

    summary = SessionHistory(path).daily_summary(days=7)
    assert len(summary) == 1
    day, counts = summary[0]
    assert day == datetime.now(timezone.utc).astimezone().date()
    assert counts["auth_success"] == 2
    assert counts["auth_fail:auth_quota"] == 2
    assert counts["auth_fail:account_locked"] == 1
    assert counts["kick_suspected"] == 1
    assert counts["session_refreshed"] == 1


def test_events_filters_by_days(tmp_path):
    path = tmp_path / "history.jsonl"
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=10)
    lines = []
    for ts, kind in (
        (old, KIND_AUTH_SUCCESS),          # 10 天前：超出 7 天窗口
        (now, KIND_KICK_SUSPECTED),        # 今天
    ):
        lines.append(json.dumps({"ts": ts.isoformat(), "kind": kind}))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    events = SessionHistory(path).events(days=7)
    assert [e.kind for e in events] == [KIND_KICK_SUSPECTED]


def test_prune_drops_old_events_on_write(tmp_path):
    path = tmp_path / "history.jsonl"
    old = (datetime.now(timezone.utc) - timedelta(days=95)).isoformat()
    path.write_text(json.dumps({"ts": old, "kind": KIND_AUTH_SUCCESS}) + "\n", encoding="utf-8")
    history = SessionHistory(path, retention_days=90)
    history.record(KIND_AUTH_FAIL, code="invalid_credentials")
    events = SessionHistory(path).events(days=365)
    assert [e.kind for e in events] == [KIND_AUTH_FAIL]


def test_prune_caps_event_count(tmp_path):
    path = tmp_path / "history.jsonl"
    history = SessionHistory(path, max_events=5)
    for _ in range(8):
        history.record(KIND_AUTH_SUCCESS)
    assert len(SessionHistory(path).tail(100)) == 5


def test_none_path_is_silent(tmp_path):
    history = SessionHistory(None)
    history.record(KIND_AUTH_SUCCESS)  # 不抛异常
    assert history.events(days=7) == []


def test_bad_timestamp_events_kept(tmp_path):
    """坏时间戳按"今天"归类（读侧防御），不丢弃数据。"""
    path = tmp_path / "history.jsonl"
    path.write_text(json.dumps({"ts": "garbage", "kind": "kick_suspected"}) + "\n",
                    encoding="utf-8")
    events = SessionHistory(path).events(days=1)
    assert len(events) == 1
    assert isinstance(events[0], HistoryEvent)
