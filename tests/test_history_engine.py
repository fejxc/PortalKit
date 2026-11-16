"""引擎 → 会话历史落盘：四类事件的记录时点与字段。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from test_engine import (
    FakeAdapter,
    FakeMonitor,
    MemoryCredentials,
    _engine,
    _internet,
    _snapshot,
)
from test_kick_detection import _seed_last_success
from portalkit.adapters.base import AuthCode, AuthResult, Credentials
from portalkit.models import InternetState, Phase


def _kinds(engine) -> list[tuple[str, str]]:
    return [(e.kind, e.code) for e in engine.history.events(days=1)]


def test_auth_success_recorded(monkeypatch, tmp_path):
    """认证成功（物理验证通过）→ auth_success。already=True 不记。"""
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
        creds=Credentials("u", "p"),
    )
    state = engine.authenticate()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    assert _kinds(engine) == [("auth_success", "")]


def test_auth_failure_recorded_with_code(monkeypatch, tmp_path):
    adapter = FakeAdapter(auth_results=[
        AuthResult(AuthCode.AUTH_QUOTA, "error.auth_quota", recovery_hint="超限"),
    ])
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED), _internet(InternetState.BLOCKED)],
        creds=Credentials("u", "p"),
    )
    state = engine.authenticate()
    assert state.phase == Phase.WAITING_USER
    assert _kinds(engine) == [("auth_fail", "auth_quota")]


def test_kick_suspected_recorded(monkeypatch, tmp_path):
    _seed_last_success(tmp_path, seconds_ago=1500)
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED)],
        creds=Credentials("u", "p"),
    )
    state = engine.auto_run()
    assert state.phase == Phase.WAITING_USER
    assert _kinds(engine) == [("kick_suspected", "")]


def test_session_refreshed_recorded(monkeypatch, tmp_path):
    """refresh 流程清理成功 → session_refreshed（含 adapter/host）。"""
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    adapter.refresh_session = lambda ctx: AuthResult(AuthCode.SUCCESS, "ok",
                                                     evidence=("cleaned",))
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
        creds=Credentials("u", "p"),
    )
    state = engine.refresh_session()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    events = engine.history.events(days=1)
    assert [(e.kind, e.adapter, e.host) for e in events] == [
        ("session_refreshed", "fake", "portal.example"),
        ("auth_success", "fake", "portal.example"),
    ]


def test_already_online_not_recorded(monkeypatch, tmp_path):
    """会话本就有效（already=True）：无认证发生，不产生 auth_success。"""
    from portalkit.adapters.base import DetectionResult

    adapter = FakeAdapter(detection=DetectionResult(
        matched=True, adapter_id="fake",
        portal_scheme="http", portal_host="portal.example", portal_port=80,
        fingerprint="fp1", already_authenticated=True,
    ))
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
        creds=Credentials("u", "p"),
    )
    state = engine.check()
    assert state.phase == Phase.ONLINE_NO_AUTH
    assert engine.history.events(days=1) == []


def test_history_survives_engine_restart(monkeypatch, tmp_path):
    """历史落盘在 state_dir/history.jsonl，跨引擎实例可读。"""
    adapter = FakeAdapter(auth_results=[AuthResult(
        AuthCode.INVALID_CREDENTIALS, "error.invalid_creds")])
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED), _internet(InternetState.BLOCKED)],
        creds=Credentials("u", "p"),
    )
    engine.authenticate()
    # 模拟重启：新引擎默认构造 SessionHistory(state_dir/history.jsonl)
    from portalkit.core.engine import Engine
    from portalkit.core.history import SessionHistory

    rebuilt = Engine(
        monitor=FakeMonitor(_snapshot()),
        registry=engine._registry,
        trust=engine._trust,
        credentials=MemoryCredentials(),
        state_dir=engine._state_dir,
    )
    events = rebuilt.history.events(days=1)
    assert [(e.kind, e.code) for e in events] == [("auth_fail", "invalid_credentials")]
    assert (tmp_path / "state" / "history.jsonl").exists()
