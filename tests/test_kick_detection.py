"""互踢识别:auto 路径的节流与"疑似抢占"转人工;手动认证可夺取。"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from test_engine import (
    FakeAdapter,
    FakeMonitor,
    MemoryCredentials,
    _engine,
    _internet,
    _snapshot,
)
from portalkit.adapters.base import AuthCode, AuthResult, Credentials
from portalkit.models import InternetState, Phase


def _seed_last_success(tmp_path, seconds_ago: float) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    ts = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    (state_dir / "state.json").write_text(
        json.dumps({"last_auth_success_at": ts}), encoding="utf-8"
    )


def test_recent_success_throttles_auto(monkeypatch, tmp_path):
    """10 分钟内成功过:auto_run 不重提交(保护刚建立的会话)。"""
    _seed_last_success(tmp_path, seconds_ago=120)
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)],
                     creds=Credentials("u", "p"))
    state = engine.auto_run()
    assert state.phase == Phase.MATCHING  # 停在识别态,未提交
    assert adapter.auth_calls == 0


def test_kick_suspect_waits_user_instead_of_refighting(monkeypatch, tmp_path):
    """10–45 分钟内成功过又掉线:疑似互踢 → WAITING_USER 明确提示,不自动夺取。"""
    _seed_last_success(tmp_path, seconds_ago=1500)
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)],
                     creds=Credentials("u", "p"))
    state = engine.auto_run()
    assert state.phase == Phase.WAITING_USER
    assert "抢占" in state.detail
    assert adapter.auth_calls == 0


def test_kick_window_expired_normal_auto_auth(monkeypatch, tmp_path):
    """超过 45 分钟:正常自动认证(自然过期重登不受影响)。"""
    _seed_last_success(tmp_path, seconds_ago=7200)
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED),   # auto_run: 前置探测
         _internet(InternetState.BLOCKED),   # authenticate: 探测
         _internet(InternetState.REACHABLE)],  # 认证后物理验证
        creds=Credentials("u", "p"),
    )
    state = engine.auto_run()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    assert adapter.auth_calls == 1


def test_manual_authenticate_overrides_kick_window(monkeypatch, tmp_path):
    """用户点「立即认证」:不受互踢窗口限制(主动夺取会话)。"""
    _seed_last_success(tmp_path, seconds_ago=1500)
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(
        monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
        [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
        creds=Credentials("u", "p"),
    )
    state = engine.authenticate()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    assert adapter.auth_calls == 1
