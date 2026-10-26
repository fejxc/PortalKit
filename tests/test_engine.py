"""引擎调度：在线判定、信任门槛、重试上界、generation 取消、物理验证红线。

全部使用 FakeMonitor / FakeAdapter / 内存凭据，无真实网络。
"""

from __future__ import annotations

import pytest

import portalkit.core.engine as engine_module
from portalkit.adapters.base import (
    AdapterContext,
    AuthResult,
    Credentials,
    DetectionResult,
    ProtocolVerifyResult,
)
from portalkit.adapters.registry import AdapterRegistry
from portalkit.core.engine import Engine
from portalkit.core.retry import RetryPolicy
from portalkit.core.trust import TrustRecord, TrustRegistry
from portalkit.diagnostics.logging import RedactedLogger
from portalkit.models import (
    AuthCode,
    ErrorCode,
    InternetState,
    NetworkSnapshot,
    Phase,
    PortalState,
    utc_now_iso,
)
from portalkit.network.monitor import GenerationStale
from portalkit.network.probes import InternetCheckResult


class FakeMonitor:
    def __init__(self, snapshot: NetworkSnapshot, generation: int = 1) -> None:
        self._snapshot = snapshot
        self._generation = generation
        self.gen_calls = 0
        self.stale_on_call: int | None = None

    def current_snapshot(self) -> NetworkSnapshot:
        return self._snapshot

    def current_generation(self) -> int:
        return self._generation

    def check_generation(self, gen: int) -> None:
        self.gen_calls += 1
        if self.stale_on_call is not None and self.gen_calls >= self.stale_on_call:
            raise GenerationStale(gen, self._generation + 1)

    def has_changed_since(self, gen: int) -> bool:
        return gen != self._generation


class FakeAdapter:
    id = "fake"
    name = "Fake Portal"
    api_version = 1

    def __init__(self, detection=None, auth_results=None, verify=None) -> None:
        self.detect_calls = 0
        self.auth_calls = 0
        self.verify_calls = 0
        self.detection = detection or DetectionResult(
            matched=True, adapter_id="fake",
            portal_scheme="http", portal_host="portal.example", portal_port=80,
            fingerprint="fp1",
        )
        self.auth_results = list(auth_results or [])
        self.verify = verify or ProtocolVerifyResult(True, ("session ok",))

    def detect(self, ctx: AdapterContext):
        self.detect_calls += 1
        return self.detection

    def authenticate(self, ctx: AdapterContext, creds: Credentials):
        self.auth_calls += 1
        ctx.check_generation()
        if self.auth_results:
            return self.auth_results.pop(0)
        return AuthResult(AuthCode.SUCCESS, "ok")

    def verify_protocol(self, ctx: AdapterContext):
        self.verify_calls += 1
        return self.verify


class MemoryCredentials:
    def __init__(self, store=None) -> None:
        self.store = dict(store or {})

    def get(self, adapter_id: str, host: str):
        return self.store.get((adapter_id, host))

    def usernames(self, adapter_id: str, host: str):
        creds = self.store.get((adapter_id, host))
        return [creds.username] if creds else []


def _snapshot(ready=True) -> NetworkSnapshot:
    if ready:
        return NetworkSnapshot(interface="en5", ipv4="10.9.9.9", gateway="10.9.9.1", dns="10.9.9.1")
    return NetworkSnapshot(interface=None, ipv4=None, gateway=None, dns=None)


def _internet(state: InternetState) -> InternetCheckResult:
    return InternetCheckResult(state=state, passed=3 if state == InternetState.REACHABLE else 0,
                               total=4, evidence=(f"state={state.value}",))


def _record(fingerprint="fp1") -> TrustRecord:
    return TrustRecord(
        adapter_id="fake", portal_host="portal.example", portal_port=80,
        scheme="http", allowed_hosts=("portal.example",),
        fingerprint=fingerprint, created_at=utc_now_iso(),
    )


def _engine(monkeypatch, tmp_path, monitor, adapter, internet_states, creds=None, retry=None):
    results = list(internet_states)
    monkeypatch.setattr(
        engine_module, "check_internet",
        lambda iface, dns, timeout=5.0: results.pop(0),
    )
    trust = TrustRegistry(tmp_path / "trust")
    trust.add(_record())
    store = {}
    if creds:
        store[("fake", "portal.example")] = creds
    return Engine(
        monitor=monitor,
        registry=AdapterRegistry([adapter]),
        trust=trust,
        credentials=MemoryCredentials(store),
        logger=RedactedLogger(),
        retry_policy=retry or RetryPolicy(max_attempts=3, delays_s=(0.0, 0.0, 0.0)),
        state_dir=tmp_path / "state",
    )


def test_offline_reports_no_interface(monkeypatch, tmp_path):
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot(ready=False)),
                     FakeAdapter(), [])
    state = engine.check()
    assert state.link.value == "DISCONNECTED"
    assert state.error_code == ErrorCode.NO_PHYSICAL_INTERFACE


def test_reachable_internet_skips_portal_entirely(monkeypatch, tmp_path):
    """A03：已验证在线 → 不识别、不认证，语义为"无需认证"。"""
    adapter = FakeAdapter()
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.REACHABLE)])
    state = engine.check()
    assert state.phase == Phase.ONLINE_NO_AUTH
    assert state.portal == PortalState.NOT_REQUIRED
    assert state.internet == InternetState.REACHABLE
    assert adapter.detect_calls == 0
    assert adapter.auth_calls == 0


def test_unmatched_portal_reports_unknown(monkeypatch, tmp_path):
    adapter = FakeAdapter(detection=DetectionResult(matched=False, adapter_id="fake"))
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)])
    state = engine.check()
    assert state.phase == Phase.ERROR
    assert state.error_code == ErrorCode.NO_ADAPTER_MATCHED
    assert state.portal == PortalState.UNKNOWN


def test_untrusted_portal_never_gets_credentials(monkeypatch, tmp_path):
    """A07：匹配但未信任 → 0 次凭据提交。"""
    adapter = FakeAdapter()
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)])
    # 未添加信任记录：重建无记录的注册表
    engine._trust = TrustRegistry(tmp_path / "empty")
    state = engine.authenticate()
    assert state.phase == Phase.TRUST_REQUIRED
    assert state.error_code == ErrorCode.TRUST_REQUIRED
    assert adapter.auth_calls == 0


def test_portal_fingerprint_change_pauses(monkeypatch, tmp_path):
    """A06：门户特征变化 → 暂停自动提交，转用户处理。"""
    adapter = FakeAdapter(detection=DetectionResult(
        matched=True, adapter_id="fake", portal_scheme="http",
        portal_host="portal.example", portal_port=80, fingerprint="fp-CHANGED",
    ))
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.WAITING_USER
    assert state.error_code == ErrorCode.PORTAL_CHANGED
    assert adapter.auth_calls == 0


def test_check_does_not_authenticate(monkeypatch, tmp_path):
    adapter = FakeAdapter()
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)])
    state = engine.check()
    assert state.phase == Phase.MATCHING
    assert state.portal == PortalState.DETECTED
    assert adapter.auth_calls == 0


def test_authenticate_without_credentials_waits_user(monkeypatch, tmp_path):
    adapter = FakeAdapter()
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)], creds=None)
    state = engine.authenticate()
    assert state.phase == Phase.WAITING_USER
    assert state.error_code == ErrorCode.NEED_CREDENTIALS
    assert adapter.auth_calls == 0


def test_success_requires_physical_verification(monkeypatch, tmp_path):
    """A10：认证成功但物理验证未通过 → 不显示已联网。"""
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED), _internet(InternetState.BLOCKED)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.DEGRADED
    assert state.error_code == ErrorCode.VERIFY_FAILED
    assert state.portal == PortalState.AUTHENTICATED
    assert state.internet == InternetState.BLOCKED


def test_success_with_verified_internet(monkeypatch, tmp_path):
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    assert state.internet == InternetState.REACHABLE
    assert adapter.verify_calls == 1
    assert (tmp_path / "state" / "state.json").exists()


def test_already_authenticated_still_verifies(monkeypatch, tmp_path):
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.ALREADY_AUTHENTICATED, "ok")])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    assert adapter.auth_calls == 1


def test_invalid_credentials_no_retry(monkeypatch, tmp_path):
    """A08：明确密码错误 → 转用户处理，不做无限自动重试。"""
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.INVALID_CREDENTIALS, "bad")])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.WAITING_USER
    assert state.error_code == ErrorCode.INVALID_CREDENTIALS
    assert adapter.auth_calls == 1


def test_network_error_retries_bounded_then_succeeds(monkeypatch, tmp_path):
    """A09：临时错误有界退避；三次内成功。"""
    adapter = FakeAdapter(auth_results=[
        AuthResult(AuthCode.NETWORK_ERROR, "net", retryable=True),
        AuthResult(AuthCode.NETWORK_ERROR, "net", retryable=True),
        AuthResult(AuthCode.SUCCESS, "ok"),
    ])
    engine = _engine(monkeypatch, tmp_path, FakeMonitor(_snapshot()), adapter,
                     [_internet(InternetState.BLOCKED), _internet(InternetState.REACHABLE)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.ONLINE_AUTHENTICATED
    assert adapter.auth_calls == 3


def test_generation_change_cancels_running_task(monkeypatch, tmp_path):
    """A04/E：网络换代 → 旧任务取消，结果不写入新状态。"""
    adapter = FakeAdapter(auth_results=[AuthResult(AuthCode.SUCCESS, "ok")])
    monitor = FakeMonitor(_snapshot())
    monitor.stale_on_call = 2  # 第 1 次探测后检查通过，认证阶段发现代际变化
    engine = _engine(monkeypatch, tmp_path, monitor, adapter,
                     [_internet(InternetState.BLOCKED)],
                     creds=Credentials("u", "p"))
    state = engine.authenticate()
    assert state.phase == Phase.CANCELLED
    assert state.error_code == ErrorCode.CANCELLED
