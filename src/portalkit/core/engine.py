"""核心引擎：单任务互斥、generation 取消、三维状态判定、有界重试。

完成判定红线（PRD §7 / 用户验收）：认证"提交成功"绝不直接等于"已联网"；
ONLINE_AUTHENTICATED / ONLINE_NO_AUTH 只能由**绑定物理接口的多探针验证**
授予。已在线（互联网探针通过）时不提交凭据（A03）。
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from portalkit.adapters.base import AdapterContext, AuthCode, Credentials, DetectionResult, PortalAdapter
from portalkit.adapters.registry import AdapterRegistry
from portalkit.core.retry import RetryPolicy
from portalkit.core.statemachine import assert_transition
from portalkit.core.trust import TrustRegistry, TrustRecord
from portalkit.diagnostics.logging import RedactedLogger
from portalkit.models import (
    ErrorCode,
    InternetState,
    LinkState,
    NetworkSnapshot,
    Phase,
    PortalState,
    StateSnapshot,
    message_key_for,
)
from portalkit.network.http import BoundHTTPClient
from portalkit.network.monitor import GenerationStale, NetworkMonitor
from portalkit.network.probes import check_internet

DEFAULT_STATE_DIR = Path.home() / "Library" / "Application Support" / "PortalKit"


class CredentialService(Protocol):
    """凭据服务最小接口；生产实现包装 Keychain，测试用内存实现。"""

    def get(self, adapter_id: str, host: str) -> Credentials | None: ...

    def usernames(self, adapter_id: str, host: str) -> list[str]: ...


@dataclass(frozen=True)
class DetectionReport:
    snapshot: NetworkSnapshot
    generation: int
    results: tuple[DetectionResult, ...]


class Engine:
    def __init__(
        self,
        monitor: NetworkMonitor,
        registry: AdapterRegistry,
        trust: TrustRegistry,
        credentials: CredentialService,
        logger: RedactedLogger | None = None,
        retry_policy: RetryPolicy | None = None,
        state_dir: Path | None = None,
    ) -> None:
        self._monitor = monitor
        self._registry = registry
        self._trust = trust
        self._credentials = credentials
        self._log = logger or RedactedLogger()
        self._retry = retry_policy or RetryPolicy()
        self._state_dir = state_dir or DEFAULT_STATE_DIR
        self._lock = threading.Lock()

    # ------------------------------------------------------------ public

    def check(self) -> StateSnapshot:
        """探测 + 识别，不提交任何凭据（PRD F10 / A07）。"""
        return self._run(allow_auth=False)

    def authenticate(self) -> StateSnapshot:
        """完整认证流。前置：目标已信任 + Keychain 有凭据，否则转 WAITING_USER。"""
        return self._run(allow_auth=True)

    def detect(self) -> DetectionReport:
        """独立识别（trust add 用），不改状态、不提交凭据。"""
        snap = self._monitor.current_snapshot()
        generation = self._monitor.current_generation()
        results: list[DetectionResult] = []
        if snap.ready:
            for adapter in self._registry.all():
                try:
                    results.append(adapter.detect(self._context(snap, generation)))
                except GenerationStale:
                    break
        return DetectionReport(snapshot=snap, generation=generation, results=tuple(results))

    # ----------------------------------------------------------- internals

    def _context(self, snap: NetworkSnapshot, generation: int) -> AdapterContext:
        def client_factory(allowed_hosts=None, *, tls_verify: bool = True) -> BoundHTTPClient:
            return BoundHTTPClient(
                interface=snap.interface,
                dns_resolver=snap.dns,
                allowed_hosts=allowed_hosts,
                tls_verify=tls_verify,
            )

        return AdapterContext(
            snapshot=snap,
            generation=generation,
            check_generation=lambda: self._monitor.check_generation(generation),
            client_factory=client_factory,
        )

    def _advance(self, phase: Phase) -> None:
        """显式推进工作状态；非法路径在此快速失败。"""
        assert_transition(self._last_phase, phase)
        self._last_phase = phase

    def _state(
        self,
        snap: NetworkSnapshot,
        generation: int,
        *,
        link: LinkState,
        portal: PortalState,
        internet: InternetState,
        phase: Phase,
        adapter_id: str | None = None,
        error: ErrorCode = ErrorCode.NONE,
        detail: str = "",
        evidence: tuple[str, ...] = (),
    ) -> StateSnapshot:
        self._last_phase = phase
        return StateSnapshot(
            link=link,
            portal=portal,
            internet=internet,
            phase=phase,
            network_generation=generation,
            interface=snap.interface,
            adapter_id=adapter_id,
            error_code=error,
            message_key=message_key_for(phase, error),
            detail=detail,
            evidence=evidence,
        )

    _last_phase: Phase = Phase.IDLE  # 引擎级记忆，仅用于转移合法性自检

    def _run(self, *, allow_auth: bool) -> StateSnapshot:
        if not self._lock.acquire(blocking=False):
            snap = self._monitor.current_snapshot()
            return self._state(
                snap, self._monitor.current_generation(),
                link=LinkState.READY, portal=PortalState.UNKNOWN,
                internet=InternetState.CHECKING, phase=Phase.ERROR,
                error=ErrorCode.ENGINE_BUSY, detail="已有任务在执行",
            )
        try:
            snap = self._monitor.current_snapshot()
            generation = self._monitor.current_generation()

            if not snap.ready:
                return self._finish(self._state(
                    snap, generation, link=LinkState.DISCONNECTED,
                    portal=PortalState.UNKNOWN, internet=InternetState.UNKNOWN,
                    phase=Phase.ERROR, error=ErrorCode.NO_PHYSICAL_INTERFACE,
                    detail="未发现带 IPv4 的物理网络接口，请连接 Wi-Fi 或以太网",
                ))

            # ---- 物理链路就绪，进入探测
            self._advance(Phase.PROBING)
            try:
                internet = check_internet(snap.interface, snap.dns)
            except Exception as exc:  # noqa: BLE001
                return self._finish(self._state(
                    snap, generation, link=LinkState.ERROR,
                    portal=PortalState.UNKNOWN, internet=InternetState.ERROR,
                    phase=Phase.ERROR, error=ErrorCode.NETWORK_ERROR,
                    detail=f"探测失败: {type(exc).__name__}",
                ))
            try:
                self._monitor.check_generation(generation)
            except GenerationStale:
                return self._cancelled(snap)

            if internet.reachable:
                # 已验证在线：不再提交凭据（A03），真实语义"无需认证"。
                return self._finish(self._state(
                    snap, generation, link=LinkState.READY,
                    portal=PortalState.NOT_REQUIRED, internet=InternetState.REACHABLE,
                    phase=Phase.ONLINE_NO_AUTH,
                    detail="物理网络已通过多探针验证，无需登录",
                    evidence=internet.evidence,
                ))

            # ---- 门户识别
            self._advance(Phase.MATCHING)
            matched: DetectionResult | None = None
            matched_adapter: PortalAdapter | None = None
            for adapter in self._registry.all():
                try:
                    detection = adapter.detect(self._context(snap, generation))
                except GenerationStale:
                    return self._cancelled(snap)
                if detection.matched:
                    matched, matched_adapter = detection, adapter
                    break
            if matched is None or matched_adapter is None:
                return self._finish(self._state(
                    snap, generation, link=LinkState.READY,
                    portal=PortalState.UNKNOWN, internet=internet.state,
                    phase=Phase.ERROR, error=ErrorCode.NO_ADAPTER_MATCHED,
                    detail="未识别到已知门户，且物理路径未通过互联网验证",
                    evidence=internet.evidence,
                ))

            assert matched.portal_host is not None
            record = self._trust.lookup(matched.adapter_id, matched.portal_host)

            if record is None:
                return self._finish(self._state(
                    snap, generation, link=LinkState.READY,
                    portal=PortalState.TRUST_PENDING, internet=internet.state,
                    phase=Phase.TRUST_REQUIRED, adapter_id=matched.adapter_id,
                    error=ErrorCode.TRUST_REQUIRED,
                    detail=f"发现 {matched_adapter.name} 认证门户，需先确认信任",
                    evidence=matched.evidence,
                ))

            if not self._trust.signature_matches(record, matched.fingerprint, matched.observed_cert_sha256):
                return self._finish(self._state(
                    snap, generation, link=LinkState.READY,
                    portal=PortalState.FAILED, internet=internet.state,
                    phase=Phase.WAITING_USER, adapter_id=matched.adapter_id,
                    error=ErrorCode.PORTAL_CHANGED,
                    detail="门户特征与已信任记录不一致，自动提交已暂停",
                    evidence=matched.evidence,
                ))

            if matched.already_authenticated:
                # 门户语义层面会话有效（zjlib 404 / zstu success.jsp），仍需物理验证。
                return self._finish(self._verify(
                    snap, generation, matched_adapter, internet_state=internet.state,
                    already=True,
                ))

            if not allow_auth:
                return self._finish(self._state(
                    snap, generation, link=LinkState.READY,
                    portal=PortalState.DETECTED, internet=internet.state,
                    phase=Phase.MATCHING, adapter_id=matched.adapter_id,
                    detail="已识别并信任该门户；运行 authenticate 执行认证",
                    evidence=matched.evidence,
                ))

            creds = self._credentials.get(matched.adapter_id, matched.portal_host)
            if creds is None:
                return self._finish(self._state(
                    snap, generation, link=LinkState.READY,
                    portal=PortalState.TRUST_PENDING, internet=internet.state,
                    phase=Phase.WAITING_USER, adapter_id=matched.adapter_id,
                    error=ErrorCode.NEED_CREDENTIALS,
                    detail="目标已信任但缺少凭据，请先录入账号",
                ))
            self._log.register_secret(creds.password)

            # ---- 认证（单任务、有界退避，永久错误不重试）
            auth = None
            for attempt in range(self._retry.attempts()):
                try:
                    self._advance(Phase.AUTHENTICATING)
                    auth = matched_adapter.authenticate(self._context(snap, generation), creds)
                except GenerationStale:
                    return self._cancelled(snap)
                if auth is not None and not (auth.code == AuthCode.NETWORK_ERROR and attempt + 1 < self._retry.attempts()):
                    break
                if auth is not None and auth.code == AuthCode.NETWORK_ERROR:
                    delay = self._retry.next_delay(attempt)
                    self._log.event("auth_retry", adapter=matched.adapter_id,
                                    attempt=attempt + 1, delay_s=round(delay, 2))
                    time.sleep(delay)
            assert auth is not None

            self._log.event("auth_result", adapter=matched.adapter_id,
                            code=auth.code.value, retryable=auth.retryable,
                            evidence=list(auth.evidence))

            if auth.code == AuthCode.ALREADY_AUTHENTICATED:
                return self._finish(self._verify(
                    snap, generation, matched_adapter, internet_state=internet.state, already=True,
                ))
            if auth.code == AuthCode.SUCCESS:
                return self._finish(self._verify(
                    snap, generation, matched_adapter, internet_state=internet.state, already=False,
                ))
            return self._finish(self._auth_failure(snap, generation, matched.adapter_id, auth, internet))

        finally:
            self._lock.release()

    # ------------------------------------------------------------ branches

    def _auth_failure(self, snap, generation, adapter_id, auth, internet) -> StateSnapshot:
        mapping = {
            AuthCode.INVALID_CREDENTIALS: (
                PortalState.FAILED, Phase.WAITING_USER, ErrorCode.INVALID_CREDENTIALS,
                "账号或密码无效，请更新凭据（不自动重试）"),
            AuthCode.INTERACTION_REQUIRED: (
                PortalState.INTERACTION_REQUIRED, Phase.WAITING_USER, ErrorCode.INTERACTION_REQUIRED,
                "门户要求网页操作（验证码等），请人工完成"),
            AuthCode.PORTAL_CHANGED: (
                PortalState.FAILED, Phase.WAITING_USER, ErrorCode.PORTAL_CHANGED,
                "门户协议特征变化，自动提交已暂停"),
            AuthCode.UNTRUSTED_TARGET: (
                PortalState.FAILED, Phase.ERROR, ErrorCode.UNTRUSTED_TARGET,
                "请求被重定向到未授权目标，已终止且未发送凭据"),
            AuthCode.UNKNOWN_ERROR: (
                PortalState.FAILED, Phase.ERROR, ErrorCode.UNKNOWN,
                "门户返回未知结果，请查看诊断"),
            AuthCode.NETWORK_ERROR: (
                PortalState.UNKNOWN, Phase.ERROR, ErrorCode.NETWORK_ERROR,
                "网络临时失败，退避重试已用尽"),
        }
        portal, phase, error, detail = mapping.get(
            auth.code,
            (PortalState.FAILED, Phase.ERROR, ErrorCode.UNKNOWN, "未知结果"),
        )
        return self._finish(self._state(
            snap, generation, link=LinkState.READY, portal=portal,
            internet=internet.state, phase=phase, adapter_id=adapter_id,
            error=error, detail=detail, evidence=auth.evidence,
        ))

    def _verify(self, snap, generation, adapter: PortalAdapter, *, internet_state, already: bool) -> StateSnapshot:
        """认证成功/会话有效后的物理出口验证（完成判定红线）。"""
        self._advance(Phase.VERIFYING)
        try:
            self._monitor.check_generation(generation)
            protocol = adapter.verify_protocol(self._context(snap, generation))
            internet = check_internet(snap.interface, snap.dns)
        except GenerationStale:
            return self._cancelled(snap)
        except Exception as exc:  # noqa: BLE001
            return self._finish(self._state(
                snap, generation, link=LinkState.READY, portal=PortalState.AUTHENTICATED,
                internet=InternetState.ERROR, phase=Phase.DEGRADED, adapter_id=adapter.id,
                error=ErrorCode.VERIFY_FAILED, detail=f"验证阶段异常: {type(exc).__name__}",
            ))
        if internet.reachable and protocol.session_valid is not False:
            return self._finish(self._state(
                snap, generation, link=LinkState.READY, portal=PortalState.AUTHENTICATED,
                internet=InternetState.REACHABLE, phase=Phase.ONLINE_AUTHENTICATED,
                adapter_id=adapter.id,
                detail=("会话有效且物理路径已验证" if already else "自动认证完成，物理路径已验证"),
                evidence=(*protocol.evidence, *internet.evidence),
            ))
        if internet.reachable and protocol.session_valid is False:
            # 互联网可达但门户称会话无效：开放网络等场景，如实报告"无需认证"。
            return self._finish(self._state(
                snap, generation, link=LinkState.READY, portal=PortalState.NOT_REQUIRED,
                internet=InternetState.REACHABLE, phase=Phase.ONLINE_NO_AUTH,
                adapter_id=adapter.id, detail="互联网可达；门户会话无效但不影响联网",
                evidence=(*protocol.evidence, *internet.evidence),
            ))
        return self._finish(self._state(
            snap, generation, link=LinkState.READY, portal=PortalState.AUTHENTICATED,
            internet=internet.state, phase=Phase.DEGRADED, adapter_id=adapter.id,
            error=ErrorCode.VERIFY_FAILED,
            detail="认证已响应，但物理网络验证未通过——不显示已联网",
            evidence=(*protocol.evidence, *internet.evidence),
        ))

    def _cancelled(self, snap: NetworkSnapshot) -> StateSnapshot:
        new_gen = self._monitor.current_generation()
        return self._finish(self._state(
            snap, new_gen, link=LinkState.READY if snap.ready else LinkState.DISCONNECTED,
            portal=PortalState.UNKNOWN, internet=InternetState.UNKNOWN,
            phase=Phase.CANCELLED, error=ErrorCode.CANCELLED,
            detail="网络已变化，旧任务已取消，请重新检查",
        ))

    # ----------------------------------------------------------- persistence

    def _finish(self, state: StateSnapshot) -> StateSnapshot:
        self._log.event(
            "state", phase=state.phase.value, adapter=state.adapter_id,
            error=state.error_code.value, generation=state.network_generation,
            evidence=list(state.evidence),
        )
        self._persist(state)
        return state

    def _persist(self, state: StateSnapshot) -> None:
        self._state_dir.mkdir(parents=True, exist_ok=True)
        path = self._state_dir / "state.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state.to_dict(), fh, ensure_ascii=False, indent=2)
