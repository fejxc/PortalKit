"""适配器契约（ADAPTER_API.md 的 Phase 1 落地）。

与草案的偏差（有意为之，README 已记录）：
- 方法为同步签名。P0 引擎单线程运行 + generation 取消已满足需求，
  async 版本留待真正出现多宿主/高并发场景再包装。

核心原则：
- 适配器只做协议；重试、信任判定、Keychain、通知全部由 core 决定。
- 每个网络步骤之间必须调用 ctx.check_generation()，过期即抛
  GenerationStale（引擎转 CANCELLED，绝不把旧结果写进新状态）。
- 适配器不得触碰全局 Keychain / UI / 其他适配器的凭据；
  只经 ctx.client_factory() 获取受约束的 BoundHTTPClient。
- AuthResult 不是联网结论；已联网只能由 core 的物理出口验证授予。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Protocol, runtime_checkable

from portalkit.models import AuthCode, NetworkSnapshot
from portalkit.network.http import BoundHTTPClient


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str = field(repr=False)  # 任何 repr/日志路径都不会带出密码

    def __repr__(self) -> str:  # 显式防御
        return f"Credentials(username={self.username!r}, password=***)"


@dataclass(frozen=True)
class DetectionResult:
    matched: bool
    adapter_id: str
    portal_scheme: str | None = None
    portal_host: str | None = None
    portal_port: int | None = None
    fingerprint: str | None = None  # 表单/页面结构指纹，用于 PORTAL_CHANGED 判定
    already_authenticated: bool = False  # 门户可达但会话已有效（zjlib 404 / zstu success.jsp）
    needs_trust: bool = True  # detect 永不自动信任
    evidence: tuple[str, ...] = ()  # 必须脱敏：宿主、状态码、字段名等
    observed_cert_sha256: str | None = None  # TLS 叶证书指纹（zjlib pinning 用）


@dataclass(frozen=True)
class AuthResult:
    code: AuthCode
    message_key: str
    retryable: bool = False
    evidence: tuple[str, ...] = ()
    keepalive_minutes: int | None = None
    # 简短的中文恢复提示（≤40 字），用于菜单一行展示；完整指引放 evidence
    # （诊断窗口可见）。缺省时引擎用 message_key 对应的默认文案。
    recovery_hint: str = ""


@dataclass(frozen=True)
class ProtocolVerifyResult:
    """门户协议层的会话状态（zjlib 入口 404 / zstu success.jsp 等）。

    与物理互联网验证彼此独立；两者都通过才允许显示"已联网"。
    """

    session_valid: bool | None  # None = 无法判定
    evidence: tuple[str, ...] = ()


@dataclass
class AdapterContext:
    """由 core 注入的受限运行环境。"""

    snapshot: NetworkSnapshot
    generation: int
    check_generation: Callable[[], None]  # 过期抛 GenerationStale
    client_factory: Callable[..., BoundHTTPClient]
    # client_factory(allowed_hosts: frozenset[str] | None, *, tls_verify: bool) -> BoundHTTPClient


@runtime_checkable
class PortalAdapter(Protocol):
    id: str
    name: str
    api_version: int

    def detect(self, ctx: AdapterContext) -> DetectionResult: ...

    def authenticate(self, ctx: AdapterContext, creds: Credentials) -> AuthResult: ...

    def verify_protocol(self, ctx: AdapterContext) -> ProtocolVerifyResult: ...
