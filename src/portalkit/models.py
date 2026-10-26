"""PortalKit 核心数据模型（STATE_MODEL.md 的落地）。

三维真实网络状态（link / portal / internet）互不正交合并，UI 文案由三维状态
与 phase/error_code 映射得出；任何状态只携带脱敏数据。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256

SCHEMA_VERSION = 1


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class LinkState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    CONFIGURING = "CONFIGURING"
    READY = "READY"
    ERROR = "ERROR"


class PortalState(str, Enum):
    UNKNOWN = "UNKNOWN"
    NOT_REQUIRED = "NOT_REQUIRED"
    DETECTED = "DETECTED"
    TRUST_PENDING = "TRUST_PENDING"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    INTERACTION_REQUIRED = "INTERACTION_REQUIRED"
    FAILED = "FAILED"


class InternetState(str, Enum):
    UNKNOWN = "UNKNOWN"
    CHECKING = "CHECKING"
    REACHABLE = "REACHABLE"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"


class Phase(str, Enum):
    IDLE = "IDLE"
    DEBOUNCING = "DEBOUNCING"
    PROBING = "PROBING"
    MATCHING = "MATCHING"
    ONLINE_NO_AUTH = "ONLINE_NO_AUTH"
    TRUST_REQUIRED = "TRUST_REQUIRED"
    AUTHENTICATING = "AUTHENTICATING"
    VERIFYING = "VERIFYING"
    ONLINE_AUTHENTICATED = "ONLINE_AUTHENTICATED"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"
    WAITING_USER = "WAITING_USER"
    RETRY_BACKOFF = "RETRY_BACKOFF"


class AuthCode(str, Enum):
    """适配器认证结果码（ADAPTER_API.md §2）。"""

    SUCCESS = "success"
    ALREADY_AUTHENTICATED = "already_authenticated"
    INVALID_CREDENTIALS = "invalid_credentials"
    INTERACTION_REQUIRED = "interaction_required"
    PORTAL_CHANGED = "portal_changed"
    NETWORK_ERROR = "network_error"
    UNTRUSTED_TARGET = "untrusted_target"
    UNKNOWN_ERROR = "unknown_error"


class ErrorCode(str, Enum):
    NONE = "none"
    NO_PHYSICAL_INTERFACE = "no_physical_interface"
    NO_ADAPTER_MATCHED = "no_adapter_matched"
    TRUST_REQUIRED = "trust_required"
    NEED_CREDENTIALS = "need_credentials"
    INVALID_CREDENTIALS = "invalid_credentials"
    INTERACTION_REQUIRED = "interaction_required"
    PORTAL_CHANGED = "portal_changed"
    UNTRUSTED_TARGET = "untrusted_target"
    VERIFY_FAILED = "verify_failed"
    NETWORK_ERROR = "network_error"
    ENGINE_BUSY = "engine_busy"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class NetworkSnapshot:
    """一次物理网络采样。fingerprint 相同即视为同一网络（generation 不变）。"""

    interface: str | None
    ipv4: str | None
    gateway: str | None
    dns: str | None
    ssid: str | None = None  # 未启用定位授权时恒为 None（PRD：SSID 可选）
    timestamp: str = field(default_factory=utc_now_iso)

    @property
    def fingerprint(self) -> str:
        raw = f"{self.interface}|{self.ipv4}|{self.gateway}|{self.dns}"
        return sha256(raw.encode()).hexdigest()[:16]

    @property
    def ready(self) -> bool:
        return bool(self.interface and self.ipv4)

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "ipv4": self.ipv4,
            "gateway": self.gateway,
            "dns": self.dns,
            "ssid": self.ssid,
            "fingerprint": self.fingerprint,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class StateSnapshot:
    """引擎对外的唯一状态出口；UI / CLI 均只消费它。"""

    link: LinkState
    portal: PortalState
    internet: InternetState
    phase: Phase
    network_generation: int
    interface: str | None = None
    adapter_id: str | None = None
    error_code: ErrorCode = ErrorCode.NONE
    message_key: str = "status.idle"
    detail: str = ""  # 人类可读补充，调用方保证脱敏
    timestamp: str = field(default_factory=utc_now_iso)
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "timestamp": self.timestamp,
            "network_generation": self.network_generation,
            "interface": self.interface,
            "adapter_id": self.adapter_id,
            "link": self.link.value,
            "portal": self.portal.value,
            "internet": self.internet.value,
            "phase": self.phase.value,
            "error_code": self.error_code.value,
            "message_key": self.message_key,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


def message_key_for(phase: Phase, error: ErrorCode = ErrorCode.NONE) -> str:
    """状态/错误到文案字典 key（FLOWS_AND_COPY.md 文案字典）的映射。"""
    if error == ErrorCode.INVALID_CREDENTIALS:
        return "error.invalid_creds"
    if error == ErrorCode.PORTAL_CHANGED:
        return "error.portal_changed"
    if error == ErrorCode.INTERACTION_REQUIRED:
        return "error.interaction_required"
    return {
        Phase.IDLE: "status.idle",
        Phase.PROBING: "status.checking",
        Phase.MATCHING: "status.checking",
        Phase.ONLINE_NO_AUTH: "status.no_auth",
        Phase.TRUST_REQUIRED: "status.unknown_portal",
        Phase.AUTHENTICATING: "status.authenticating",
        Phase.VERIFYING: "status.verifying",
        Phase.ONLINE_AUTHENTICATED: "status.online",
        Phase.DEGRADED: "status.verifying",
        Phase.ERROR: "status.action_required",
        Phase.CANCELLED: "status.checking",
        Phase.WAITING_USER: "status.action_required",
        Phase.RETRY_BACKOFF: "status.checking",
    }.get(phase, "status.idle")
