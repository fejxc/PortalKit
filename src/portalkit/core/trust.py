"""TrustedTargetRegistry：用户显式确认过的门户目标（SECURITY §1）。

信任记录 = 适配器身份 + 门户主机/端口/scheme + 证书指纹（可选 pinning）
+ 网络线索 + 用户确认时间。仅凭 IP 可达或同 SSID 不构成信任。
指纹变化 → PORTAL_CHANGED，自动提交暂停。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime
from pathlib import Path

DEFAULT_STORE_DIR = Path.home() / "Library" / "Application Support" / "PortalKit"


@dataclass(frozen=True)
class TrustRecord:
    adapter_id: str
    portal_host: str
    portal_port: int
    scheme: str  # "https" | "http"
    allowed_hosts: tuple[str, ...]  # 允许携带凭据请求的宿主全集（含门户自身）
    cert_sha256: str | None = None  # 自签证书指纹 pinning；None 表示未固定
    fingerprint: str | None = None  # 页面结构指纹（表单字段集）；变化 = 门户改版信号
    network_hint: str = ""  # 首次确认时的网关/接口线索，仅展示用
    created_at: str = ""
    note: str = ""
    auto_auth: bool = True  # 此网络是否自动认证（PRD F13；显式 authenticate 不受此限）
    last_connected_at: str = ""  # 最近一次"认证成功且物理验证通过"的时间
    last_auth_ok_at: str = ""  # 最近一次认证提交成功（会话建立）时间
    entry_url: str = ""  # 门户入口完整 URL（含会话参数；discovery 被白名单放行时的直连入口）
    # 观测到的会话寿命样本（小时）：两次真实重登之间的间隔。zjlib 不下发
    # keepalive，用中位数驱动"临近过期加密检查"（只加检查不加提交，A03）。
    session_lifetime_samples: tuple[float, ...] = ()

    @property
    def key(self) -> str:
        return f"{self.adapter_id}:{self.portal_host}"

    def matches_host(self, host: str, port: int, scheme: str) -> bool:
        return (
            self.portal_host == host
            and self.portal_port == port
            and self.scheme == scheme
        )


class TrustRegistry:
    def __init__(self, store_dir: Path | None = None) -> None:
        self._dir = store_dir or DEFAULT_STORE_DIR
        self._path = self._dir / "trust.json"
        self._lock = threading.Lock()
        self._records: dict[str, TrustRecord] = {}
        self._load()

    # ---------------------------------------------------------------- io

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for item in raw.get("records", []):
                rec = TrustRecord(
                    adapter_id=item["adapter_id"],
                    portal_host=item["portal_host"],
                    portal_port=int(item["portal_port"]),
                    scheme=item["scheme"],
                    allowed_hosts=tuple(item.get("allowed_hosts", ())),
                    cert_sha256=item.get("cert_sha256"),
                    fingerprint=item.get("fingerprint"),
                    network_hint=item.get("network_hint", ""),
                    created_at=item.get("created_at", ""),
                    note=item.get("note", ""),
                    auto_auth=bool(item.get("auto_auth", True)),  # 旧记录缺省视为开启
                    last_connected_at=item.get("last_connected_at", ""),
                    last_auth_ok_at=item.get("last_auth_ok_at", ""),
                    entry_url=str(item.get("entry_url", "")),
                    session_lifetime_samples=tuple(item.get("session_lifetime_samples") or ()),
                )
                self._records[rec.key] = rec
        except (OSError, ValueError, KeyError):
            # 存储损坏时按空处理，等待下次写入重建；不静默信任任何旧记录。
            self._records = {}

    def _save(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        payload = {"records": [asdict(r) for r in self._records.values()]}
        # 0600：信任记录虽不含密码，也不应被同机其他用户读取。
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

    # ------------------------------------------------------------- lookup

    def reload(self) -> None:
        """从磁盘重读(跨进程场景:CLI 写入后菜单栏进程需感知)。"""
        with self._lock:
            self._records = {}
            self._load()

    def all(self) -> list[TrustRecord]:
        self.reload()
        return list(self._records.values())

    def lookup(self, adapter_id: str, portal_host: str) -> TrustRecord | None:
        self.reload()
        return self._records.get(f"{adapter_id}:{portal_host}")

    def update_auto_auth(self, adapter_id: str, portal_host: str, enabled: bool) -> TrustRecord | None:
        """按网络开关自动认证（PRD F13）。记录不存在返回 None。"""
        with self._lock:
            rec = self._records.get(f"{adapter_id}:{portal_host}")
            if rec is None:
                return None
            rec = replace(rec, auto_auth=enabled)
            self._records[rec.key] = rec
            self._save()
            return rec

    def touch_connected(self, adapter_id: str, portal_host: str, iso_ts: str) -> TrustRecord | None:
        """认证成功且物理验证通过后更新"上次连接"（网络管理窗口展示用）。"""
        with self._lock:
            rec = self._records.get(f"{adapter_id}:{portal_host}")
            if rec is None:
                return None
            rec = replace(rec, last_connected_at=iso_ts)
            self._records[rec.key] = rec
            self._save()
            return rec

    def note_auth_success(self, adapter_id: str, portal_host: str, iso_ts: str,
                          *, min_gap_hours: float = 1.0, max_samples: int = 10) -> TrustRecord | None:
        """记录认证成功时刻，并从"两次真实重登的间隔"学习会话寿命样本。

        间隔小于 min_gap_hours（快速刷新/卡死重试）不计入——它们不代表
        会话自然到期。样本保留最近 max_samples 个。
        """
        with self._lock:
            rec = self._records.get(f"{adapter_id}:{portal_host}")
            if rec is None:
                return None
            samples = list(rec.session_lifetime_samples)
            if rec.last_auth_ok_at:
                try:
                    gap_h = (datetime.fromisoformat(iso_ts)
                             - datetime.fromisoformat(rec.last_auth_ok_at)).total_seconds() / 3600
                    if gap_h >= min_gap_hours:
                        samples.append(round(gap_h, 2))
                        samples = samples[-max_samples:]
                except ValueError:
                    pass  # 时间戳损坏时丢弃本次样本，不影响会话记录
            rec = replace(rec, last_auth_ok_at=iso_ts, session_lifetime_samples=tuple(samples))
            self._records[rec.key] = rec
            self._save()
            return rec

    def median_session_lifetime_hours(self, adapter_id: str, portal_host: str) -> float | None:
        rec = self._records.get(f"{adapter_id}:{portal_host}")
        samples = rec.session_lifetime_samples if rec else None
        if not samples:
            return None
        ordered = sorted(samples)
        mid = len(ordered) // 2
        if len(ordered) % 2:
            return float(ordered[mid])
        return (ordered[mid - 1] + ordered[mid]) / 2

    def fingerprint_matches(self, record: TrustRecord, observed: str | None) -> bool:
        """observed=None 视为"本次未能观测"，不据此否定既有信任。"""
        if record.cert_sha256 is None or observed is None:
            return True
        return record.cert_sha256 == observed

    def signature_matches(
        self, record: TrustRecord, fingerprint: str | None, cert_sha256: str | None
    ) -> bool:
        """双指纹比对：证书 + 页面结构。任一已固定且不匹配 → PORTAL_CHANGED。"""
        if record.fingerprint is not None and fingerprint is not None:
            if record.fingerprint != fingerprint:
                return False
        return self.fingerprint_matches(record, cert_sha256)

    # -------------------------------------------------------------- mutate

    def add(self, record: TrustRecord) -> TrustRecord:
        with self._lock:
            self._records[record.key] = record
            self._save()
            return record

    def revoke(self, adapter_id: str, portal_host: str) -> bool:
        with self._lock:
            removed = self._records.pop(f"{adapter_id}:{portal_host}", None) is not None
            if removed:
                self._save()  # 撤销必须落盘,否则 reload 会把它找回来
            return removed

    def update_fingerprint(self, adapter_id: str, portal_host: str, cert_sha256: str) -> TrustRecord | None:
        with self._lock:
            rec = self._records.get(f"{adapter_id}:{portal_host}")
            if rec is None:
                return None
            rec = replace(rec, cert_sha256=cert_sha256)
            self._records[rec.key] = rec
            self._save()
            return rec
