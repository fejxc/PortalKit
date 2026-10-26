"""TrustedTargetRegistry：用户显式确认过的门户目标（SECURITY §1）。

信任记录 = 适配器身份 + 门户主机/端口/scheme + 证书指纹（可选 pinning）
+ 网络线索 + 用户确认时间。仅凭 IP 可达或同 SSID 不构成信任。
指纹变化 → PORTAL_CHANGED，自动提交暂停。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field, replace
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

    def all(self) -> list[TrustRecord]:
        return list(self._records.values())

    def lookup(self, adapter_id: str, portal_host: str) -> TrustRecord | None:
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
            return self._records.pop(f"{adapter_id}:{portal_host}", None) is not None

    def update_fingerprint(self, adapter_id: str, portal_host: str, cert_sha256: str) -> TrustRecord | None:
        with self._lock:
            rec = self._records.get(f"{adapter_id}:{portal_host}")
            if rec is None:
                return None
            rec = replace(rec, cert_sha256=cert_sha256)
            self._records[rec.key] = rec
            self._save()
            return rec
