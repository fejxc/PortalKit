"""TrustedTargetRegistry：显式信任、指纹变化拒绝、持久化回读。"""

from __future__ import annotations

from portalkit.core.trust import TrustRecord, TrustRegistry
from portalkit.models import utc_now_iso


def _record(**overrides) -> TrustRecord:
    base = dict(
        adapter_id="zjlib", portal_host="2.2.1.1", portal_port=8443,
        scheme="https", allowed_hosts=("2.2.1.1",),
        cert_sha256="a" * 64, fingerprint="fp-zjlib-v1",
        created_at=utc_now_iso(), note="test",
    )
    base.update(overrides)
    return TrustRecord(**base)


def test_add_lookup_revoke(tmp_path):
    registry = TrustRegistry(tmp_path)
    registry.add(_record())
    assert registry.lookup("zjlib", "2.2.1.1") is not None
    assert registry.lookup("zjlib", "other") is None
    assert registry.revoke("zjlib", "2.2.1.1")
    assert not registry.revoke("zjlib", "2.2.1.1")  # 二次撤销 = False
    assert registry.lookup("zjlib", "2.2.1.1") is None


def test_persist_roundtrip(tmp_path):
    TrustRegistry(tmp_path).add(_record())
    # 新实例从磁盘读回——信任不因进程重启丢失
    loaded = TrustRegistry(tmp_path).lookup("zjlib", "2.2.1.1")
    assert loaded is not None
    assert loaded.cert_sha256 == "a" * 64
    assert loaded.fingerprint == "fp-zjlib-v1"


def test_signature_match_on_identical(tmp_path):
    registry = TrustRegistry(tmp_path)
    record = registry.add(_record())
    assert registry.signature_matches(record, "fp-zjlib-v1", "a" * 64)


def test_fingerprint_change_is_rejected(tmp_path):
    registry = TrustRegistry(tmp_path)
    record = registry.add(_record())
    # 页面结构指纹变化（门户改版）→ 拒绝
    assert not registry.signature_matches(record, "fp-CHANGED", "a" * 64)
    # 证书指纹变化（自签证书更换）→ 拒绝
    assert not registry.signature_matches(record, "fp-zjlib-v1", "b" * 64)


def test_unobserved_signature_does_not_break_trust(tmp_path):
    """本次未能观测到指纹（如未走 TLS）不构成变更证据。"""
    registry = TrustRegistry(tmp_path)
    record = registry.add(_record())
    assert registry.signature_matches(record, None, None)


def test_auto_auth_toggle_persists(tmp_path):
    """F13：按网络自动认证开关，持久化回读 + 旧记录缺省视为开启。"""
    registry = TrustRegistry(tmp_path)
    registry.add(_record())
    updated = registry.update_auto_auth("zjlib", "2.2.1.1", False)
    assert updated is not None and updated.auto_auth is False
    reloaded = TrustRegistry(tmp_path).lookup("zjlib", "2.2.1.1")
    assert reloaded is not None and reloaded.auto_auth is False
    assert registry.update_auto_auth("zjlib", "missing-host", True) is None
