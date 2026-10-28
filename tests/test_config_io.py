"""配置导出/导入:roundtrip、凭据零包含、坏间隔白名单、schema 校验。"""

from __future__ import annotations

import json

import pytest

from portalkit.core.config_io import export_config, import_config
from portalkit.core.settings import SettingsStore
from portalkit.core.trust import TrustRecord, TrustRegistry


def _seed(trust: TrustRegistry, settings: SettingsStore) -> None:
    trust.add(TrustRecord(
        adapter_id="zjlib", portal_host="2.2.1.1", portal_port=8443,
        scheme="https", allowed_hosts=("2.2.1.1",),
        cert_sha256="a" * 64, fingerprint="fp1", auto_auth=True,
    ))
    trust.add(TrustRecord(
        adapter_id="zstu", portal_host="192.168.102.130", portal_port=80,
        scheme="http", allowed_hosts=("192.168.102.130",), auto_auth=False,
    ))
    settings.update(auto_auth=False, check_interval_s=30)


def test_export_import_roundtrip(tmp_path):
    trust, settings = TrustRegistry(tmp_path / "t1"), SettingsStore(tmp_path / "s1.json")
    _seed(trust, settings)
    export_path = tmp_path / "cfg.json"
    count = export_config(trust, settings, export_path)
    assert count == 2

    fresh_trust, fresh_settings = TrustRegistry(tmp_path / "t2"), SettingsStore(tmp_path / "s2.json")
    n_t, n_s = import_config(fresh_trust, fresh_settings, export_path)
    assert (n_t, n_s) == (2, 3)  # 信任 2 条;设置白名单 3 项(launch_at_login 不迁移)
    assert len(fresh_trust.all()) == 2
    imported = fresh_trust.lookup("zjlib", "2.2.1.1")
    assert imported.cert_sha256 == "a" * 64 and imported.auto_auth is True
    assert fresh_settings.get().auto_auth is False
    assert fresh_settings.get().check_interval_s == 30


def test_export_contains_no_credentials(tmp_path):
    trust = TrustRegistry(tmp_path / "t")
    trust.add(TrustRecord(
        adapter_id="zjlib", portal_host="2.2.1.1", portal_port=8443,
        scheme="https", allowed_hosts=("2.2.1.1",),
    ))
    path = tmp_path / "cfg.json"
    export_config(trust, SettingsStore(tmp_path / "s.json"), path)
    raw = path.read_text(encoding="utf-8").lower()
    for secret in ("password", "secret", "token", "credential"):
        assert secret not in raw, f"导出文件不应包含 {secret}"


def test_import_skips_invalid_interval(tmp_path):
    trust, settings = TrustRegistry(tmp_path / "t"), SettingsStore(tmp_path / "s.json")
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({
        "schema": 1,
        "trust": [],
        "settings": {"check_interval_s": 5, "auto_auth": False},  # 5 不在白名单
    }), encoding="utf-8")
    n_t, n_s = import_config(trust, settings, path)
    assert (n_t, n_s) == (0, 1)
    assert settings.get().check_interval_s == 120  # 保持默认
    assert settings.get().auto_auth is False


def test_import_rejects_foreign_schema(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(ValueError):
        import_config(TrustRegistry(tmp_path / "t"), SettingsStore(tmp_path / "s.json"), path)
