"""SettingsStore：默认值、白名单间隔、持久化回读、损坏兜底。"""

from __future__ import annotations

import pytest

from portalkit.core.settings import SettingsStore


def test_defaults(tmp_path):
    store = SettingsStore(tmp_path / "settings.json")
    s = store.get()
    assert s.auto_auth is True
    assert s.notify_on_error is True
    assert s.check_interval_s == 120
    assert s.launch_at_login is False


def test_update_roundtrip_and_whitelist(tmp_path):
    path = tmp_path / "settings.json"
    store = SettingsStore(path)
    store.update(auto_auth=False, check_interval_s=30)
    reloaded = SettingsStore(path).get()
    assert reloaded.auto_auth is False
    assert reloaded.check_interval_s == 30
    with pytest.raises(ValueError):
        store.update(check_interval_s=5)  # 防过短轮询


def test_corrupt_file_falls_back_to_defaults(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{not json", encoding="utf-8")
    store = SettingsStore(path)
    assert store.get().check_interval_s == 120
