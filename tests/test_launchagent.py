"""LaunchAgent plist 生成（纯函数部分）与安装/卸载。"""

from __future__ import annotations

import plistlib

from portalkit.ui import launchagent


def test_build_plist_contents():
    plist = launchagent.build_plist("/venv/bin/python", "/Users/x/logs/portalkit-ui.log")
    assert plist["Label"] == launchagent.LABEL
    assert plist["ProgramArguments"] == ["/venv/bin/python", "-m", "portalkit.ui.menubar"]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is False  # 菜单栏应用不自动复活
    data = plistlib.dumps(plist)  # 必须可被 launchd 解析
    assert b"portalkit.ui.menubar" in data


def test_install_uninstall_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(launchagent, "launchagents_dir", lambda: tmp_path)
    monkeypatch.setattr(launchagent, "log_path", lambda: tmp_path / "ui.log")
    monkeypatch.setattr(launchagent, "_start", lambda: True)
    monkeypatch.setattr(launchagent, "_stop", lambda: None)

    assert not launchagent.installed()
    assert launchagent.install() is True
    assert launchagent.installed()
    on_disk = plistlib.loads((tmp_path / f"{launchagent.LABEL}.plist").read_bytes())
    assert on_disk["ProgramArguments"][1:] == ["-m", "portalkit.ui.menubar"]

    launchagent.uninstall()
    assert not launchagent.installed()
