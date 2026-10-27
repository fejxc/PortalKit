"""LaunchAgent plist 生成（纯函数部分）与安装/卸载。"""

from __future__ import annotations

import plistlib

from portalkit.ui import launchagent


def test_build_plist_contents():
    args = ["/Applications/PortalKit.app/Contents/MacOS/PortalKit"]
    plist = launchagent.build_plist(args, "/Users/x/logs/portalkit-ui.log")
    assert plist["Label"] == launchagent.LABEL
    assert plist["ProgramArguments"] == args
    assert plist["RunAtLoad"] is True
    # 崩溃自愈：仅非零退出拉起；正常退出（0）保持停止；10s 节流防僵尸循环
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["ThrottledInterval"] == 10
    data = plistlib.dumps(plist)  # 必须可被 launchd 解析
    assert b"PortalKit.app" in data


def test_install_prefers_standalone_bundle(monkeypatch, tmp_path):
    monkeypatch.setattr(launchagent, "launchagents_dir", lambda: tmp_path)
    monkeypatch.setattr(launchagent, "log_path", lambda: tmp_path / "ui.log")
    monkeypatch.setattr(launchagent, "_start", lambda: True)
    monkeypatch.setattr(launchagent, "_stop", lambda: None)
    fake_exe = tmp_path / "PortalKit.app" / "Contents" / "MacOS" / "PortalKit"
    fake_exe.parent.mkdir(parents=True)
    fake_exe.write_text("#!/bin/sh\n")
    # _program_args 在调用时从 appbundle 模块取函数——patch 源头模块属性
    monkeypatch.setattr("portalkit.ui.appbundle.bundle_executable", lambda: fake_exe)

    assert launchagent.install() is True
    on_disk = plistlib.loads((tmp_path / f"{launchagent.LABEL}.plist").read_bytes())
    assert on_disk["ProgramArguments"] == [str(fake_exe)]


def test_install_falls_back_to_venv_python(monkeypatch, tmp_path):
    monkeypatch.setattr(launchagent, "launchagents_dir", lambda: tmp_path)
    monkeypatch.setattr(launchagent, "log_path", lambda: tmp_path / "ui.log")
    monkeypatch.setattr(launchagent, "_start", lambda: True)
    monkeypatch.setattr(launchagent, "_stop", lambda: None)
    monkeypatch.setattr("portalkit.ui.appbundle.bundle_executable", lambda: None)

    assert launchagent.install() is True
    on_disk = plistlib.loads((tmp_path / f"{launchagent.LABEL}.plist").read_bytes())
    assert on_disk["ProgramArguments"][1:] == ["-m", "portalkit.ui.menubar"]


def test_install_uninstall_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr(launchagent, "launchagents_dir", lambda: tmp_path)
    monkeypatch.setattr(launchagent, "log_path", lambda: tmp_path / "ui.log")
    monkeypatch.setattr(launchagent, "_start", lambda: True)
    monkeypatch.setattr(launchagent, "_stop", lambda: None)
    monkeypatch.setattr("portalkit.ui.appbundle.bundle_executable", lambda: None)

    assert not launchagent.installed()
    assert launchagent.install() is True
    assert launchagent.installed()
    on_disk = plistlib.loads((tmp_path / f"{launchagent.LABEL}.plist").read_bytes())
    assert on_disk["ProgramArguments"][1:] == ["-m", "portalkit.ui.menubar"]

    launchagent.uninstall()
    assert not launchagent.installed()
