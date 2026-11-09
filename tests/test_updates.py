"""更新检查与一键安装：版本比较、API 解析、下载、bundle 替换（不联网）。"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from portalkit.ui import updates as upd
from portalkit.ui.updates import UpdateInfo, check_for_update, is_newer


def test_is_newer_semantics():
    assert is_newer("v1.0.1", "1.0.0")
    assert is_newer("v1.1.0", "1.0.9")
    assert is_newer("1.0", "1.0.0") is False  # 1.0 == 1.0.0
    assert is_newer("v1.0.0", "1.0.0") is False
    assert is_newer("v0.9", "1.0.0") is False
    assert is_newer("garbage", "1.0.0") is False


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _patch_urlopen(monkeypatch, payloads: dict[str, bytes]):
    import urllib.request

    def fake_urlopen(request, timeout=None):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if url not in payloads:
            raise OSError(f"unexpected url {url}")
        return _FakeResponse(payloads[url])

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


_PAYLOAD = json.dumps({
    "tag_name": "v9.9.9",
    "html_url": "https://github.com/fejxc/PortalKit/releases/tag/v9.9.9",
    "assets": [
        {"name": "PortalKit-9.9.9-macos-arm64.zip",
         "browser_download_url": "https://github.com/fejxc/PortalKit/releases/download/v9.9.9/PortalKit-9.9.9-macos-arm64.zip"},
        {"name": "checksums.txt", "browser_download_url": "https://example.com/checksums.txt"},
    ],
}).encode()


def test_check_for_update_extracts_arm64_asset(monkeypatch):
    _patch_urlopen(monkeypatch, {
        "https://api.github.com/repos/fejxc/PortalKit/releases/latest": _PAYLOAD,
    })
    info = check_for_update("1.0.1")
    assert info is not None
    assert info.has_update
    assert info.asset_url and info.asset_url.endswith("PortalKit-9.9.9-macos-arm64.zip")


def test_check_for_update_no_update_means_no_asset(monkeypatch):
    _patch_urlopen(monkeypatch, {
        "https://api.github.com/repos/fejxc/PortalKit/releases/latest": _PAYLOAD,
    })
    info = check_for_update("9.9.9")
    assert info is not None
    assert not info.has_update
    assert info.asset_url is None  # 无更新就不引导安装


def test_check_for_update_payload_without_assets(monkeypatch):
    _patch_urlopen(monkeypatch, {
        "https://api.github.com/repos/fejxc/PortalKit/releases/latest":
            b'{"tag_name": "v1.2.0", "html_url": "https://github.com/fejxc/PortalKit/releases/tag/v1.2.0"}',
    })
    info = check_for_update("1.0.1")
    assert info is not None and info.has_update and info.asset_url is None

    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert check_for_update("1.0.1") is None  # 网络失败静默为 None


# ------------------------------------------------------------- telemetry (F)

def test_check_for_update_telemetry_header_opt_in(monkeypatch):
    """遥测默认关：传 None 时请求绝不含 X-PortalKit-Stats 头。"""
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        return _FakeResponse(_PAYLOAD)

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    check_for_update("1.3.0")  # 不传 telemetry
    assert "x-portalkit-stats" not in captured["headers"]
    assert captured["headers"]["user-agent"] == "PortalKit-Update-Check/1.3.0"

    telemetry = {"checks": 12, "auth_total": 3, "auth_ok": 2, "auth_fail": 1,
                 "top_fail_code": "invalid_credentials"}
    check_for_update("1.3.0", telemetry=telemetry)
    sent = json.loads(captured["headers"]["x-portalkit-stats"])
    assert sent == telemetry  # 原样透传，无任何附加字段


def test_check_for_update_telemetry_none_means_no_header(monkeypatch):
    """telemetry=None（今日无数据）同样不带头。"""
    captured = {}

    def fake_urlopen(request, timeout=None):
        captured["headers"] = {k.lower(): v for k, v in request.header_items()}
        return _FakeResponse(_PAYLOAD)

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    check_for_update("1.3.0", telemetry=None)
    assert "x-portalkit-stats" not in captured["headers"]


# ---------------------------------------------------------------- download

def test_download_update_writes_file(monkeypatch, tmp_path):
    body = b"PK-zip-bytes" * 100
    _patch_urlopen(monkeypatch, {"https://dl.example/PortalKit-9.9.9-macos-arm64.zip": body})
    dest = tmp_path / "update.zip"
    assert upd.download_update("https://dl.example/PortalKit-9.9.9-macos-arm64.zip", dest) == dest
    assert dest.read_bytes() == body


def test_download_update_network_failure_cleans_up(monkeypatch, tmp_path):
    import urllib.request

    monkeypatch.setattr(
        urllib.request, "urlopen",
        lambda *a, **k: (_ for _ in ()).throw(OSError("boom")),
    )
    dest = tmp_path / "update.zip"
    assert upd.download_update("https://dl.example/x.zip", dest) is None
    assert not dest.exists()


# ------------------------------------------------------------ install/replace

def _make_running_bundle(base_dir):
    """构造一个"运行中"的假 .app（含 Contents/MacOS 可执行）。"""
    bundle = base_dir / "PortalKit.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    (bundle / "Contents" / "MacOS" / "PortalKit").write_text("#!/bin/sh\n")
    return bundle


def _make_update_zip(path, app_name="PortalKit.app", version_file=True):
    with zipfile.ZipFile(path, "w") as zf:
        exe = f"{app_name}/Contents/MacOS/PortalKit"
        zf.writestr(exe, "#!/bin/sh\nnew build\n")
        if version_file:
            zf.writestr(f"{app_name}/Contents/version.txt", "9.9.9")


def _allow_verify(monkeypatch, allowed=True):
    monkeypatch.setattr(upd, "verify_bundle", lambda _p: allowed)


def test_install_update_replaces_bundle(tmp_path, monkeypatch):
    running = _make_running_bundle(tmp_path / "Applications")
    zip_path = tmp_path / "update.zip"
    _make_update_zip(zip_path)
    _allow_verify(monkeypatch)
    backup_dir = tmp_path / "backup"

    new_app = upd.install_update(zip_path, running, backup_dir=backup_dir)
    assert new_app == tmp_path / "Applications" / "PortalKit.app"
    assert new_app.is_dir()
    assert b"new build" in (new_app / "Contents" / "MacOS" / "PortalKit").read_bytes()
    # 旧版完整保留在备份（更新失败可人工复位）
    old_exe = backup_dir / "PortalKit.app" / "Contents" / "MacOS" / "PortalKit"
    assert old_exe.exists() and b"new build" not in old_exe.read_bytes()


def test_install_update_moves_old_back_on_failure(tmp_path, monkeypatch):
    """新版 mv 进 dest 失败 → 旧版必须复位（更新永不留半成品）。"""
    running = _make_running_bundle(tmp_path / "Applications")
    zip_path = tmp_path / "update.zip"
    _make_update_zip(zip_path)
    _allow_verify(monkeypatch)

    import shutil as _shutil

    real_move = _shutil.move
    calls = {"n": 0}

    def failing_move(src, dst):
        calls["n"] += 1
        if calls["n"] == 2:  # 第一次=旧版进备份，第二次=新版进 dest → 制造失败
            raise OSError("disk full")
        return real_move(src, dst)

    monkeypatch.setattr(upd.shutil, "move", failing_move)
    assert upd.install_update(zip_path, running, backup_dir=tmp_path / "backup") is None
    # 旧版复位：可执行仍在原位
    assert (running / "Contents" / "MacOS" / "PortalKit").exists()


def test_install_update_rejects_bad_signature(tmp_path, monkeypatch):
    running = _make_running_bundle(tmp_path / "Applications")
    zip_path = tmp_path / "update.zip"
    _make_update_zip(zip_path)
    _allow_verify(monkeypatch, allowed=False)
    assert upd.install_update(zip_path, running, backup_dir=tmp_path / "backup") is None
    assert running.exists()  # 旧版原封不动


def test_install_update_rejects_corrupt_zip(tmp_path, monkeypatch):
    running = _make_running_bundle(tmp_path / "Applications")
    zip_path = tmp_path / "update.zip"
    zip_path.write_bytes(b"this is not a zip file")
    _allow_verify(monkeypatch)
    assert upd.install_update(zip_path, running, backup_dir=tmp_path / "backup") is None
    assert running.exists()


def test_install_update_rejects_zip_without_app(tmp_path, monkeypatch):
    running = _make_running_bundle(tmp_path / "Applications")
    zip_path = tmp_path / "update.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("README.txt", "no app here")
    _allow_verify(monkeypatch)
    assert upd.install_update(zip_path, running, backup_dir=tmp_path / "backup") is None


def test_running_bundle_path_detection(tmp_path):
    bundle = _make_running_bundle(tmp_path)
    exe = bundle / "Contents" / "MacOS" / "PortalKit"
    assert upd.running_bundle_path(exe) == bundle
    plain = tmp_path / "script.py"
    plain.write_text("")
    assert upd.running_bundle_path(plain) is None


def test_verify_bundle_invokes_codesign(monkeypatch, tmp_path):
    import subprocess

    recorded = {}

    def fake_run(args, **kwargs):
        recorded["args"] = args
        return type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert upd.verify_bundle(tmp_path / "whatever.app")
    assert recorded["args"][:3] == ["codesign", "--verify", "--deep"]
