"""生成可双击的本地 PortalKit.app（LSUIElement 菜单栏应用）。

定位：个人使用级别的本地 bundle（未签名/未公证），双击或 `open -a PortalKit`
启动；正式签名分发是 Phase 3 事项。bundle 的启动器钉死 venv 解释器，
受菜单栏单实例守卫保护，与 LaunchAgent 启动方式互斥安全。
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path

APP_NAME = "PortalKit"
BUNDLE_ID = "com.fejxc.portalkit"


def default_install_dir() -> Path:
    applications = Path("/Applications")
    if os.access(applications, os.W_OK):
        return applications
    return Path.home() / "Applications"


def bundle_path(install_dir: Path | None = None) -> Path:
    return (install_dir or default_install_dir()) / f"{APP_NAME}.app"


def build_info_plist() -> dict:
    return {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleVersion": "0.2.0",
        "CFBundleShortVersionString": "0.2.0",
        "CFBundleExecutable": APP_NAME,
        "CFBundlePackageType": "APPL",
        "LSUIElement": True,  # 纯菜单栏应用：无 Dock 图标、无主窗口
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": "Local build",
    }


def _launcher_script(python_exe: str, log_file: Path) -> str:
    return (
        "#!/bin/sh\n"
        "# PortalKit 本地启动器：钉死 venv 解释器，日志与 launchd 版共用。\n"
        f'exec "{python_exe}" -m portalkit.ui.menubar >> "{log_file}" 2>&1\n'
    )


def _make_icns(source_png: Path, out_icns: Path, tmp_dir: Path) -> bool:
    """用 sips + iconutil 从状态图标生成 icns；任一环节失败返回 False。"""
    try:
        iconset = tmp_dir / "AppIcon.iconset"
        iconset.mkdir(parents=True, exist_ok=True)
        for size in (16, 32, 128, 256, 512):
            target = iconset / f"icon_{size}x{size}.png"
            subprocess.run(
                ["sips", "-z", str(size), str(size), str(source_png),
                 "--out", str(target)],
                capture_output=True, check=True,
            )
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset), "-o", str(out_icns)],
            capture_output=True, check=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def build_bundle(python_exe: str, install_dir: Path | None = None,
                 icons_dir: Path | None = None, log_file: Path | None = None) -> Path:
    root = bundle_path(install_dir)
    contents = root / "Contents"
    macos_dir = contents / "MacOS"
    resources_dir = contents / "Resources"
    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)

    info = build_info_plist()
    log = log_file or Path.home() / "Library/Logs/portalkit-ui.log"

    icons_dir = icons_dir or (Path.home() / "Library/Application Support/PortalKit/icons")
    source_icon = icons_dir / "status-ok.png"
    if source_icon.exists():
        icns = resources_dir / "AppIcon.icns"
        if _make_icns(source_icon, icns, contents):
            info["CFBundleIconFile"] = "AppIcon"

    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    launcher = macos_dir / APP_NAME
    launcher.write_text(_launcher_script(python_exe, log), encoding="utf-8")
    launcher.chmod(0o755)
    return root
