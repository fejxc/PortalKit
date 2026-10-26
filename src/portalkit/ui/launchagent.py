"""用户级 LaunchAgent（PRD F15：登录启动，不用守护服务提权）。

plist 写入 ~/Library/LaunchAgents/com.fejxc.portalkit.plist；
加载用现代 `launchctl bootstrap/bootout gui/<uid>`。
`build_plist` 为纯函数（可测试）；install/uninstall 封装 subprocess。
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from pathlib import Path

LABEL = "com.fejxc.portalkit"
LOG_SUBPATH = "Library/Logs/portalkit-ui.log"


def launchagents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def plist_path() -> Path:
    return launchagents_dir() / f"{LABEL}.plist"


def log_path() -> Path:
    return Path.home() / LOG_SUBPATH


def build_plist(program_args: list[str], log_file: str) -> dict:
    """纯函数：返回 plist 字典（ProgramArguments 由调用方决定）。"""
    return {
        "Label": LABEL,
        "ProgramArguments": program_args,
        "RunAtLoad": True,
        "KeepAlive": False,  # 菜单栏应用崩溃不自动复活，避免僵尸循环；用户可手动重开
        "ProcessType": "Interactive",
        "StandardOutPath": log_file,
        "StandardErrorPath": log_file,
        "EnvironmentVariables": {"PORTALKIT_LAUNCHED_BY": "launchd"},
    }


def _program_args() -> list[str]:
    """优先使用已部署的独立 bundle；开发态回退 venv 解释器。"""
    from portalkit.ui.appbundle import bundle_executable

    exe = bundle_executable()
    if exe:
        return [str(exe)]
    return [sys.executable, "-m", "portalkit.ui.menubar"]


def installed() -> bool:
    return plist_path().exists()


def install() -> bool:
    plist = build_plist(_program_args(), str(log_path()))
    plist_path().parent.mkdir(parents=True, exist_ok=True)
    plist_path().write_bytes(plistlib.dumps(plist))
    return _start()


def uninstall() -> None:
    _stop()
    plist_path().unlink(missing_ok=True)


def _gui_target() -> str:
    return f"gui/{os.getuid()}"


def _start() -> bool:
    subprocess.run(
        ["launchctl", "bootout", _gui_target(), str(plist_path())],
        capture_output=True, check=False,
    )
    proc = subprocess.run(
        ["launchctl", "bootstrap", _gui_target(), str(plist_path())],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def _stop() -> None:
    subprocess.run(
        ["launchctl", "bootout", _gui_target(), str(plist_path())],
        capture_output=True, check=False,
    )


def status() -> str:
    if not installed():
        return "not-installed"
    proc = subprocess.run(
        ["launchctl", "print", f"{_gui_target()}/{LABEL}"],
        capture_output=True, text=True, check=False,
    )
    if proc.returncode == 0 and "state = 3" not in proc.stdout:
        return "running"
    return "installed"
