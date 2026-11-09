"""GitHub Release 更新检查与一键安装。

v1.3 起：后台检查（默认开，仅提醒）+ 菜单横幅 + 一键下载替换 .app。
安装流程：下载 zip → 解压 → codesign 完整性校验 → 运行中 bundle 原位
替换（旧版移入备份目录）→ 调用方负责重启。任何环节失败都安全退出
（旧版保持原位不受影响），不自动回滚半成品。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

RELEASES_API = "https://api.github.com/repos/fejxc/PortalKit/releases/latest"
ASSET_PATTERN = re.compile(r"PortalKit-.+-macos-arm64\.zip$")
# 自替换旧版本的备份位置（重启不丢；下次更新时清理）
UPDATE_BACKUP_DIR = Path.home() / "Library" / "Caches" / "PortalKit" / "update-backup"


@dataclass(frozen=True)
class UpdateInfo:
    latest_tag: str
    url: str
    has_update: bool
    asset_url: str | None = None  # Release zip 资产（一键安装用）；缺失回退网页手动装


def _parse_version(tag: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)", tag.strip())
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def is_newer(latest_tag: str, current: str) -> bool:
    latest = _parse_version(latest_tag)
    cur = _parse_version(current)
    if latest is None or cur is None:
        return False
    width = max(len(latest), len(cur))
    latest += (0,) * (width - len(latest))
    cur += (0,) * (width - len(cur))
    return latest > cur


def _asset_url(payload: dict) -> str | None:
    for asset in payload.get("assets") or []:
        if ASSET_PATTERN.search(str(asset.get("name") or "")):
            return str(asset.get("browser_download_url") or "") or None
    return None


def check_for_update(current_version: str, timeout: float = 6.0,
                     telemetry: dict | None = None) -> UpdateInfo | None:
    """查询最新 Release。网络失败返回 None（由调用方提示，不抛栈）。

    telemetry：可选匿名聚合摘要（Settings.share_anonymous_stats 默认关；
    开启时随请求附 X-PortalKit-Stats 头）。只含计数与失败码，无任何
    用户标识。当前 GitHub API 不消费该头——它是自建遥测端点启用前的
    数据格式预留，同时让请求可被服务端日志按需统计。
    """
    headers = {
        "User-Agent": f"PortalKit-Update-Check/{current_version}",
        "Accept": "application/vnd.github+json",
    }
    if telemetry:
        headers["X-PortalKit-Stats"] = json.dumps(telemetry, ensure_ascii=True, sort_keys=True)
    request = urllib.request.Request(RELEASES_API, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            data = json.loads(resp.read(256_000).decode("utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    tag = str(data.get("tag_name") or "")
    if not tag:
        return None
    url = str(data.get("html_url") or RELEASES_API.replace("/releases/latest", "/releases"))
    return UpdateInfo(
        latest_tag=tag, url=url, has_update=is_newer(tag, current_version),
        asset_url=_asset_url(data) if is_newer(tag, current_version) else None,
    )


def download_update(asset_url: str, dest: Path, timeout: float = 300.0) -> Path | None:
    """下载 Release zip 到 dest；网络/写入失败返回 None（不抛栈）。"""
    request = urllib.request.Request(
        asset_url, headers={"User-Agent": "PortalKit-Update-Download"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp, \
                dest.open("wb") as fh:
            while chunk := resp.read(256_000):
                fh.write(chunk)
        return dest if dest.stat().st_size > 0 else None
    except OSError:
        dest.unlink(missing_ok=True)
        return None


def verify_bundle(app_path: Path) -> bool:
    """codesign 完整性校验（ad-hoc/正式签名都适用）；损坏即拒绝安装。"""
    proc = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", str(app_path)],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0


def install_update(zip_path: Path, running_bundle: Path,
                   backup_dir: Path = UPDATE_BACKUP_DIR) -> Path | None:
    """把下载好的 zip 原位替换进 running_bundle 所在目录。

    安全序：解压 → 校验 .app 存在 → codesign verify → 旧版移入备份 →
    新版移入。跨卷 mv 回退 copytree。任一步失败返回 None，旧版不受影响。
    """
    if not running_bundle.is_dir() or running_bundle.suffix != ".app":
        return None
    staging = Path(tempfile.mkdtemp(prefix="portalkit-update-"))
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(staging)
        new_app = next(iter(sorted(staging.glob("*.app"))), None)
        if new_app is None or not (new_app / "Contents" / "MacOS").is_dir():
            return None
        if not verify_bundle(new_app):
            return None
        dest_dir = running_bundle.parent
        if dest_dir.stat().st_dev != staging.stat().st_dev:
            return None  # 跨卷：mv 语义不可靠，交给手动安装，不做半吊子 copy
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / running_bundle.name
        if backup.exists():
            shutil.rmtree(backup)
        shutil.move(str(running_bundle), str(backup))
        try:
            shutil.move(str(new_app), str(dest_dir / running_bundle.name))
        except OSError:
            shutil.move(str(backup), str(running_bundle))  # 回滚：旧版复位
            return None
        return dest_dir / running_bundle.name
    except (OSError, zipfile.BadZipFile, shutil.Error):
        return None
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def running_bundle_path(executable: Path | None = None) -> Path | None:
    """当前运行中的 .app 目录（PyInstaller frozen）；非 bundle 环境返回 None。"""
    if executable is None:
        exe = Path(sys.executable if getattr(sys, "frozen", False) else __file__)
    else:
        exe = executable
    for parent in (exe, *exe.parents):
        if parent.suffix == ".app" and (parent / "Contents").is_dir():
            return parent
    return None
