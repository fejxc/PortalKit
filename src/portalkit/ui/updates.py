"""GitHub Release 更新检查（用户主动触发，不做后台轮询、不自动安装）。"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass

RELEASES_API = "https://api.github.com/repos/fejxc/PortalKit/releases/latest"


@dataclass(frozen=True)
class UpdateInfo:
    latest_tag: str
    url: str
    has_update: bool


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


def check_for_update(current_version: str, timeout: float = 6.0) -> UpdateInfo | None:
    """查询最新 Release。网络失败返回 None（由调用方提示，不抛栈）。"""
    try:
        request = urllib.request.Request(
            RELEASES_API,
            headers={
                "User-Agent": "PortalKit-Update-Check",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            data = json.loads(resp.read(64_000).decode("utf-8"))
    except (OSError, ValueError):
        return None
    tag = str(data.get("tag_name") or "")
    if not tag:
        return None
    url = str(data.get("html_url") or RELEASES_API.replace("/releases/latest", "/releases"))
    return UpdateInfo(latest_tag=tag, url=url, has_update=is_newer(tag, current_version))
