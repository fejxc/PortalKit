"""ePortal 站点配置：内置站点 + 用户自定义站点（加校园 = 一份 JSON，免发版）。

文件位置：`~/Library/Application Support/PortalKit/eportal_sites.json`
格式（数组，每项一个站点）：

    [
      {
        "id": "xxu",
        "name": "某某大学",
        "entry_url": "http://10.20.30.40:8080/eportal/redirectortosuccess.jsp",
        "host_hint": "10.20.30.40"
      }
    ]

- `id`：小写字母/数字/`-`/`_`，2–32 字符。信任与凭据按它隔离，一旦
  在某网络建立信任，**不要再改**（改了等于全新适配器，需重新信任）。
- `entry_url`：可选。白名单放行探针域名的网络里 authenticate 的
  最后手段直连入口（可含会话参数占位，登录时以门户实际下发为准）。
- `host_hint`：可选。同网存在多个 ePortal 门户时防止 detect 误配。

非法条目跳过并打 stderr 警告——站点配置损坏绝不阻断应用启动。
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

from portalkit.adapters.eportal import EPortalAdapter

SITE_FILENAME = "eportal_sites.json"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")


def validate_site(raw: object) -> dict:
    """校验单个站点条目，返回规范化 dict；非法抛 ValueError。"""
    if not isinstance(raw, dict):
        raise ValueError("站点条目必须是对象")
    site_id = str(raw.get("id") or "").strip()
    if not _ID_RE.fullmatch(site_id):
        raise ValueError(f"id 非法（需小写字母/数字开头，2-32 位）: {site_id!r}")
    name = str(raw.get("name") or "").strip()
    if not name or len(name) > 40:
        raise ValueError("name 必须为 1-40 字符")
    entry_url = str(raw.get("entry_url") or "").strip()
    if entry_url:
        parts = urlsplit(entry_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"entry_url 必须是 http(s) URL: {entry_url!r}")
    host_hint = str(raw.get("host_hint") or "").strip()
    if host_hint:
        parts = urlsplit(f"//{host_hint}")
        if parts.hostname != host_hint or "/" in host_hint or "@" in host_hint:
            raise ValueError(f"host_hint 必须是纯主机名/IP: {host_hint!r}")
    return {
        "id": site_id,
        "name": name,
        "entry_url": entry_url,
        "host_hint": host_hint,
    }


def load_site_configs(state_dir: Path | None = None) -> list[dict]:
    """读取并校验用户站点配置；空/损坏/非法条目跳过（警告到 stderr）。"""
    path = (state_dir or Path.home() / "Library" / "Application Support" / "PortalKit") / SITE_FILENAME
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"[portalkit] 站点配置无法解析，已忽略: {path.name} ({type(exc).__name__})", file=sys.stderr, flush=True)
        return []
    if not isinstance(raw, list):
        print(f"[portalkit] 站点配置应为 JSON 数组，已忽略: {path.name}", file=sys.stderr, flush=True)
        return []
    sites: list[dict] = []
    seen: set[str] = set()
    for item in raw:
        try:
            site = validate_site(item)
        except ValueError as exc:
            print(f"[portalkit] 站点配置条目已跳过: {exc}", file=sys.stderr, flush=True)
            continue
        if site["id"] in seen:
            print(f"[portalkit] 站点 id 重复，保留首个: {site['id']}", file=sys.stderr, flush=True)
            continue
        seen.add(site["id"])
        sites.append(site)
    return sites


def adapter_from_site(site: dict) -> EPortalAdapter:
    normalized = validate_site(site)  # 裸 dict（如测试/手工调用）也在此规范化
    return EPortalAdapter(
        adapter_id=normalized["id"],
        name=normalized["name"],
        entry_url=normalized["entry_url"] or None,
        host_hint=normalized["host_hint"] or None,
    )


def adapters_from_sites(state_dir: Path | None = None) -> list[EPortalAdapter]:
    return [adapter_from_site(site) for site in load_site_configs(state_dir)]
