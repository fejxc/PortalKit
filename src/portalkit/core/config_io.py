"""配置导出/导入（不含凭据）：换机迁移用。

导出 = 信任记录 + 用户设置的 JSON（0600）；凭据只存在于 Keychain，
永远不进入导出文件。导入 = 合并覆盖（信任记录按 key 覆盖、设置按
已知键白名单合并）。导入的是"信任"，文件须由用户手动选择，界面二次确认。
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from portalkit.core.settings import ALLOWED_INTERVALS_S, SettingsStore
from portalkit.core.trust import TrustRecord, TrustRegistry

SCHEMA = 1
_SETTING_KEYS = ("auto_auth", "notify_on_error", "check_interval_s")


def export_config(trust: TrustRegistry, settings: SettingsStore, path: Path) -> int:
    """导出到 path，返回导出的信任记录数。"""
    payload = {
        "schema": SCHEMA,
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "settings": asdict(settings.get()),
        "trust": [asdict(r) for r in trust.all()],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return len(payload["trust"])


def _record_from_dict(item: dict) -> TrustRecord:
    return TrustRecord(
        adapter_id=str(item["adapter_id"]),
        portal_host=str(item["portal_host"]),
        portal_port=int(item.get("portal_port", 0)),
        scheme=str(item.get("scheme", "https")),
        allowed_hosts=tuple(item.get("allowed_hosts") or ()),
        cert_sha256=item.get("cert_sha256"),
        fingerprint=item.get("fingerprint"),
        network_hint=str(item.get("network_hint", "")),
        created_at=str(item.get("created_at", "")),
        note=str(item.get("note", "")),
        auto_auth=bool(item.get("auto_auth", True)),
        last_connected_at=str(item.get("last_connected_at", "")),
        last_auth_ok_at=str(item.get("last_auth_ok_at", "")),
        session_lifetime_samples=tuple(item.get("session_lifetime_samples") or ()),
    )


def import_config(trust: TrustRegistry, settings: SettingsStore, path: Path) -> tuple[int, int]:
    """从 path 合并导入，返回 (导入的信任记录数, 应用的设置项数)。

    抛 ValueError = 文件不是合法的 PortalKit 配置；抛 OSError = 读取失败。
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("不是 PortalKit 导出的配置文件（schema 不符）")

    records = data.get("trust", [])
    if not isinstance(records, list):
        raise ValueError("trust 字段格式异常")
    count = 0
    for item in records:
        trust.add(_record_from_dict(item))
        count += 1

    applied = 0
    raw_settings = data.get("settings", {})
    if isinstance(raw_settings, dict):
        changes = {}
        for key in _SETTING_KEYS:
            if key not in raw_settings:
                continue
            if key == "check_interval_s":
                if raw_settings[key] in ALLOWED_INTERVALS_S:
                    changes[key] = raw_settings[key]
            else:
                changes[key] = bool(raw_settings[key])
        settings.update(**changes)
        applied = len(changes)
    return count, applied
