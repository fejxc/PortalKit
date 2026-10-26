"""生产 CredentialService：Keychain 存密码 + 侧车索引存"账号名"。

账号名不属于机密（UI 需要展示"已保存账号 xxx"），密码只在认证时经
SecKeychain API 读取，任何路径都不回显。
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from portalkit.adapters.base import Credentials
from portalkit.credentials import keychain

_INDEX_PATH = Path.home() / "Library" / "Application Support" / "PortalKit" / "accounts.json"


class KeychainCredentialService:
    def __init__(self, index_path: Path | None = None) -> None:
        self._path = index_path or _INDEX_PATH
        self._lock = threading.Lock()

    # ------------------------------------------------------------- index

    def _read_index(self) -> dict[str, str]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_index(self, index: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(index, fh, ensure_ascii=False, indent=2)

    @staticmethod
    def _key(adapter_id: str, host: str) -> str:
        return f"{adapter_id}:{host}"

    # -------------------------------------------------------------- api

    def usernames(self, adapter_id: str, host: str) -> list[str]:
        username = self._read_index().get(self._key(adapter_id, host), "")
        return [username] if username else []

    def get(self, adapter_id: str, host: str) -> Credentials | None:
        usernames = self.usernames(adapter_id, host)
        if not usernames:
            return None
        password = keychain.load(adapter_id, host, usernames[0])
        if password is None:
            return None
        return Credentials(username=usernames[0], password=password)

    def save(self, adapter_id: str, host: str, username: str, password: str) -> None:
        keychain.save(adapter_id, host, username, password)
        with self._lock:
            index = self._read_index()
            index[self._key(adapter_id, host)] = username
            self._write_index(index)

    def delete(self, adapter_id: str, host: str, username: str) -> bool:
        removed = keychain.delete(adapter_id, host, username)
        with self._lock:
            index = self._read_index()
            if index.pop(self._key(adapter_id, host), None) is not None or removed:
                self._write_index(index)
        return removed
