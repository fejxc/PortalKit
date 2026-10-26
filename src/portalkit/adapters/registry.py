"""适配器注册表。MVP 仅内置 zjlib / zstu（SECURITY §6：外部插件 P2）。"""

from __future__ import annotations

from portalkit.adapters.base import PortalAdapter


class AdapterRegistry:
    def __init__(self, adapters: list[PortalAdapter] | None = None) -> None:
        self._adapters: dict[str, PortalAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: PortalAdapter) -> None:
        if adapter.id in self._adapters:
            raise ValueError(f"适配器 id 冲突: {adapter.id}")
        self._adapters[adapter.id] = adapter

    def all(self) -> list[PortalAdapter]:
        return list(self._adapters.values())

    def get(self, adapter_id: str) -> PortalAdapter | None:
        return self._adapters.get(adapter_id)

    def ids(self) -> list[str]:
        return sorted(self._adapters)
