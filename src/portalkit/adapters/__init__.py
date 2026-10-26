"""PortalKit 适配器层。"""

from portalkit.adapters.registry import AdapterRegistry
from portalkit.adapters.zjlib import ZjlibAdapter
from portalkit.adapters.zstu import ZstuAdapter

__all__ = ["AdapterRegistry", "ZjlibAdapter", "ZstuAdapter"]


def default_registry() -> AdapterRegistry:
    return AdapterRegistry([ZjlibAdapter(), ZstuAdapter()])
