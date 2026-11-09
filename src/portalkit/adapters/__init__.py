"""PortalKit 适配器层。"""

from pathlib import Path

from portalkit.adapters.eportal import EPortalAdapter
from portalkit.adapters.registry import AdapterRegistry
from portalkit.adapters.zjlib import ZjlibAdapter
from portalkit.adapters.zstu import ZstuAdapter

__all__ = [
    "AdapterRegistry",
    "EPortalAdapter",
    "ZjlibAdapter",
    "ZstuAdapter",
]


def default_registry(state_dir: Path | None = None) -> AdapterRegistry:
    """内置适配器 + 用户自定义 ePortal 站点（eportal_sites.json，免发版加校园）。

    站点配置的加载/校验失败绝不阻断注册表构建（启动路径红线）。
    """
    import sys

    from portalkit.adapters import eportal_sites

    adapters: list = [ZjlibAdapter(), ZstuAdapter()]
    try:
        adapters.extend(eportal_sites.adapters_from_sites(state_dir))
    except Exception as exc:  # noqa: BLE001 — 配置层任何意外都不拦启动
        print(f"[portalkit] 自定义站点加载失败，已忽略: {type(exc).__name__}: {exc}",
              file=sys.stderr, flush=True)
    return AdapterRegistry(adapters)
