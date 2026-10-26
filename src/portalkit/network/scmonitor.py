"""SystemConfiguration 网络变化监听（Phase 2 事件源，替代轮询）。

监听 `State:/Network/Global/IPv4` 键：接口/IP/网关变化即回调。
独立线程跑 CFRunLoop；SystemConfiguration/PyObjC 不可用时静默降级为
"无事件"——宿主的低频兜底检查保证功能不受损（README 已记录）。
"""

from __future__ import annotations

import threading
from typing import Callable


class SCNetworkListener:
    def __init__(self, on_change: Callable[[], None]) -> None:
        self._on_change = on_change
        self._thread: threading.Thread | None = None
        self.started = False

    def start(self) -> bool:
        """启动监听线程；返回是否真正启用了 SC 事件（False = 已降级）。"""
        try:
            from CoreFoundation import (  # noqa: F401
                CFRunLoopAddSource,
                CFRunLoopGetCurrent,
                CFRunLoopRun,
                kCFRunLoopDefaultMode,
            )
            from SystemConfiguration import (
                SCDynamicStoreCreate,
                SCDynamicStoreCreateRunLoopSource,
                SCDynamicStoreSetNotificationKeys,
            )
        except Exception:  # noqa: BLE001 — 降级路径
            return False

        def sc_callback(_store, _changed_keys, _info) -> None:
            try:
                self._on_change()
            except Exception:  # noqa: BLE001 — 回调异常不能杀死 runloop
                pass

        def thread_body() -> None:
            store = SCDynamicStoreCreate(None, "PortalKit", sc_callback, None)
            if store is None:
                return
            SCDynamicStoreSetNotificationKeys(
                store, ["State:/Network/Global/IPv4"], []
            )
            source = SCDynamicStoreCreateRunLoopSource(None, store, 0)
            CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode)
            CFRunLoopRun()

        self._thread = threading.Thread(
            target=thread_body, name="portalkit-sc-listener", daemon=True
        )
        self._thread.start()
        self.started = True
        return True
