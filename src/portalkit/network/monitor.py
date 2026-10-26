"""NetworkMonitor：network_generation 的来源。

P0（CLI 阶段）：按需采样 + 快照指纹对比，指纹变化即递增 generation；
事件监听（SCDynamicStore via PyObjC）在 Phase 2 UI 宿主接入，本类的
`current_snapshot()` 接口保持不变，UI 层直接替换实现。

并发：同一 engine 任务的各网络步骤之间调用 `has_changed_since(gen)`，
变化即抛 GenerationStale 取消旧任务（STATE_MODEL §2 转移规则）。
"""

from __future__ import annotations

import threading

from portalkit.network.interfaces import build_snapshot
from portalkit.network.interfaces import NetworkSnapshot  # noqa: F401  再导出


class GenerationStale(RuntimeError):
    """网络代际已变化，当前任务必须取消。"""

    def __init__(self, old: int, new: int) -> None:
        super().__init__(f"network_generation 已从 {old} 变为 {new}，任务取消")
        self.old = old
        self.new = new


class NetworkMonitor:
    def __init__(self, interface: str | None = None) -> None:
        self._lock = threading.Lock()
        self._interface = interface
        self._last_fingerprint: str | None = None
        self._generation = 0
        self._last_snapshot: NetworkSnapshot | None = None

    def current_snapshot(self) -> NetworkSnapshot:
        snap = build_snapshot(self._interface)
        with self._lock:
            if snap.fingerprint != self._last_fingerprint:
                self._last_fingerprint = snap.fingerprint
                self._generation += 1
            self._last_snapshot = snap
            return snap

    def current_generation(self) -> int:
        with self._lock:
            return self._generation

    def has_changed_since(self, generation: int) -> bool:
        return self.current_generation() != generation

    def check_generation(self, generation: int) -> None:
        """适配器在每网络步之间调用；代际过期抛 GenerationStale。"""
        current = self.current_generation()
        if current != generation:
            raise GenerationStale(generation, current)

    def request_cancel(self) -> None:
        """外部取消：立即递增 generation，使在途任务在下一个边界失效。"""
        with self._lock:
            self._generation += 1
