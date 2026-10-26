"""有界指数退避（STATE_MODEL.md §3）。

只对临时错误（NETWORK_ERROR 等 retryable 结果）退避重试；
密码错误 / 需交互 / 门户改版等永久错误由引擎直接转 WAITING_USER，不进入重试。
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    delays_s: tuple[float, ...] = (1.0, 2.0, 4.0)
    jitter: float = 0.3
    _rng: random.Random = field(default_factory=random.Random, repr=False, compare=False)

    def attempts(self) -> int:
        return self.max_attempts

    def next_delay(self, attempt_index: int) -> float:
        """attempt_index 从 0 计（第 0 次失败后的等待）。超过表长时取最后一档。"""
        if not self.delays_s:
            return 0.0
        base = self.delays_s[min(attempt_index, len(self.delays_s) - 1)]
        jitter = base * self.jitter
        return max(0.0, base + self._rng.uniform(-jitter, jitter))
