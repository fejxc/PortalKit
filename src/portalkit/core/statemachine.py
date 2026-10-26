"""Phase 状态机的合法转移表（STATE_MODEL.md §2）。

引擎每次 phase 变更都经过 assert_transition 校验，防止出现
"旧网络的认证结果写进新状态" 一类的非法路径。
"""

from __future__ import annotations

from portalkit.models import Phase

ALLOWED_TRANSITIONS: dict[Phase, frozenset[Phase]] = {
    Phase.IDLE: frozenset({Phase.DEBOUNCING, Phase.PROBING, Phase.ERROR}),
    Phase.DEBOUNCING: frozenset({Phase.PROBING, Phase.CANCELLED}),
    Phase.PROBING: frozenset(
        {
            Phase.MATCHING,
            Phase.ONLINE_NO_AUTH,
            Phase.ERROR,
            Phase.CANCELLED,
            Phase.RETRY_BACKOFF,
        }
    ),
    Phase.MATCHING: frozenset(
        {
            Phase.PROBING,
            Phase.ONLINE_NO_AUTH,
            Phase.TRUST_REQUIRED,
            Phase.AUTHENTICATING,
            Phase.WAITING_USER,
            Phase.ERROR,
            Phase.CANCELLED,
        }
    ),
    Phase.TRUST_REQUIRED: frozenset(
        {
            Phase.AUTHENTICATING,
            Phase.WAITING_USER,
            Phase.PROBING,
            Phase.CANCELLED,
            Phase.ERROR,
        }
    ),
    Phase.AUTHENTICATING: frozenset(
        {
            Phase.VERIFYING,
            Phase.RETRY_BACKOFF,
            Phase.WAITING_USER,
            Phase.ERROR,
            Phase.CANCELLED,
        }
    ),
    Phase.VERIFYING: frozenset(
        {
            Phase.ONLINE_AUTHENTICATED,
            Phase.DEGRADED,
            Phase.RETRY_BACKOFF,
            Phase.ERROR,
            Phase.CANCELLED,
        }
    ),
    Phase.ONLINE_AUTHENTICATED: frozenset(
        {
            Phase.PROBING, Phase.DEBOUNCING, Phase.IDLE,
            Phase.ERROR, Phase.CANCELLED, Phase.WAITING_USER,
        }
    ),
    Phase.ONLINE_NO_AUTH: frozenset(
        {
            Phase.PROBING, Phase.DEBOUNCING, Phase.IDLE,
            Phase.ERROR, Phase.CANCELLED, Phase.WAITING_USER,
        }
    ),
    Phase.DEGRADED: frozenset(
        {
            Phase.PROBING,
            Phase.AUTHENTICATING,
            Phase.VERIFYING,
            Phase.RETRY_BACKOFF,
            Phase.WAITING_USER,
            Phase.IDLE,
            Phase.ERROR,
            Phase.CANCELLED,
        }
    ),
    Phase.ERROR: frozenset({Phase.PROBING, Phase.DEBOUNCING, Phase.IDLE, Phase.WAITING_USER}),
    Phase.CANCELLED: frozenset({Phase.PROBING, Phase.DEBOUNCING, Phase.IDLE}),
    Phase.WAITING_USER: frozenset(
        {
            Phase.AUTHENTICATING, Phase.PROBING, Phase.DEBOUNCING, Phase.IDLE,
            Phase.CANCELLED, Phase.ERROR,
        }
    ),
    Phase.RETRY_BACKOFF: frozenset(
        {
            Phase.AUTHENTICATING,
            Phase.VERIFYING,
            Phase.PROBING,
            Phase.CANCELLED,
            Phase.ERROR,
        }
    ),
}


class InvalidTransition(RuntimeError):
    pass


def assert_transition(current: Phase, nxt: Phase) -> None:
    if current == nxt:
        return
    allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
    if nxt not in allowed:
        raise InvalidTransition(f"非法状态转移: {current.value} -> {nxt.value}")
