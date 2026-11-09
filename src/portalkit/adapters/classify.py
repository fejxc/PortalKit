"""门户失败文案 → 失败码 + 恢复提示（跨适配器共享）。

背景（2026-11 评审）：认证失败是高频事件（改密/欠费/锁定/单设备互踢），
只报"认证失败"等于让用户抓瞎。本模块把门户返回的消息归类为少量
**可行动**的失败码，每个码带一句 ≤40 字的行动指引（AuthResult.recovery_hint）。

原则：
- 欠费/锁定类消息常含"账号"二字，**先**查账号状态类再查凭据类；
- 拿不准就返回 None，让适配器落回 UNKNOWN_ERROR（门户原话进 evidence），
  绝不为凑分类而放宽匹配；
- 只做关键词匹配，不碰任何网络逻辑——纯函数，测试即文档。
"""

from __future__ import annotations

from portalkit.models import AuthCode

# 每类：(关键词元组, 失败码, 恢复提示)。顺序即优先级：账号状态 > 设备上限 > 凭据。
_PATTERNS: tuple[tuple[tuple[str, ...], AuthCode, str], ...] = (
    # 账号状态异常：欠费/停机/锁定/冻结/黑名单/违规（含英文门户常见词）
    (
        ("欠费", "停机", "锁定", "冻结", "黑名单", "违规", "余额", "已禁用",
         "suspended", "frozen", "locked", "arrears", "overdue", "balance", "disabled"),
        AuthCode.ACCOUNT_LOCKED,
        "账号受限（欠费/锁定/停机）：请到学校自助服务网站处理",
    ),
    # 设备/会话数上限：单设备学校"账号已在别处在线"也归此类（互踢前兆）
    (
        ("上限", "已达", "终端数", "设备数", "在线数", "超出", "并发",
         "已在线", "已经在线", "exceeded", "maximum", "concurrent",
         "already logged in", "already online", "online already", "been online"),
        AuthCode.AUTH_QUOTA,
        "已达在线设备上限：请先在其他设备上注销校园网",
    ),
    # 凭据错误
    (
        ("密码", "用户名", "账号", "password", "username", "invalid user", "user not found", "auth fail"),
        AuthCode.INVALID_CREDENTIALS,
        "账号或密码被门户拒绝：若改过密码请更新凭据",
    ),
)

MESSAGE_KEY_BY_CODE = {
    AuthCode.INVALID_CREDENTIALS: "error.invalid_creds",
    AuthCode.ACCOUNT_LOCKED: "error.account_locked",
    AuthCode.AUTH_QUOTA: "error.auth_quota",
}


def classify_portal_message(message: str) -> tuple[AuthCode, str] | None:
    """门户失败消息 → (失败码, 恢复提示)；无把握返回 None。

    message 为门户返回的用户可见文案（适配器已做长度截断）；
    大小写不敏感（英文门户），中文不受影响。
    """
    lowered = (message or "").lower()
    if not lowered:
        return None
    for tokens, code, hint in _PATTERNS:
        if any(token in lowered for token in tokens):
            return code, hint
    return None
