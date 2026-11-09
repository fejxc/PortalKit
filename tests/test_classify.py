"""共享失败分类器：门户文案 → 失败码 + 行动指引。

模式表按序匹配是行为契约：欠费文案常含"账号"，账号状态类必须先于凭据类。
"""

from __future__ import annotations

import pytest

from portalkit.adapters.classify import classify_portal_message
from portalkit.models import AuthCode


def test_arrears_message_before_credential_tokens():
    """欠费文案含"账号"二字 → 必须归类账号受限，不是凭据错误。"""
    code, hint = classify_portal_message("认证失败：账号已欠费，请充值后重试")
    assert code == AuthCode.ACCOUNT_LOCKED
    assert "自助服务" in hint


def test_locked_message():
    code, _ = classify_portal_message("Your account has been locked by administrator")
    assert code == AuthCode.ACCOUNT_LOCKED


def test_quota_message():
    code, hint = classify_portal_message("登录失败：终端数已达上限")
    assert code == AuthCode.AUTH_QUOTA
    assert "其他设备" in hint


def test_account_online_elsewhere_is_quota():
    """单设备学校"账号已在线"= 会话冲突（互踢前兆）→ 归设备上限类。"""
    code, _ = classify_portal_message("用户已经在线，不能重复登录")
    assert code == AuthCode.AUTH_QUOTA


def test_credential_message():
    code, hint = classify_portal_message("密码错误，请重新输入")
    assert code == AuthCode.INVALID_CREDENTIALS
    assert "凭据" in hint


def test_english_credential_message():
    assert classify_portal_message("Invalid username or password")[0] == AuthCode.INVALID_CREDENTIALS


@pytest.mark.parametrize("text", [
    "",
    "system error page",
    "门户开小差了，请稍后再试",
    "result=fail",
])
def test_unmatched_returns_none(text):
    """拿不准必须返回 None（落回 UNKNOWN_ERROR），不为凑分类放宽匹配。"""
    assert classify_portal_message(text) is None


def test_case_insensitive_english():
    assert classify_portal_message("IP Has Been Online Already")[0] == AuthCode.AUTH_QUOTA
