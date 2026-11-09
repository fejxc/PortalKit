"""窗口构造冒烟测试：在无 run loop 的 AppKit 环境下实例化全部窗口。

动机：2026-10-26 现场 OnboardingWindow 因 _checkbox 漏参 TypeError 导致
菜单点击静默无反应——此类构造期错误必须在 CI 抓住。
"""

from __future__ import annotations

import pytest

AppKit = pytest.importorskip("AppKit")

from AppKit import NSApplication  # noqa: E402

from portalkit.core.settings import SettingsStore  # noqa: E402
from portalkit.core.trust import TrustRecord, TrustRegistry  # noqa: E402
from portalkit.credentials.service import KeychainCredentialService  # noqa: E402
from portalkit.ui.menubar import UIContext  # noqa: E402
from portalkit.ui.windows import (  # noqa: E402
    CredentialsWindow,
    DiagnosticsWindow,
    ManagerWindow,
    OnboardingWindow,
    SettingsWindow,
    _fmt_expiry,
    _group_hex,
    _readable_events,
    _resolve_username,
    mask_username,
)


@pytest.fixture(scope="module")
def app_shell():
    NSApplication.sharedApplication()  # 控件构造所需的最低环境
    yield


@pytest.fixture()
def ctx(tmp_path):
    c = UIContext(
        engine=None,
        monitor=None,
        trust=TrustRegistry(tmp_path / "trust"),
        credentials=KeychainCredentialService(index_path=tmp_path / "accounts.json"),
        settings=SettingsStore(tmp_path / "settings.json"),
        state_dir=tmp_path,
    )
    c.logger = None
    return c


def test_all_windows_construct(app_shell, ctx):
    onboarding = OnboardingWindow(ctx)
    creds = CredentialsWindow(ctx)
    manager = ManagerWindow(ctx)
    diag = DiagnosticsWindow(ctx)
    settings = SettingsWindow(ctx)
    for win in (onboarding, creds, manager, diag, settings):
        assert win.win is not None


def test_credentials_window_refresh_empty(app_shell, ctx):
    creds = CredentialsWindow(ctx)
    creds.refresh()  # 无信任记录时不抛
    assert creds._selected() is None


def test_diagnostics_window_renders_without_state(app_shell, ctx):
    diag = DiagnosticsWindow(ctx)
    diag.refresh()  # 无 engine/state 时仍应渲染文本


# ------------------------------------------------ v1.3.1 展示层修复回归

def test_fmt_expiry_marks_past_time(app_shell):
    """学习值过期后必须明说"已过期"，不得以现在时误导（P1-1）。"""
    text = _fmt_expiry("2026-11-06T20:13:30+00:00")
    assert text is not None and text.startswith("已于") and "过期" in text


def test_fmt_expiry_future_renders_short_local(app_shell):
    from datetime import datetime, timedelta, timezone

    future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
    text = _fmt_expiry(future)
    assert text is not None and text.startswith("已于") is False
    assert len(text) == 11  # MM-DD HH:MM


def test_fmt_expiry_invalid_and_none(app_shell):
    assert _fmt_expiry(None) is None
    assert _fmt_expiry("") is None
    assert _fmt_expiry("not-a-date") is None  # 坏 ISO 不给用户看


def test_group_hex_splits_64_bit_fingerprint(app_shell):
    fp = ("1d62ed2bc37dfe194cedea1399ac2b57446f3b2d35cf182dbc5d5b189edf5af0")[:64]
    grouped = _group_hex(fp)
    assert grouped == " ".join(fp[i:i + 16] for i in range(0, 64, 16))
    assert _group_hex("short-value") == "short-value"  # 非 64hex 原样
    assert _group_hex(None) == ""


def test_mask_username_keeps_head_and_tail(app_shell):
    masked = mask_username("362323199801071710")
    assert masked.startswith("36") and masked.endswith("1710")
    assert "•" in masked and len(masked) == 18
    assert mask_username("stu001") == "stu001"  # 短账号原样
    assert mask_username("") == ""


def test_resolve_username_roundtrip(app_shell):
    real = "362323199801071710"
    assert _resolve_username(mask_username(real), real) == real  # 未改打码 → 还原
    assert _resolve_username("newid123", real) == "newid123"     # 换账号
    import pytest
    with pytest.raises(ValueError):
        _resolve_username("36••••wrong", real)  # 含掩码字符但非打码显示
    assert _resolve_username("stu001", "") == "stu001"


def test_readable_events_merges_repeated_states(app_shell, ctx):
    """连续相同的正常状态折叠为 ×N，时间线不再被刷屏（P1-3）。"""
    for i in range(5):
        (ctx.state_dir / "events.jsonl").open("a", encoding="utf-8").write(
            '{"event":"state","ts":"2026-11-10T18:0%d:00.000+00:00",'
            '"phase":"ONLINE_NO_AUTH","error":"none"}\n' % i
        )
    lines = _readable_events(ctx, tail=40)
    assert sum("已联网" in line for line in lines) == 1
    assert any("×5" in line for line in lines)


def test_credentials_window_masks_saved_username(app_shell, ctx, monkeypatch):
    """已存长账号在凭据窗口显示为掩码（P3 瞥屏防护）。"""
    ctx.trust.add(TrustRecord(
        adapter_id="zjlib", portal_host="2.2.1.1", portal_port=8443,
        scheme="https", allowed_hosts=("2.2.1.1",),
    ))
    real = "362323199801071710"
    monkeypatch.setattr(
        ctx.credentials, "usernames", lambda a, h: [real], raising=False
    )
    creds = CredentialsWindow(ctx)
    creds.refresh()
    assert creds.username.stringValue() == mask_username(real)
    assert creds._prefill_real == real  # 保存时可还原
