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
    _history_summary_lines,
    _readable_events,
    _readable_history,
    _resolve_username,
    mask_username,
)


@pytest.fixture(scope="module")
def app_shell():
    NSApplication.sharedApplication()  # 控件构造所需的最低环境
    yield


class _FakeLogger:
    """生产契约：ctx.logger 恒可用（menubar 注入 RedactedLogger）。"""

    def __init__(self):
        self.events: list[tuple] = []

    def event(self, *args, **kwargs):
        self.events.append((args, kwargs))


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
    c.logger = _FakeLogger()
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


# ---------------------------------------- v1.3.2 管理窗交互逻辑回归

def _trust_pair(ctx):
    for adapter, host, port in (("zjlib", "2.2.1.1", 8443), ("zstu", "192.168.102.166", 80)):
        ctx.trust.add(TrustRecord(
            adapter_id=adapter, portal_host=host, portal_port=port,
            scheme="https", allowed_hosts=(host,), fingerprint=f"fp-{host}",
        ))


def test_manager_empty_state_disables_actions(app_shell, ctx):
    """空记录态：撤销/编辑凭据/自动认证开关全部禁用——杜绝"点了没反应"。"""
    manager = ManagerWindow(ctx)
    manager.refresh()
    assert manager._selected() is None
    assert manager.revoke_btn.isEnabled() is False
    assert manager.creds_btn.isEnabled() is False
    assert manager.auto_toggle.isEnabled() is False


def test_manager_with_record_enables_actions(app_shell, ctx):
    _trust_pair(ctx)
    manager = ManagerWindow(ctx)
    manager.refresh()
    assert manager.revoke_btn.isEnabled() is True
    assert manager.auto_toggle.isEnabled() is True


def test_manager_toggle_updates_detail_text(app_shell, ctx):
    """切换自动认证后详情区"自动认证:"必须同步（v1.3.1 前 display 旧值）。"""
    _trust_pair(ctx)
    manager = ManagerWindow(ctx)
    manager.refresh()
    manager.auto_toggle.setState_(0)  # NSControlStateValueOff
    manager._auto_changed()
    assert "自动认证: 关闭" in manager.detail_tv.string()
    manager.auto_toggle.setState_(1)
    manager._auto_changed()
    assert "自动认证: 开启" in manager.detail_tv.string()


def test_credentials_focus_record_selects_target(app_shell, ctx):
    """管理窗跳转：凭据窗口必须定位到指定记录，不落回第一项。"""
    _trust_pair(ctx)
    creds = CredentialsWindow(ctx)
    creds.show()
    creds.focus_record("zstu", "192.168.102.166")
    assert creds.popup.indexOfSelectedItem() == 1
    assert "192.168.102.166" in creds.popup.titleOfSelectedItem()


def test_credentials_focus_unknown_keeps_first(app_shell, ctx):
    _trust_pair(ctx)
    creds = CredentialsWindow(ctx)
    creds.show()
    creds.focus_record("nope", "0.0.0.0")  # 未匹配 → 保持默认选中
    assert creds.popup.indexOfSelectedItem() == 0


def test_purge_credentials_deletes_all_accounts(app_shell, ctx, monkeypatch):
    """撤销并删除凭据：逐账号删除并计数。"""
    _trust_pair(ctx)
    rec = ctx.trust.lookup("zjlib", "2.2.1.1")
    deleted = []
    monkeypatch.setattr(ctx.credentials, "usernames", lambda a, h: ["u1", "u2"], raising=False)
    monkeypatch.setattr(
        ctx.credentials, "delete",
        lambda a, h, u: deleted.append((a, h, u)) or True, raising=False,
    )
    from portalkit.ui.windows import _purge_credentials
    assert _purge_credentials(ctx, rec) == 2
    assert deleted == [("zjlib", "2.2.1.1", "u1"), ("zjlib", "2.2.1.1", "u2")]


def test_unfixed_fingerprint_hint(app_shell, ctx):
    """旧记录无页面指纹时给出解释，不再裸露"未固定"。"""
    ctx.trust.add(TrustRecord(
        adapter_id="zjlib", portal_host="2.2.1.1", portal_port=8443,
        scheme="https", allowed_hosts=("2.2.1.1",), fingerprint="",
    ))
    manager = ManagerWindow(ctx)
    manager.refresh()
    assert "重新添加可信网络可更新" in manager.detail_tv.string()


# ------------------------------------------------ v1.4 会话历史展示

def _write_history(state_dir, rows):
    import json as _json
    lines = [_json.dumps({"ts": ts, "kind": kind, "code": code,
                          "adapter": adapter, "host": ""})
             for ts, kind, code, adapter in rows]
    (state_dir / "history.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_readable_history_renders_kinds_and_dates(app_shell, ctx):
    from datetime import datetime, timezone
    from portalkit.core.history import SessionHistory

    now = datetime.now(timezone.utc)
    _write_history(ctx.state_dir, [
        (now.isoformat(), "auth_success", "", "zstu"),
        (now.isoformat(), "auth_fail", "auth_quota", "zstu"),
        (now.isoformat(), "kick_suspected", "", ""),
    ])
    lines = _readable_history(ctx, tail=10, only_issues=False)
    assert lines is not None
    assert lines[0].startswith("[") is False or lines[-1]  # 有输出即可
    joined = "\n".join(lines)
    assert "认证成功" in joined and "认证失败" in joined
    assert "已达在线设备/会话上限" in joined  # code → 中文
    assert "疑似设备互踢" in joined


def test_readable_history_only_issues_filters_success(app_shell, ctx):
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    _write_history(ctx.state_dir, [
        (now.isoformat(), "auth_success", "", "zstu"),
        (now.isoformat(), "auth_fail", "invalid_credentials", "zstu"),
    ])
    lines = _readable_history(ctx, tail=10, only_issues=True)
    assert lines is not None
    assert len(lines) == 1 and "账号或密码无效" in lines[0]


def test_readable_history_missing_file_returns_none(app_shell, ctx):
    assert _readable_history(ctx, tail=10) is None


def test_history_summary_lines_format(app_shell, ctx):
    from portalkit.core.history import SessionHistory

    SessionHistory(ctx.state_dir / "history.jsonl")  # 只为确认模块可导入
    from portalkit.core.history import KIND_AUTH_FAIL, KIND_AUTH_SUCCESS
    history = SessionHistory(ctx.state_dir / "history.jsonl")
    history.record(KIND_AUTH_SUCCESS, adapter="zstu")
    history.record(KIND_AUTH_FAIL, code="auth_quota", adapter="zstu")
    lines = _history_summary_lines(ctx, days=7)
    assert len(lines) == 1
    assert "成功 1" in lines[0] and "失败 1" in lines[0]
    assert "设备" in lines[0]  # auth_quota 的中文描述进入失败细分


def test_diagnostics_text_includes_history_summary(app_shell, ctx):
    from portalkit.core.history import KIND_KICK_SUSPECTED, SessionHistory
    from portalkit.ui.windows import _diagnostics_text

    SessionHistory(ctx.state_dir / "history.jsonl").record(KIND_KICK_SUSPECTED)
    text = _diagnostics_text(ctx)
    assert "近 7 天会话汇总" in text
    assert "互踢 1" in text


def test_settings_window_constructs_with_telemetry_preview(app_shell, ctx):
    """v1.4 设置窗口新增「查看将上报的数据」按钮——构造期回归。"""
    settings = SettingsWindow(ctx)
    assert settings.win is not None
