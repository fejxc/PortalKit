"""窗口构造冒烟测试：在无 run loop 的 AppKit 环境下实例化全部窗口。

动机：2026-10-26 现场 OnboardingWindow 因 _checkbox 漏参 TypeError 导致
菜单点击静默无反应——此类构造期错误必须在 CI 抓住。
"""

from __future__ import annotations

import pytest

AppKit = pytest.importorskip("AppKit")

from AppKit import NSApplication  # noqa: E402

from portalkit.core.settings import SettingsStore  # noqa: E402
from portalkit.core.trust import TrustRegistry  # noqa: E402
from portalkit.credentials.service import KeychainCredentialService  # noqa: E402
from portalkit.ui.menubar import UIContext  # noqa: E402
from portalkit.ui.windows import (  # noqa: E402
    CredentialsWindow,
    DiagnosticsWindow,
    ManagerWindow,
    OnboardingWindow,
    SettingsWindow,
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
