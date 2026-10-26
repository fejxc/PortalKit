"""原生窗口：信任引导 / 凭据 / 网络管理 / 诊断与日志 / 设置。

全部为 AppKit 原生控件（系统字体/语义行为/深色模式随系统），frame 布局、
固定尺寸。窗口只读 core 状态、只发命令——无任何第二套网络/状态逻辑
（ARCHITECTURE §1）。所有数据来自真实 Engine/Trust/Keychain，无演示数据。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from AppKit import (
    NSAlert,
    NSAlertFirstButtonReturn,
    NSBackingStoreBuffered,
    NSButton,
    NSControlStateValueOff,
    NSControlStateValueOn,
    NSFont,
    NSMakeRect,
    NSModalResponseOK,
    NSPopUpButton,
    NSSavePanel,
    NSScrollView,
    NSSecureTextField,
    NSSwitchButton,
    NSTextField,
    NSTextView,
    NSWindow,
    NSWindowStyleMaskClosable,
    NSWindowStyleMaskTitled,
)
from Foundation import NSObject

from portalkit.core.trust import TrustRecord
from portalkit.diagnostics.logging import redact_text
from portalkit.models import ErrorCode, Phase, StateSnapshot, utc_now_iso

if TYPE_CHECKING:  # pragma: no cover
    from portalkit.ui.menubar import UIContext

BODY_FONT = 13
TITLE_FONT = 16


def _window(title: str, w: float, h: float) -> NSWindow:
    win = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
        NSMakeRect(0, 0, w, h),
        NSWindowStyleMaskTitled | NSWindowStyleMaskClosable,
        NSBackingStoreBuffered,
        False,
    )
    win.setTitle_(title)
    win.center()
    win.setReleasedWhenClosed_(False)
    return win


def _label(frame, text: str, *, bold: bool = False, size: int = BODY_FONT) -> NSTextField:
    field = NSTextField.alloc().initWithFrame_(frame)
    field.setStringValue_(text)
    field.setBezeled_(False)
    field.setBordered_(False)
    field.setEditable_(False)
    field.setDrawsBackground_(False)
    field.setFont_(NSFont.boldSystemFontOfSize_(size) if bold else NSFont.systemFontOfSize_(size))
    return field


def _input(frame, placeholder: str = "", secure: bool = False) -> NSTextField:
    cls = NSSecureTextField if secure else NSTextField
    field = cls.alloc().initWithFrame_(frame)
    field.setPlaceholderString_(placeholder)
    return field


def _checkbox(frame, title: str, checked: bool) -> NSButton:
    btn = NSButton.alloc().initWithFrame_(frame)
    btn.setButtonType_(NSSwitchButton)
    btn.setTitle_(title)
    btn.setState_(NSControlStateValueOn if checked else NSControlStateValueOff)
    return btn


class _ActionBridge(NSObject):
    """把 Python 闭包接成 AppKit target/action。"""

    def initWithCallback_(self, callback: Callable[[], None]):
        import objc

        self = objc.super(_ActionBridge, self).init()
        self.callback = callback
        return self

    def call_(self, sender) -> None:
        try:
            self.callback()
        except Exception as exc:  # noqa: BLE001 — UI 层兜底，不打印敏感栈
            print(f"[portalkit-ui] action error: {type(exc).__name__}: {exc}", flush=True)


_ACTION_BRIDGES: list = []  # 持有全部 action bridge：NSControl target 弱引用 + pyobjc 不允许挂属性


def _button(frame, title: str, callback: Callable[[], None]) -> NSButton:
    from AppKit import NSMomentaryPushInButton, NSRoundedBezelStyle

    btn = NSButton.alloc().initWithFrame_(frame)
    btn.setTitle_(title)
    btn.setButtonType_(NSMomentaryPushInButton)
    btn.setBezelStyle_(NSRoundedBezelStyle)
    bridge = _ActionBridge.alloc().initWithCallback_(callback)
    # NSControl 的 target 是 unsafe_unretained（弱引用），且 pyobjc 不允许在
    # NSButton 实例上挂 Python 属性——bridge 由模块级列表持有（数量=按钮数，
    # 生命周期=进程）。缺它则点击静默失效（2026-10-26 现场实测踩坑）。
    _ACTION_BRIDGES.append(bridge)
    btn.setTarget_(bridge)
    btn.setAction_("call:")
    return btn


def _textview(frame, content: str = ""):
    scroll = NSScrollView.alloc().initWithFrame_(frame)
    scroll.setHasVerticalScroller_(True)
    tv = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, frame.size.width, frame.size.height))
    tv.setEditable_(False)
    tv.setRichText_(False)
    tv.setFont_(NSFont.userFixedPitchFontOfSize_(12))
    tv.setString_(content)
    scroll.setDocumentView_(tv)
    return scroll, tv


def _popup(frame, titles: list[str]) -> NSPopUpButton:
    popup = NSPopUpButton.alloc().initWithFrame_(frame)
    popup.setPullsDown_(False)
    popup.addItemsWithTitles_(titles)
    return popup


def _confirm(title: str, info: str, ok: str) -> bool:
    alert = NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(info)
    alert.addButtonWithTitle_(ok)
    alert.addButtonWithTitle_("取消")
    return alert.runModal() == NSAlertFirstButtonReturn


def _trust_titles(records: list[TrustRecord]) -> list[str]:
    return [f"[{r.adapter_id}] {r.portal_host}:{r.portal_port} ({r.scheme})" for r in records]


def _record_detail(rec: TrustRecord) -> str:
    lines = [
        f"适配器:   {rec.adapter_id}",
        f"认证目标: {rec.scheme}://{rec.portal_host}:{rec.portal_port}",
        f"允许宿主: {', '.join(rec.allowed_hosts)}",
        f"页面指纹: {rec.fingerprint or '未固定'}",
        f"证书指纹: {rec.cert_sha256 or '未固定'}",
        f"信任时间: {rec.created_at or '未知'}",
        f"网络线索: {rec.network_hint or '-'}",
    ]
    if rec.scheme == "http":
        lines.append("⚠ HTTP 明文门户：凭据传输不加密。")
    return "\n".join(lines)


# ---------------------------------------------------------------- onboarding

class OnboardingWindow:
    """首次信任引导（UI_UX_SPEC §5 三步合并为一屏：证据 → 账号 → 结果走通知/菜单）。"""

    def __init__(self, ctx: "UIContext") -> None:
        self.ctx = ctx
        self.win = _window("PortalKit — 添加可信网络", 460, 430)
        c = self.win.contentView()
        c.addSubview_(_label(NSMakeRect(20, 388, 300, 24), "发现认证网络", bold=True, size=TITLE_FONT))
        self.summary, self.summary_tv = _textview(NSMakeRect(20, 218, 420, 160))
        c.addSubview_(self.summary)
        self.agree = _checkbox(NSMakeRect(20, 190, 420, 22), "我确认信任以上登录目标", False)
        c.addSubview_(self.agree)
        c.addSubview_(_label(NSMakeRect(20, 160, 60, 22), "账号"))
        self.username = _input(NSMakeRect(90, 158, 350, 24), "读者证号 / 学工号")
        c.addSubview_(self.username)
        c.addSubview_(_label(NSMakeRect(20, 128, 60, 22), "密码"))
        self.password = _input(NSMakeRect(90, 126, 350, 24), "密码（不回显）", secure=True)
        c.addSubview_(self.password)
        self.save_keychain = _checkbox(NSMakeRect(20, 98, 420, 22), "保存到 macOS Keychain（用于本网络自动认证）", True)
        self.save_keychain.setState_(NSControlStateValueOn)
        c.addSubview_(self.save_keychain)
        self.auto = _checkbox(NSMakeRect(20, 74, 420, 22), "以后在此网络自动认证", True)
        self.auto.setState_(NSControlStateValueOn)
        c.addSubview_(self.auto)
        c.addSubview_(_button(NSMakeRect(290, 24, 150, 32), "保存并认证", self._confirm))
        c.addSubview_(_button(NSMakeRect(160, 24, 110, 32), "稍后", self.win.close))
        self._detection = None

    def present_with_detection(self, detection) -> None:
        """detection: DetectionResult；在主线程调用。"""
        self._detection = detection
        if detection is None:
            self.summary_tv.setString_("正在识别当前网络的门户……请稍候，或点击菜单“重新检查网络”。")
        else:
            lines = ["未能在当前网络识别门户。可尝试：连接目标 Wi-Fi 后重试；或手动指定目标（见 README）。"]
            if detection.matched:
                scheme = detection.portal_scheme or "https"
                lines = [
                    f"识别到门户：{scheme}://{detection.portal_host}:{detection.portal_port}",
                    f"页面指纹：{detection.fingerprint or '-'}",
                    f"证书指纹：{detection.observed_cert_sha256 or '-'}",
                    "",
                    "匹配证据：",
                    *[f"  · {e}" for e in detection.evidence],
                    "",
                ]
                if scheme == "http":
                    lines.append("⚠ 该门户为 HTTP 明文：凭据传输不加密，请确认你信任当前网络。")
            self.summary_tv.setString_("\n".join(lines))
        self.win.makeKeyAndOrderFront_(None)
        from AppKit import NSApp
        NSApp.activateIgnoringOtherApps_(True)

    def _confirm(self) -> None:
        from AppKit import NSApp

        detection = self._detection
        if detection is None or not detection.matched or not detection.portal_host:
            _confirm("无法保存", "尚未识别到门户，不能创建信任。", "知道了")
            return
        if self.agree.state() != NSControlStateValueOn:
            _confirm("需要确认", "请先勾选“我确认信任以上登录目标”。", "知道了")
            return
        username = str(self.username.stringValue()).strip()
        password = str(self.password.stringValue())
        save_kb = self.save_keychain.state() == NSControlStateValueOn
        if not username or (save_kb and not password):
            _confirm("信息不完整", "账号与密码不能为空。", "知道了")
            return
        record = TrustRecord(
            adapter_id=detection.adapter_id,
            portal_host=detection.portal_host,
            portal_port=detection.portal_port or 0,
            scheme=detection.portal_scheme or "https",
            allowed_hosts=(detection.portal_host,),
            cert_sha256=detection.observed_cert_sha256,
            fingerprint=detection.fingerprint,
            network_hint=(
                f"iface={self.ctx.engine_latest_snapshot().interface} "
                f"gw={self.ctx.engine_latest_snapshot().gateway}"
            ),
            created_at=utc_now_iso(),
            note="ui onboarding",
        )
        self.ctx.trust.add(record)
        if save_kb:
            self.ctx.credentials.save(record.adapter_id, record.portal_host, username, password)
        self.win.close()
        if self.auto.state() == NSControlStateValueOn:
            self.ctx.request_authenticate()


# --------------------------------------------------------------- credentials

class CredentialsWindow:
    def __init__(self, ctx: "UIContext") -> None:
        self.ctx = ctx
        self.win = _window("PortalKit — 凭据", 420, 220)
        c = self.win.contentView()
        c.addSubview_(_label(NSMakeRect(20, 178, 380, 22), "选择受信网络", bold=True))
        self.popup = _popup(NSMakeRect(20, 148, 380, 26), [])
        c.addSubview_(self.popup)
        c.addSubview_(_label(NSMakeRect(20, 116, 60, 22), "账号"))
        self.username = _input(NSMakeRect(90, 114, 310, 24))
        c.addSubview_(self.username)
        c.addSubview_(_label(NSMakeRect(20, 84, 60, 22), "密码"))
        self.password = _input(NSMakeRect(90, 82, 310, 24), "留空 = 不修改", secure=True)
        c.addSubview_(self.password)
        c.addSubview_(_button(NSMakeRect(20, 28, 110, 32), "保存", self._save))
        c.addSubview_(_button(NSMakeRect(150, 28, 110, 32), "删除凭据", self._delete))
        c.addSubview_(_button(NSMakeRect(300, 28, 100, 32), "刷新", self.refresh))
        self._popup_bridge = _ActionBridge.alloc().initWithCallback_(self._picked)
        self.popup.setTarget_(self._popup_bridge)
        self.popup.setAction_("pick:")

    def _picked(self) -> None:
        username = self._current_username()
        self.username.setStringValue_(username or "")

    def _records(self) -> list[TrustRecord]:
        return self.ctx.trust.all()

    def _selected(self) -> TrustRecord | None:
        idx = self.popup.indexOfSelectedItem()
        records = self._records()
        if 0 <= idx < len(records):
            return records[idx]
        return None

    def _current_username(self) -> str:
        rec = self._selected()
        if rec is None:
            return ""
        names = self.ctx.credentials.usernames(rec.adapter_id, rec.portal_host)
        return names[0] if names else ""

    def refresh(self) -> None:
        records = self._records()
        self.popup.removeAllItems()
        if records:
            self.popup.addItemsWithTitles_(_trust_titles(records))
        self._picked()

    def show(self) -> None:
        self.refresh()
        self.win.makeKeyAndOrderFront_(None)
        from AppKit import NSApp
        NSApp.activateIgnoringOtherApps_(True)

    def _save(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        username = str(self.username.stringValue()).strip()
        password = str(self.password.stringValue())
        if not username or not password:
            _confirm("信息不完整", "账号与密码不能为空。", "知道了")
            return
        self.ctx.credentials.save(rec.adapter_id, rec.portal_host, username, password)
        self.ctx.logger.event("credentials_saved", adapter=rec.adapter_id, host=rec.portal_host)

    def _delete(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        username = self._current_username()
        if not username:
            return
        if not _confirm("删除凭据", f"删除 {rec.portal_host} 上账号 {username} 的 Keychain 凭据？", "删除"):
            return
        self.ctx.credentials.delete(rec.adapter_id, rec.portal_host, username)
        self._picked()


# ------------------------------------------------------------ network manage

class ManagerWindow:
    def __init__(self, ctx: "UIContext") -> None:
        self.ctx = ctx
        self.win = _window("PortalKit — 管理可信网络", 460, 320)
        c = self.win.contentView()
        c.addSubview_(_label(NSMakeRect(20, 278, 380, 22), "受信网络", bold=True))
        self.popup = _popup(NSMakeRect(20, 248, 420, 26), [])
        c.addSubview_(self.popup)
        self.detail, self.detail_tv = _textview(NSMakeRect(20, 78, 420, 160))
        c.addSubview_(self.detail)
        c.addSubview_(_button(NSMakeRect(20, 28, 120, 32), "撤销信任", self._revoke))
        c.addSubview_(_button(NSMakeRect(160, 28, 120, 32), "编辑凭据", self._edit_creds))
        c.addSubview_(_button(NSMakeRect(320, 28, 120, 32), "刷新", self.refresh))
        self._bridge = _ActionBridge.alloc().initWithCallback_(self._picked)
        self.popup.setTarget_(self._bridge)
        self.popup.setAction_("pick:")

    def _records(self):
        return self.ctx.trust.all()

    def _selected(self):
        idx = self.popup.indexOfSelectedItem()
        records = self._records()
        return records[idx] if 0 <= idx < len(records) else None

    def _picked(self) -> None:
        rec = self._selected()
        self.detail_tv.setString_(_record_detail(rec) if rec else "（无受信网络）")

    def refresh(self) -> None:
        records = self._records()
        self.popup.removeAllItems()
        if records:
            self.popup.addItemsWithTitles_(_trust_titles(records))
        self._picked()

    def show(self) -> None:
        self.refresh()
        self.win.makeKeyAndOrderFront_(None)
        from AppKit import NSApp
        NSApp.activateIgnoringOtherApps_(True)

    def _revoke(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        if not _confirm(
            "撤销信任",
            f"撤销 [{rec.adapter_id}] {rec.portal_host}:{rec.portal_port} 的信任？\n"
            "此后该网络不再自动认证；是否同时删除 Keychain 凭据可在凭据窗口操作。此操作可随时重新信任。",
            "撤销信任",
        ):
            return
        self.ctx.trust.revoke(rec.adapter_id, rec.portal_host)
        self.ctx.logger.event("trust_revoked", adapter=rec.adapter_id, host=rec.portal_host)
        self.refresh()

    def _edit_creds(self) -> None:
        self.ctx.open_credentials()


# --------------------------------------------------------------- diagnostics

def _diagnostics_text(ctx: "UIContext", tail: int = 40) -> str:
    state: StateSnapshot | None = ctx.engine_latest_state()
    lines = ["== PortalKit 诊断（脱敏） ==", ""]
    snap = ctx.engine_latest_snapshot()
    if snap and snap.ready:
        lines.append(f"物理网络: {snap.interface}  IP: {snap.ipv4}  网关: {snap.gateway}")
    else:
        lines.append("物理网络: 未连接")
    if state:
        lines += [
            "",
            f"状态: {state.message_key} ({state.phase.value})",
            f"  link={state.link.value} portal={state.portal.value} internet={state.internet.value}",
            f"  generation={state.network_generation} adapter={state.adapter_id or '-'}",
            f"  错误: {state.error_code.value}",
            f"  说明: {state.detail or '-'}",
            *(f"  · {e}" for e in state.evidence),
        ]
    events_path = ctx.state_dir / "events.jsonl"
    if events_path.exists():
        items = events_path.read_text(encoding="utf-8").splitlines()[-tail:]
        lines += ["", f"最近事件 {len(items)} 条:"]
        for line in items:
            try:
                item = json.loads(line)
                lines.append(
                    f"  {item.get('ts', '')} {item.get('event')}"
                    f" phase={item.get('phase', '')} err={item.get('error', '')}"
                )
            except ValueError:
                continue
    return "\n".join(lines)


class DiagnosticsWindow:
    def __init__(self, ctx: "UIContext") -> None:
        self.ctx = ctx
        self.win = _window("PortalKit — 诊断与日志", 560, 420)
        c = self.win.contentView()
        self.text, self.tv = _textview(NSMakeRect(20, 62, 520, 340))
        c.addSubview_(self.text)
        c.addSubview_(_button(NSMakeRect(20, 18, 110, 32), "重新检查", self.ctx.request_check))
        c.addSubview_(_button(NSMakeRect(150, 18, 90, 32), "刷新", self.refresh))
        c.addSubview_(_button(NSMakeRect(430, 18, 110, 32), "导出脱敏诊断", self._export))
        self.refresh()

    def refresh(self) -> None:
        self.tv.setString_(_diagnostics_text(self.ctx))

    def show(self) -> None:
        self.refresh()
        self.win.makeKeyAndOrderFront_(None)
        from AppKit import NSApp
        NSApp.activateIgnoringOtherApps_(True)

    def _export(self) -> None:
        content = redact_text(_diagnostics_text(self.ctx, tail=200), max_len=100000)
        panel = NSSavePanel.savePanel()
        panel.setNameFieldStringValue_(f"portalkit-diagnostics-{utc_now_iso()[:10]}.txt")
        if panel.runModal() == NSModalResponseOK:
            path = panel.URL().path()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)


# ------------------------------------------------------------------ settings

class SettingsWindow:
    def __init__(self, ctx: "UIContext") -> None:
        self.ctx = ctx
        self.win = _window("PortalKit — 设置", 420, 240)
        c = self.win.contentView()
        settings = self.ctx.settings.get()
        self.auto = _checkbox(NSMakeRect(20, 190, 380, 22), "在已信任网络自动认证", settings.auto_auth)
        c.addSubview_(self.auto)
        self.notify = _checkbox(NSMakeRect(20, 164, 380, 22), "异常与需要操作时系统通知", settings.notify_on_error)
        c.addSubview_(self.notify)
        c.addSubview_(_label(NSMakeRect(20, 132, 120, 22), "兜底检查间隔"))
        self.interval = _popup(NSMakeRect(140, 128, 120, 26),
                               [f"{s} 秒" for s in (30, 60, 120)])
        self.interval.selectItemAtIndex_((30, 60, 120).index(settings.check_interval_s))
        c.addSubview_(self.interval)
        c.addSubview_(_label(
            NSMakeRect(20, 96, 380, 22),
            "网络变化由系统事件驱动；此间隔仅为兜底。凭据保存在 Keychain，日志全程脱敏。"))
        c.addSubview_(_button(NSMakeRect(300, 32, 100, 32), "保存", self._save))
        self.refresh()

    def refresh(self) -> None:
        settings = self.ctx.settings.get()
        self.auto.setState_(NSControlStateValueOn if settings.auto_auth else NSControlStateValueOff)
        self.notify.setState_(NSControlStateValueOn if settings.notify_on_error else NSControlStateValueOff)
        self.interval.selectItemAtIndex_((30, 60, 120).index(settings.check_interval_s))

    def show(self) -> None:
        self.refresh()
        self.win.makeKeyAndOrderFront_(None)
        from AppKit import NSApp
        NSApp.activateIgnoringOtherApps_(True)

    def _save(self) -> None:
        self.ctx.settings.update(
            auto_auth=self.auto.state() == NSControlStateValueOn,
            notify_on_error=self.notify.state() == NSControlStateValueOn,
            check_interval_s=(30, 60, 120)[self.interval.indexOfSelectedItem()],
        )
        self.ctx.on_settings_changed()
        self.win.close()
