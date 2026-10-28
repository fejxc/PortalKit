"""原生窗口：信任引导 / 凭据 / 网络管理 / 诊断与日志 / 设置。

全部为 AppKit 原生控件（系统字体/语义行为/深色模式随系统），frame 布局、
固定尺寸。窗口只读 core 状态、只发命令——无任何第二套网络/状态逻辑
（ARCHITECTURE §1）。所有数据来自真实 Engine/Trust/Keychain，无演示数据。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from AppKit import (
    NSAlert,
    NSAlertFirstButtonReturn,
    NSBackingStoreBuffered,
    NSBox,
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


class FormLayout:
    """纵向表单布局辅助：自上而下放置行，免去逐个手摆 NSMakeRect。

    用法：FormLayout(contentView, width=420, top=200) 后链式调用
    label/input/checkbox/popup/button_row/textview/space。每方法返回控件。
    """

    def __init__(self, view, width: float, top: float, margin: float = 20.0):
        self.view = view
        self.width = width
        self.margin = margin
        self.y = top

    def space(self, height: float = 10.0) -> None:
        self.y -= height

    def label(self, text: str, *, bold: bool = False, size: int = BODY_FONT, height: float = 20.0):
        control = _label(NSMakeRect(self.margin, self.y, self.width, height), text, bold=bold, size=size)
        self.view.addSubview_(control)
        self.y -= height
        return control

    def input(self, placeholder: str = "", *, secure: bool = False, height: float = 24.0, label: str | None = None):
        if label is not None:
            self.label(label, height=20.0)
        control = _input(NSMakeRect(self.margin, self.y, self.width, height), placeholder, secure=secure)
        self.view.addSubview_(control)
        self.y -= height + 6.0
        return control

    def checkbox(self, title: str, checked: bool, height: float = 22.0):
        control = _checkbox(NSMakeRect(self.margin, self.y, self.width, height), title, checked)
        self.view.addSubview_(control)
        self.y -= height
        return control

    def popup(self, titles: list[str], height: float = 26.0):
        control = _popup(NSMakeRect(self.margin, self.y, self.width, height), titles)
        self.view.addSubview_(control)
        self.y -= height + 6.0
        return control

    def textview(self, height: float):
        control, tv = _textview(NSMakeRect(self.margin, self.y, self.width, height))
        self.view.addSubview_(control)
        self.y -= height + 6.0
        return control, tv

    def button_row(self, buttons: list[tuple[str, Callable[[], None]]], *, height: float = 32.0, right_align: bool = True):
        """一行按钮；right_align 从右往左排列，否则从左往右。"""
        count = len(buttons)
        gap = 10.0
        btn_width = (self.width - gap * (count - 1)) / count
        for index, (title, callback) in enumerate(buttons):
            x = (self.margin + self.width - btn_width - index * (btn_width + gap)) if right_align \
                else (self.margin + index * (btn_width + gap))
            control = _button(NSMakeRect(x, self.y, btn_width, height), title, callback)
            self.view.addSubview_(control)
        self.y -= height + 8.0


def _confirm(title: str, info: str, ok: str) -> bool:
    alert = NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(info)
    alert.addButtonWithTitle_(ok)
    alert.addButtonWithTitle_("取消")
    return alert.runModal() == NSAlertFirstButtonReturn


def _trust_titles(records: list[TrustRecord]) -> list[str]:
    return [f"[{r.adapter_id}] {r.portal_host}:{r.portal_port} ({r.scheme})" for r in records]


def _fmt_local(iso_ts: str) -> str:
    """UTC ISO → 本地短时间（MM-DD HH:MM）；空/损坏返回占位。"""
    if not iso_ts:
        return "—"
    try:
        from datetime import datetime, timezone

        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%m-%d %H:%M")
    except ValueError:
        return "—"


def _record_detail(rec: TrustRecord) -> str:
    lines = [
        f"适配器:   {rec.adapter_id}",
        f"认证目标: {rec.scheme}://{rec.portal_host}:{rec.portal_port}",
        f"允许宿主: {', '.join(rec.allowed_hosts)}",
        f"自动认证: {'开启' if rec.auto_auth else '关闭'}",
        f"上次连接: {_fmt_local(rec.last_connected_at)}",
        f"页面指纹: {rec.fingerprint or '未固定'}",
        f"证书指纹: {rec.cert_sha256 or '未固定'}",
        f"信任时间: {_fmt_local(rec.created_at) if rec.created_at else '未知'}",
        f"网络线索: {rec.network_hint or '-'}",
    ]
    if rec.session_lifetime_samples:
        median = sorted(rec.session_lifetime_samples)[len(rec.session_lifetime_samples) // 2]
        lines.append(f"会话寿命: 约 {median:.0f} 小时（{len(rec.session_lifetime_samples)} 次观测）")
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
        existing = self.ctx.trust.lookup(detection.adapter_id, detection.portal_host)
        record = TrustRecord(
            adapter_id=detection.adapter_id,
            portal_host=detection.portal_host,
            portal_port=detection.portal_port or 0,
            scheme=detection.portal_scheme or "https",
            allowed_hosts=(detection.portal_host,),
            cert_sha256=detection.observed_cert_sha256,
            fingerprint=detection.fingerprint,
            entry_url=existing.entry_url if existing else "",
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
        self.win = _window("PortalKit — 凭据", 420, 226)
        form = FormLayout(self.win.contentView(), width=380, top=184)
        form.label("选择受信网络", bold=True)
        self.popup = form.popup([])
        form.space(4)
        self.username = form.input(placeholder="账号", label="账号")
        self.password = form.input(placeholder="密码（不回显；留空 = 不修改）", secure=True, label="密码")
        form.button_row([("保存", self._save), ("删除凭据", self._delete), ("刷新", self.refresh)])
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
        self.password.setStringValue_("")  # 保存后清空明文，避免残留
        _confirm(
            "已保存",
            f"凭据已写入 Keychain（{rec.portal_host} · 账号 {username}）。\n"
            "点击菜单栏「立即认证」执行认证。",
            "好",
        )

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
        self.win = _window("PortalKit — 管理可信网络", 460, 352)
        c = self.win.contentView()
        c.addSubview_(_label(NSMakeRect(20, 310, 380, 22), "受信网络", bold=True))
        self.popup = _popup(NSMakeRect(20, 280, 420, 26), [])
        c.addSubview_(self.popup)
        self.detail, self.detail_tv = _textview(NSMakeRect(20, 118, 420, 152))
        c.addSubview_(self.detail)
        self.auto_toggle = _checkbox(NSMakeRect(20, 88, 420, 22), "此网络自动认证", True)
        c.addSubview_(self.auto_toggle)
        self._auto_bridge = _ActionBridge.alloc().initWithCallback_(self._auto_changed)
        self.auto_toggle.setTarget_(self._auto_bridge)
        self.auto_toggle.setAction_("call:")
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
        self.auto_toggle.setState_(
            NSControlStateValueOn if (rec and rec.auto_auth) else NSControlStateValueOff
        )

    def _auto_changed(self) -> None:
        rec = self._selected()
        if rec is None:
            return
        enabled = self.auto_toggle.state() == NSControlStateValueOn
        if enabled != rec.auto_auth:
            self.ctx.trust.update_auto_auth(rec.adapter_id, rec.portal_host, enabled)
            self.ctx.logger.event("auto_auth_toggled", adapter=rec.adapter_id,
                                  host=rec.portal_host, enabled=enabled)

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

_PHASE_CN = {
    "ONLINE_AUTHENTICATED": "✓ 已联网（自动认证完成）",
    "ONLINE_NO_AUTH": "✓ 已联网（无需登录）",
    "PROBING": "… 正在检查网络",
    "MATCHING": "… 正在识别门户",
    "AUTHENTICATING": "… 正在自动认证",
    "VERIFYING": "… 正在验证联网",
    "RETRY_BACKOFF": "… 临时失败，等待重试",
    "TRUST_REQUIRED": "! 发现认证网络，待确认信任",
    "WAITING_USER": "! 需要操作",
    "DEGRADED": "! 连接待验证",
    "ERROR": "× 异常",
    "CANCELLED": "· 已取消（网络变化）",
}

_AUTH_CODE_CN = {
    "success": "提交成功",
    "already_authenticated": "会话仍有效",
    "invalid_credentials": "门户拒绝：账号或密码无效",
    "interaction_required": "门户要求网页操作",
    "portal_changed": "门户特征变化",
    "network_error": "网络临时失败",
    "untrusted_target": "重定向到未授权目标，已终止",
    "unknown_error": "未知结果",
}


def _readable_events(ctx: "UIContext", tail: int = 40, only_issues: bool = False) -> list[str]:
    """事件日志 → 可读时间线（最新在最上）。只呈现用户关心的状态流转。

    only_issues=True 时过滤掉正常项（已联网/成功提交），只留需操作、
    待验证、失败与系统睡眠唤醒——"扫一眼今天有没有出过事"。
    """
    events_path = ctx.state_dir / "events.jsonl"
    if not events_path.exists():
        return ["（暂无事件）"]
    _OK_PHASES = {"ONLINE_AUTHENTICATED", "ONLINE_NO_AUTH"}
    _OK_AUTH = {"success", "already_authenticated"}
    items: list[dict] = []
    for line in events_path.read_text(encoding="utf-8").splitlines()[-tail * 3:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        ev = item.get("event")
        if ev == "state":
            phase = str(item.get("phase", ""))
            if only_issues and phase in _OK_PHASES:
                continue
            text = _PHASE_CN.get(phase, phase)
            err = str(item.get("error", "none"))
            if err not in ("", "none"):
                text += f"（{err}）"
            items.append(("state", item.get("ts", ""), text))
        elif ev == "auth_result":
            code = str(item.get("code", ""))
            if only_issues and code in _OK_AUTH:
                continue
            items.append(("auth", item.get("ts", ""),
                          "认证提交：" + _AUTH_CODE_CN.get(code, code)))
        elif ev == "system_sleep":
            items.append(("sys", item.get("ts", ""), "系统睡眠"))
        elif ev == "system_wake":
            items.append(("sys", item.get("ts", ""), "系统唤醒，正在重新检查"))
    lines = []
    for kind, ts, text in reversed(items[-tail:]):
        clock = ts[11:19] if len(ts) >= 19 else ts  # ISO → HH:MM:SS
        lines.append(f"{clock}  {text}")
    return lines


def _diagnostics_text(ctx: "UIContext", tail: int = 40) -> str:
    state: StateSnapshot | None = ctx.engine_latest_state()
    lines = ["== PortalKit 诊断（脱敏） ==", ""]
    snap = ctx.engine_latest_snapshot()
    if snap and snap.ready:
        label = f"{snap.ssid}" if snap.ssid else f"{snap.gateway or '-'} · {snap.interface}"
        lines.append(f"物理网络: {label}  IP: {snap.ipv4}  接口: {snap.interface}")
    else:
        lines.append("物理网络: 未连接")
    expiry = None
    if ctx.engine is not None:
        expiry = ctx.engine.session_expires_at()
    if expiry:
        lines.append(f"会话预计有效至: {expiry}")
    elif ctx.engine is not None:
        predicted = ctx.engine.session_predicted_expiry()
        if predicted:
            lines.append(f"会话预计有效至: {predicted}（学习值，按历史重登间隔估计）")
    if ctx.engine is not None and getattr(ctx.engine, "stats", None) is not None:
        summary = ctx.engine.stats.summary_today()
        if summary:
            lines.append(f"使用统计: {summary}")
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
    readable = _readable_events(ctx, tail=tail,
                                only_issues=bool(getattr(ctx, "only_issues", False)))
    lines += ["", "最近事件（最新在最上）:"] + [f"  {line}" for line in readable]
    return "\n".join(lines)


def _health_summary(ctx: "UIContext") -> tuple[str, str, str]:
    """三维健康卡的一句话摘要：(物理链路, 门户认证, 互联网可达)。"""
    state = ctx.engine_latest_state()
    snap = ctx.engine_latest_snapshot()
    if state is None:
        return ("未知", "未知", "未知")
    link_word = {
        "READY": "已就绪", "DISCONNECTED": "未连接",
        "CONFIGURING": "配置中", "ERROR": "错误",
    }.get(state.link.value, "未知")
    portal_word = {
        "AUTHENTICATED": "已通过", "NOT_REQUIRED": "无需认证",
        "AUTHENTICATING": "进行中", "TRUST_PENDING": "待确认",
        "DETECTED": "待确认", "INTERACTION_REQUIRED": "需人工",
        "FAILED": "失败",
    }.get(state.portal.value, "未知")
    internet_word = {
        "REACHABLE": "已通过", "CHECKING": "检查中",
        "BLOCKED": "未通过", "ERROR": "错误",
    }.get(state.internet.value, "未知")
    if snap is None or not snap.ready:
        link_word = "未连接"
    return (link_word, portal_word, internet_word)


def _health_payload(ctx: "UIContext") -> str:
    """复制到剪贴板的脱敏诊断 JSON（状态 + 快照 + 最近事件摘要）。"""
    state = ctx.engine_latest_state()
    snap = ctx.engine_latest_snapshot()
    events: list[dict] = []
    events_path = ctx.state_dir / "events.jsonl"
    if events_path.exists():
        for line in events_path.read_text(encoding="utf-8").splitlines()[-15:]:
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    payload = {
        "state": state.to_dict() if state else None,
        "network": snap.to_dict() if snap else None,
        "session_expires_at": (ctx.engine.session_expires_at() if ctx.engine else None),
        "recent_events": events,
    }
    return redact_text(json.dumps(payload, ensure_ascii=False, indent=2), max_len=200_000)


class DiagnosticsWindow:
    def __init__(self, ctx: "UIContext") -> None:
        self.ctx = ctx
        self.win = _window("PortalKit — 诊断与日志", 560, 470)
        c = self.win.contentView()
        # 三维健康卡（UI_UX_SPEC §7：三项检查卡，不用单一红绿）
        self.cards: list = []
        for index, title in enumerate(("物理链路", "门户认证", "互联网可达")):
            box = NSBox.alloc().initWithFrame_(
                NSMakeRect(20 + index * 178, 408, 164, 52)
            )
            box.setTitle_(title)
            value = _label(NSMakeRect(8, 0, 148, 18), "未知")
            box.setContentView_(value)
            c.addSubview_(box)
            self.cards.append(value)
        self.text, self.tv = _textview(NSMakeRect(20, 58, 520, 330))
        c.addSubview_(self.text)
        self.only_issues_toggle = _checkbox(
            NSMakeRect(20, 380, 300, 20), "只看异常与需要操作", False)
        c.addSubview_(self.only_issues_toggle)
        self._issues_bridge = _ActionBridge.alloc().initWithCallback_(self.refresh)
        self.only_issues_toggle.setTarget_(self._issues_bridge)
        self.only_issues_toggle.setAction_("call:")
        c.addSubview_(_button(NSMakeRect(20, 18, 110, 32), "重新检查", self.ctx.request_check))
        c.addSubview_(_button(NSMakeRect(150, 18, 90, 32), "刷新", self.refresh))
        c.addSubview_(_button(NSMakeRect(260, 18, 130, 32), "复制诊断信息", self._copy))
        c.addSubview_(_button(NSMakeRect(430, 18, 110, 32), "导出脱敏诊断", self._export))
        self.refresh()
        self._start_autorefresh()

    def _start_autorefresh(self) -> None:
        """打开期间每 2 秒自动刷新（用户反馈：事件在跑，窗口却停在打开
        瞬间的快照，等于"看不到日志"）。窗口不可见时跳过，零开销。"""
        from Foundation import NSRunLoop, NSTimer

        self._refresh_bridge = _ActionBridge.alloc().initWithCallback_(self._auto_refresh)
        timer = NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(
            2.0, self._refresh_bridge, "call:", None, True
        )
        NSRunLoop.mainRunLoop().addTimer_forMode_(timer, "kCFRunLoopCommonModes")

    def _auto_refresh(self) -> None:
        if self.win.isVisible():
            self.refresh()

    def refresh(self) -> None:
        self.ctx.only_issues = self.only_issues_toggle.state() == NSControlStateValueOn
        self.tv.setString_(_diagnostics_text(self.ctx))
        for label, word in zip(self.cards, _health_summary(self.ctx)):
            label.setStringValue_(word)

    def _copy(self) -> None:
        from AppKit import NSPasteboard

        text = _health_payload(self.ctx)
        pb = NSPasteboard.generalPasteboard()
        pb.clearContents()
        pb.setString_forType_(text, "public.utf8-plain-text")
        _confirm("已复制", "脱敏诊断 JSON 已复制到剪贴板。", "好")

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
        self.win = _window("PortalKit — 设置", 420, 236)
        settings = self.ctx.settings.get()
        form = FormLayout(self.win.contentView(), width=380, top=196)
        self.auto = form.checkbox("在已信任网络自动认证", settings.auto_auth)
        self.notify = form.checkbox("异常与需要操作时系统通知", settings.notify_on_error)
        form.space(4)
        form.label("兜底检查间隔")
        self.interval = form.popup([f"{s} 秒" for s in (30, 60, 120)], height=26)
        self.interval.selectItemAtIndex_((30, 60, 120).index(settings.check_interval_s))
        form.space(4)
        form.label("网络变化由系统事件驱动；此间隔仅为兜底。\n凭据保存在 Keychain，日志全程脱敏。", height=34)
        form.button_row([("保存", self._save), ("导出配置", self._export), ("导入配置", self._import)])
        self.refresh()

    def _export(self) -> None:
        from portalkit.core.config_io import export_config

        panel = NSSavePanel.savePanel()
        panel.setNameFieldStringValue_("portalkit-config.json")
        if panel.runModal() != NSModalResponseOK:
            return
        count = export_config(self.ctx.trust, self.ctx.settings, Path(panel.URL().path()))
        _confirm("已导出", f"已导出 {count} 个受信网络与设置。\n（不含 Keychain 凭据，凭据需在新机重新录入）", "好")

    def _import(self) -> None:
        from AppKit import NSOpenPanel
        from portalkit.core.config_io import import_config

        panel = NSOpenPanel.openPanel()
        panel.setAllowedFileTypes_(["json"])
        if panel.runModal() != NSModalResponseOK:
            return
        if not _confirm("导入配置",
                        "将合并导入受信网络与设置（凭据需重新录入）。\n继续导入所选文件？", "导入"):
            return
        try:
            n_t, n_s = import_config(self.ctx.trust, self.ctx.settings, Path(panel.URL().path()))
        except (ValueError, OSError) as exc:
            _confirm("导入失败", f"文件无法解析：{exc}", "好")
            return
        _confirm("已导入", f"导入 {n_t} 个受信网络、{n_s} 项设置。", "好")
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
