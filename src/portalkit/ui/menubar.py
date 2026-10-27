"""PortalKit 菜单栏宿主（原生 NSStatusItem，零第三方 UI 依赖）。

历史：v1.0.x 用 rumps/PyObjC，为兼容 pyobjc 12 monkeypatch 过库内部
（_nsimage_from_file）；1.1.0 起直接实现 NSStatusItem + NSMenu +
NSUserNotification，删除该补丁债，菜单/图标/通知行为完全受控。

职责边界（ARCHITECTURE §1）：只消费 core 的 StateSnapshot、只发命令，
不含任何第二套网络或状态机逻辑。引擎调用在独立工作线程；AppKit 全在
主线程（NSTimer 刷新）。

事件源：SCDynamicStore（network/scmonitor.py）+ NSWorkspace 睡眠/唤醒
通知 → 去抖 → engine.auto_run()；低频兜底检查按设置（30/60/120s）。
"""

from __future__ import annotations

import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from Foundation import NSObject, NSRunLoop, NSTimer

from portalkit.adapters import default_registry
from portalkit.adapters.base import DetectionResult
from portalkit.cli import DEFAULT_STATE_DIR, _build_engine
from portalkit.core.engine import Engine
from portalkit.core.settings import SettingsStore
from portalkit.core.trust import TrustRegistry
from portalkit.credentials.service import KeychainCredentialService
from portalkit.models import ErrorCode, Phase, StateSnapshot
from portalkit.network.interfaces import NetworkSnapshot, network_label
from portalkit.network.monitor import NetworkMonitor
from portalkit.network.scmonitor import SCNetworkListener
from portalkit.ui.icons import (
    ANIM_INTERVAL_S,
    icon_for_state,
    load_checking_frames,
    load_status_images,
    reduce_motion_enabled,
)
from portalkit.ui.windows import (
    _ActionBridge,
    CredentialsWindow,
    DiagnosticsWindow,
    ManagerWindow,
    OnboardingWindow,
    SettingsWindow,
)

_IN_FLIGHT = {
    Phase.PROBING, Phase.MATCHING, Phase.AUTHENTICATING,
    Phase.VERIFYING, Phase.RETRY_BACKOFF,
}

_TAG_BY_PHASE = {
    Phase.ONLINE_AUTHENTICATED: "已联网",
    Phase.ONLINE_NO_AUTH: "已联网",
    Phase.PROBING: "正在检查网络",
    Phase.MATCHING: "正在检查网络",
    Phase.AUTHENTICATING: "正在自动认证",
    Phase.VERIFYING: "正在验证联网",
    Phase.RETRY_BACKOFF: "正在重试",
    Phase.TRUST_REQUIRED: "发现认证网络",
    Phase.WAITING_USER: "需要操作",
    Phase.DEGRADED: "连接待验证",
    Phase.ERROR: "异常",
    Phase.CANCELLED: "已取消",
    Phase.IDLE: "空闲",
}


def _alert(title: str, info: str, ok: str, open_url: str | None = None) -> None:
    """结果弹窗（主线程回调内调用）；确认后可选打开链接。"""
    from AppKit import NSAlert, NSAlertFirstButtonReturn, NSURL, NSWorkspace

    alert = NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(info)
    alert.addButtonWithTitle_(ok)
    alert.addButtonWithTitle_("取消")
    if alert.runModal() == NSAlertFirstButtonReturn and open_url:
        NSWorkspace.sharedWorkspace().openURL_(NSURL.URLWithString_(open_url))


def _notify(title: str, message: str, *, action: str | None = None) -> None:
    """系统通知。action 非空时，点击通知触发该动作（见 _NotificationDelegate）。"""
    try:
        from AppKit import NSUserNotificationCenter
        from Foundation import NSUserNotification

        notification = NSUserNotification.alloc().init()
        notification.setTitle_(title)
        notification.setInformativeText_(message[:200])
        if action:
            notification.setUserInfo_({"action": action})
        center = NSUserNotificationCenter.defaultUserNotificationCenter()
        if center is not None:
            center.deliverNotification_(notification)
    except Exception as exc:  # noqa: BLE001 — 通知失败不影响主链路
        print(f"[portalkit-ui] notify failed: {type(exc).__name__}", flush=True)


class _NotificationDelegate(NSObject):
    """通知点击桥：仅在点击了带 action 的通知时回调。"""

    def initWithCallback_(self, callback: Callable[[str], None]):
        import objc

        self = objc.super(_NotificationDelegate, self).init()
        self.callback = callback
        return self

    def userNotificationCenter_didActivateNotification_(self, center, notification):  # noqa: N802
        from Foundation import NSUserNotificationActivationTypeContentsClicked

        if notification.activationType() != NSUserNotificationActivationTypeContentsClicked:
            return
        userinfo = notification.userInfo() or {}
        action = str((userinfo or {}).get("action", ""))
        if action:
            self.callback(action)


class _WakeBridge(NSObject):
    """系统睡眠/唤醒通知桥（NSWorkspace，主线程投递）→ 转交 worker 队列。"""

    def initWithCallback_(self, callback: Callable[[str], None]):
        import objc

        self = objc.super(_WakeBridge, self).init()
        self.callback = callback
        return self

    def onSleep_(self, note) -> None:  # noqa: N802
        self.callback("sleep")

    def onWake_(self, note) -> None:  # noqa: N802
        self.callback("wake")


@dataclass
class UIContext:
    engine: Engine
    monitor: NetworkMonitor
    trust: TrustRegistry
    credentials: KeychainCredentialService
    settings: SettingsStore
    state_dir: Path

    # ---- 回调由宿主注入（窗口 → 宿主命令，绝不直接触碰引擎线程）
    request_check: Callable[[], None] = lambda: None
    request_authenticate: Callable[[], None] = lambda: None
    open_credentials: Callable[[], None] = lambda: None
    on_settings_changed: Callable[[], None] = lambda: None
    logger = None  # RedactedLogger；由宿主赋值

    _holder: "StateHolder" = None  # type: ignore[assignment]

    def engine_latest_state(self) -> Optional[StateSnapshot]:
        return self._holder.get().state if self._holder else None

    def engine_latest_snapshot(self) -> Optional[NetworkSnapshot]:
        return self._holder.get().snapshot if self._holder else None


class StateHolder:
    """工作线程 → 主线程的唯一数据通道（线程安全）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Optional[StateSnapshot] = None
        self._snapshot: Optional[NetworkSnapshot] = None
        self._busy = False
        self._detection: Optional[DetectionResult] = None

    def update(self, state: StateSnapshot, snapshot: NetworkSnapshot | None, busy: bool) -> None:
        with self._lock:
            self._state, self._snapshot, self._busy = state, snapshot, busy

    def set_detection(self, detection: Optional[DetectionResult]) -> None:
        with self._lock:
            self._detection = detection

    def get(self) -> tuple[Optional[StateSnapshot], Optional[NetworkSnapshot], bool, Optional[DetectionResult]]:
        with self._lock:
            return self._state, self._snapshot, self._busy, self._detection


class EngineWorker(threading.Thread):
    """串行执行引擎命令；SC 事件在此线程去抖后调用 auto_run。"""

    def __init__(self, engine: Engine, settings: SettingsStore, holder: StateHolder) -> None:
        super().__init__(name="portalkit-engine-worker", daemon=True)
        self.engine = engine
        self.settings = settings
        self.holder = holder
        self.queue: queue.Queue = queue.Queue()
        self.sc_events = False

    def submit(self, command: str) -> None:
        self.queue.put((command, None))

    def run(self) -> None:
        self._set_busy(False)
        listener = SCNetworkListener(on_change=lambda: self.submit("network"))
        self.sc_events = listener.start()
        next_fallback = time.monotonic() + self._next_fallback_delay()
        while True:
            timeout = max(0.5, next_fallback - time.monotonic())
            try:
                command, _ = self.queue.get(timeout=timeout)
            except queue.Empty:
                command = "fallback"
            if command == "quit":
                return
            if command == "network":
                self._debounce()
                self._run("auto")
                next_fallback = time.monotonic() + self._next_fallback_delay()
            elif command == "fallback":
                if self.sc_events:
                    # SC 事件可用时兜底只做轻量对齐，避免与事件重复全量认证
                    self._run("check")
                else:
                    self._run("auto")
                next_fallback = time.monotonic() + self._next_fallback_delay()
            elif command == "check":
                self._run("check")
            elif command == "detect":
                self._detect()
            elif command == "authenticate":
                self._run("authenticate")
            elif command == "refresh-session":
                self._run("refresh-session")
            elif command == "cancel":
                self.engine.request_cancel()
            elif command == "sleep":
                self.engine._log.event("system_sleep")  # noqa: SLF001
                print("[portalkit-ui] system sleep", flush=True)
                self.engine.request_cancel()  # 睡眠中在途请求必死，主动转为干净取消
            elif command == "wake":
                self.engine._log.event("system_wake")  # noqa: SLF001
                print("[portalkit-ui] system wake — recheck", flush=True)
                self._debounce()
                self._run("auto")
                next_fallback = time.monotonic() + self._next_fallback_delay()
            elif command == "settings_changed":
                next_fallback = min(
                    next_fallback, time.monotonic() + self._next_fallback_delay()
                )

    def _next_fallback_delay(self) -> float:
        """兜底间隔 = 设置值与会话"到期前余量窗口"取近者。

        会话临近过期时提前加密检查（只加检查、不加凭据提交——是否重登
        仍由 auto_run 的在线判定决定，遵守 A03）。
        """
        base = float(self.settings.get().check_interval_s)
        expires = self.engine.session_expires_at()
        if not expires:
            return base
        try:
            expiry = datetime.fromisoformat(expires)
        except ValueError:
            return base
        margin = timedelta(minutes=30)
        seconds_to_margin = (expiry - margin - datetime.now(timezone.utc)).total_seconds()
        if seconds_to_margin <= 0:
            return min(base, 30.0)  # 已进入余量窗口：尽快复查（限流防打转）
        return max(30.0, min(base, seconds_to_margin))

    def _debounce(self, delay: float = 1.2) -> None:
        """网络事件去抖：窗口期内的新事件并入一次处理（STATE_MODEL §3）。"""
        deadline = time.monotonic() + delay
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                self.queue.get(timeout=remaining)
            except queue.Empty:
                return

    def _run(self, kind: str) -> None:
        self._set_busy(True)
        try:
            if kind == "check":
                state = self.engine.check()
            elif kind == "authenticate":
                state = self.engine.authenticate()
            elif kind == "refresh-session":
                state = self.engine.refresh_session()
            else:
                if self.settings.get().auto_auth:
                    state = self.engine.auto_run()
                else:
                    state = self.engine.check()
            self.holder.update(state, self.engine._monitor.current_snapshot(), False)  # noqa: SLF001
            print(
                f"[portalkit-ui] engine {kind}: phase={state.phase.value} "
                f"err={state.error_code.value} gen={state.network_generation} "
                f"iface={state.interface}",
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001 — 工作线程兜底
            print(f"[portalkit-ui] engine error: {type(exc).__name__}: {exc}", flush=True)
            self._set_busy(False)

    def _detect(self) -> None:
        try:
            report = self.engine.detect()
            matched = next(
                (r for r in report.results if r.matched and r.adapter_id), None
            )
            self.holder.set_detection(matched)
        except Exception as exc:  # noqa: BLE001
            print(f"[portalkit-ui] detect error: {type(exc).__name__}: {exc}", flush=True)
            self.holder.set_detection(None)

    def _set_busy(self, busy: bool) -> None:
        snapshot = self.engine._monitor.current_snapshot()  # noqa: SLF001
        state, _, _, _ = self.holder.get()
        self.holder.update(state, snapshot, busy)


class PortalKitStatusBar:
    """NSStatusItem 菜单栏宿主（原生实现）。"""

    def __init__(self, ctx: UIContext) -> None:
        from AppKit import (
            NSApplication,
            NSApplicationActivationPolicyAccessory,
            NSStatusBar,
            NSStatusItem,
            NSVariableStatusItemLength,
        )

        # 必须最先初始化 NSApplication——任何 AppKit UI 对象（状态项/菜单）
        # 在它之前创建会触发 CGSConnectionByID 断言崩溃（2026-10-27 实测）。
        self._app = NSApplication.sharedApplication()
        self._app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)

        self.ctx = ctx
        self.icons = load_status_images()
        self.checking_frames = load_checking_frames()
        self._frame_index = 0
        self._anim_shown: str | None = None
        self._bridges: list = []
        self._windows: dict[str, object] = {}
        self._last_notify_key: tuple | None = None
        self._last_rendered: str | None = None

        self._holder = StateHolder()
        self.ctx._holder = self._holder
        self.ctx.request_check = lambda: self.worker.submit("check")
        self.ctx.request_authenticate = lambda: self.worker.submit("authenticate")
        self.ctx.open_credentials = self._on_credentials
        self.ctx.on_settings_changed = lambda: self.worker.submit("settings_changed")
        self.ctx.logger = self.ctx.engine._log  # noqa: SLF001

        self.worker = EngineWorker(ctx.engine, ctx.settings, self._holder)

        # ---- 状态项
        self._status_item = (
            NSStatusBar.systemStatusBar().statusItemWithLength_(NSVariableStatusItemLength)
        )
        button = self._status_item.button()
        button.setImage_(self.icons["offline"])
        button.setToolTip_("PortalKit — 正在启动…")

        self._build_menu()

        self.worker.start()
        self.worker.submit("check")
        self._register_sleep_wake_listener()
        self._register_notification_delegate()

        # ---- 定时器（主 runloop）
        self._timer = NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(
            1.0, self._bridge(self._tick), "call:", None, True
        )
        NSRunLoop.mainRunLoop().addTimer_forMode_(self._timer, "kCFRunLoopCommonModes")
        self._anim_timer = NSTimer.timerWithTimeInterval_target_selector_userInfo_repeats_(
            ANIM_INTERVAL_S, self._bridge(self._animate), "call:", None, True
        )
        NSRunLoop.mainRunLoop().addTimer_forMode_(self._anim_timer, "kCFRunLoopCommonModes")

    # -------------------------------------------------------------- build

    def _bridge(self, callback: Callable[[], None]):
        """target 是 unsafe_unretained：桥接对象必须持久持有。"""
        bridge = _ActionBridge.alloc().initWithCallback_(callback)
        self._bridges.append(bridge)
        return bridge

    def _build_menu(self) -> None:
        from AppKit import NSMenu, NSMenuItem

        menu = NSMenu.alloc().init()
        menu.setAutoenablesItems_(False)

        def add(title: str, callback=None, key: str = "", enabled: bool = True):
            item = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
                title, "call:" if callback else None, key
            )
            if callback:
                item.setTarget_(self._bridge(callback))
            item.setEnabled_(enabled)
            menu.addItem_(item)
            return item

        self._hdr_tag = add("PortalKit — 空闲")
        self._hdr_detail = add("正在等待首次检查…")
        menu.addItem_(NSMenuItem.separatorItem())
        add("重新检查网络", self._on_check, key="r")
        add("立即认证", self._on_authenticate)
        add("强制刷新会话", self._on_refresh_session)
        add("取消当前任务", self._on_cancel)
        add("检查更新…", self._on_check_updates)
        menu.addItem_(NSMenuItem.separatorItem())
        add("添加 / 确认可信网络…", self._on_onboarding)
        add("录入 / 更新凭据…", self._on_credentials)
        add("管理可信网络…", self._on_manage)
        add("诊断与日志…", self._on_diagnostics)
        add("设置…", self._on_settings)
        menu.addItem_(NSMenuItem.separatorItem())
        add("退出 PortalKit", self._on_quit, key="q")
        self._status_item.setMenu_(menu)

    def _register_sleep_wake_listener(self) -> None:
        """NSWorkspace 睡眠/唤醒通知（主线程投递）→ worker 队列。"""
        try:
            from AppKit import NSWorkspace
            from Foundation import NSNotificationCenter

            self._wake_bridge = _WakeBridge.alloc().initWithCallback_(
                self.worker.submit
            )
            center = NSWorkspace.sharedWorkspace().notificationCenter()
            center.addObserver_selector_name_object_(
                self._wake_bridge, "onWake:", "NSWorkspaceDidWakeNotification", None
            )
            center.addObserver_selector_name_object_(
                self._wake_bridge, "onSleep:", "NSWorkspaceWillSleepNotification", None
            )
            print("[portalkit-ui] sleep/wake listener armed", flush=True)
        except Exception as exc:  # noqa: BLE001 — 监听失败降级为 SC+兜底
            print(f"[portalkit-ui] sleep/wake listener unavailable: {exc}", flush=True)

    def _register_notification_delegate(self) -> None:
        try:
            from AppKit import NSUserNotificationCenter

            self._notif_delegate = _NotificationDelegate.alloc().initWithCallback_(
                self._on_notification_action
            )
            center = NSUserNotificationCenter.defaultUserNotificationCenter()
            if center is not None:
                center.setDelegate_(self._notif_delegate)
                print("[portalkit-ui] notification delegate armed", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[portalkit-ui] notification delegate unavailable: {exc}", flush=True)

    # ----------------------------------------------------------- handlers

    def _on_check(self) -> None:
        self.worker.submit("check")

    def _on_authenticate(self) -> None:
        self.worker.submit("authenticate")

    def _on_refresh_session(self) -> None:
        self.worker.submit("refresh-session")

    def _on_cancel(self) -> None:
        self.worker.submit("cancel")

    def _on_notification_action(self, action: str) -> None:
        if action == "onboarding":
            self._on_onboarding()

    def _on_onboarding(self) -> None:
        win = self._windows.get("onboarding")
        if win is None:
            win = OnboardingWindow(self.ctx)
            self._windows["onboarding"] = win
        win.present_with_detection(None)
        self._holder.set_detection(None)
        self.worker.submit("detect")

    def _on_credentials(self, _sender=None) -> None:
        if "credentials" not in self._windows:
            self._windows["credentials"] = CredentialsWindow(self.ctx)
        self._windows["credentials"].show()

    def _on_manage(self) -> None:
        if "manage" not in self._windows:
            self._windows["manage"] = ManagerWindow(self.ctx)
        self._windows["manage"].show()

    def _on_diagnostics(self) -> None:
        if "diagnostics" not in self._windows:
            self._windows["diagnostics"] = DiagnosticsWindow(self.ctx)
        self._windows["diagnostics"].show()

    def _on_settings(self) -> None:
        if "settings" not in self._windows:
            self._windows["settings"] = SettingsWindow(self.ctx)
        self._windows["settings"].show()

    def _on_check_updates(self) -> None:
        from portalkit import __version__
        from portalkit.ui.updates import check_for_update

        info = check_for_update(__version__)
        if info is None:
            _alert("检查更新", "无法查询 GitHub Release（网络不可达或超时）。", "好")
        elif info.has_update:
            _alert(
                "发现新版本",
                f"最新版本 {info.latest_tag}，当前 {__version__}。\n{info.url}",
                "打开 Releases 页面",
                open_url=info.url,
            )
        else:
            _alert("已是最新", f"当前版本 {__version__} 已是最新。", "好")

    def _on_quit(self) -> None:
        self.worker.submit("quit")
        self._app.terminate_(None)  # 正常退出（0）：launchd 不再拉起

    # ---------------------------------------------------------- ui refresh

    def _tick(self) -> None:
        try:
            self._tick_inner()
        except Exception as exc:  # noqa: BLE001 — 计时回调兜底，避免静默死亡
            import traceback

            print(f"[portalkit-ui] tick error: {type(exc).__name__}: {exc}", flush=True)
            traceback.print_exc()

    def _animate(self) -> None:
        """checking 旋转动画：只在状态为 checking 且未降动态时轮换帧。"""
        try:
            state, _, _, _ = self._holder.get()
            if icon_for_state(state) != "checking" or not self.checking_frames:
                self._anim_shown = None
                return
            if reduce_motion_enabled():
                if self._anim_shown != "static":
                    self._set_icon(self.icons["checking"])
                    self._anim_shown = "static"
                return
            frame = self.checking_frames[self._frame_index % len(self.checking_frames)]
            self._frame_index += 1
            self._set_icon(frame)
            self._anim_shown = "anim"
        except Exception as exc:  # noqa: BLE001
            print(f"[portalkit-ui] anim error: {type(exc).__name__}: {exc}", flush=True)

    def _set_icon(self, image) -> None:
        self._status_item.button().setImage_(image)

    def _tick_inner(self) -> None:
        state, snapshot, busy, detection = self._holder.get()
        if detection is not None and "onboarding" in self._windows:
            onboarding = self._windows["onboarding"]
            if onboarding.win.isVisible():
                onboarding.present_with_detection(detection)
                self._holder.set_detection(None)
                return
        name = icon_for_state(state)
        # checking 时交给动画帧，避免 1s tick 抢设静态图
        if not (name == "checking" and self.checking_frames and self._anim_shown == "anim"):
            self._set_icon(self.icons[name])
        if state is None:
            return
        tag = _TAG_BY_PHASE.get(state.phase, state.phase.value)
        self._hdr_tag.setTitle_(f"PortalKit — {tag}")
        detail = state.detail or state.message_key
        # 网络名：SSID 优先（定位授权时），缺省网关·接口摘要
        label = network_label(snapshot) if snapshot else None
        show_iface = state.interface and not (snapshot and snapshot.ssid)
        iface = f" · {state.interface}" if show_iface else ""
        text = f"{label} · {detail}{iface}" if label else f"{detail}{iface}"
        if len(text) > 140:
            text = text[:139].rstrip() + "…"
        self._hdr_detail.setTitle_(text)
        if tag != self._last_rendered:
            self._last_rendered = tag
            print(f"[portalkit-ui] ui: {tag} ({state.error_code.value})", flush=True)
        self._maybe_notify(state)

    def _maybe_notify(self, state: StateSnapshot) -> None:
        settings = self.ctx.settings.get()
        if not settings.notify_on_error:
            return
        attention = state.phase in (
            Phase.WAITING_USER, Phase.TRUST_REQUIRED, Phase.DEGRADED,
        ) or (state.phase == Phase.ERROR and state.error_code != ErrorCode.NONE)
        if not attention:
            return
        key = (state.network_generation, state.phase.value, state.error_code.value)
        if key == self._last_notify_key:
            return
        self._last_notify_key = key
        action = "onboarding" if state.phase == Phase.TRUST_REQUIRED else None
        _notify(
            "PortalKit",
            f"{_TAG_BY_PHASE.get(state.phase, state.phase.value)} — {state.detail or state.message_key}",
            action=action,
        )

    # ---------------------------------------------------------------- run

    def run(self) -> None:
        self._app.run()


# --------------------------------------------------------------- bootstrap

def build_context() -> UIContext:
    engine = _build_engine()
    monitor = engine._monitor  # noqa: SLF001 — 同包宿主
    return UIContext(
        engine=engine,
        monitor=monitor,
        trust=TrustRegistry(),
        credentials=KeychainCredentialService(),
        settings=SettingsStore(),
        state_dir=DEFAULT_STATE_DIR,
    )


def _single_instance_guard(state_dir: Path) -> bool:
    """返回 True 表示可以继续；已有实例在跑则 False。

    pid 存活检查必须同时验证进程身份——PID 可能被系统复用给无关进程
    （2026-10-26 实测：旧 pid 被复用导致新实例永远无法启动）。
    """
    lock = state_dir / "ui.pid"
    state_dir.mkdir(parents=True, exist_ok=True)
    if lock.exists():
        try:
            pid = int(lock.read_text().strip())
            proc = subprocess.run(
                ["ps", "-p", str(pid), "-o", "args="],
                capture_output=True, text=True, timeout=5, check=False,
            )
            args_text = proc.stdout
            if "portalkit.ui.menubar" in args_text or "PortalKit.app" in args_text:
                return False  # 确认是另一个 PortalKit 实例
        except (ValueError, OSError, subprocess.SubprocessError):
            pass
    lock.write_text(str(os.getpid()))
    import atexit

    atexit.register(lambda: lock.unlink(missing_ok=True))
    return True


def main() -> int:
    if not _single_instance_guard(DEFAULT_STATE_DIR):
        print("PortalKit 菜单栏已在运行。", flush=True)
        return 0
    host = PortalKitStatusBar(build_context())
    try:
        host.run()
    finally:
        host.worker.submit("quit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
