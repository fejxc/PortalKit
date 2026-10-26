"""PortalKit 菜单栏宿主（rumps/PyObjC）。

职责边界（ARCHITECTURE §1 / PRD F11）：只消费 core 的 StateSnapshot、
只发命令（check/authenticate/cancel/settings），不含任何第二套网络或
状态机逻辑。所有引擎调用在独立工作线程执行；AppKit 全部在主线程
（rumps Timer 轮询线程安全的 StateHolder 刷新 UI）。

事件源：SCDynamicStore（network/scmonitor.py）→ 去抖 → engine.auto_run()；
低频兜底检查按设置（30/60/120s，默认 120）。
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

import rumps

from portalkit.adapters import default_registry


def _patch_rumps_nsimage() -> None:
    """绕过 rumps 0.4 × pyobjc 12 兼容 bug：initByReferencingFile_ 在
    Python 3.14 下抛 OC_PythonURL length 异常，导致状态图标永远无法更新
    （2026-10-26 实测）。语义等价替换为 initWithContentsOfFile_。"""
    from AppKit import NSImage
    import rumps.rumps as _rumps_mod

    def _nsimage_from_file(filename, template=None, dimensions=None):
        image = NSImage.alloc().initWithContentsOfFile_(str(filename))
        if image is None:
            return None
        image.setScalesWhenResized_(True)
        image.setSize_((20, 20) if dimensions is None else dimensions)
        if template is not None:
            image.setTemplate_(template)
        return image

    _rumps_mod._nsimage_from_file = _nsimage_from_file


_patch_rumps_nsimage()

from portalkit.cli import DEFAULT_STATE_DIR, _build_engine  # noqa: E402
from portalkit.adapters.base import DetectionResult  # noqa: E402
from portalkit.core.engine import Engine
from portalkit.core.settings import Settings, SettingsStore
from portalkit.core.trust import TrustRegistry
from portalkit.credentials.service import KeychainCredentialService
from portalkit.models import ErrorCode, Phase, StateSnapshot
from portalkit.network.interfaces import NetworkSnapshot, network_label
from portalkit.network.monitor import NetworkMonitor
from portalkit.network.scmonitor import SCNetworkListener
from portalkit.ui.icons import ensure_icons, icon_for_state
from portalkit.ui.windows import (
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


def _confirm_update_box(title: str, info: str, ok: str, open_url: str | None = None) -> None:
    """更新检查结果弹窗（主线程回调内调用）；确认后可选打开 Releases 页。"""
    from AppKit import NSAlert, NSAlertFirstButtonReturn, NSURL, NSWorkspace

    alert = NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(info)
    alert.addButtonWithTitle_(ok)
    alert.addButtonWithTitle_("取消")
    if alert.runModal() == NSAlertFirstButtonReturn and open_url:
        NSWorkspace.sharedWorkspace().openURL_(NSURL.URLWithString_(open_url))

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
    logger = None  # RedactedLogger；由 build_context 赋值

    def engine_latest_state(self) -> Optional[StateSnapshot]:
        return self._holder.get().state if self._holder else None

    def engine_latest_snapshot(self) -> Optional[NetworkSnapshot]:
        return self._holder.get().snapshot if self._holder else None

    _holder: "StateHolder" = None  # type: ignore[assignment]


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
        self.queue: queue.Queue[tuple[str, None]] = queue.Queue()
        self.sc_events = False  # SC 监听是否可用（决定兜底间隔的意义）

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
                empty = False
            except queue.Empty:
                command, empty = "fallback", True
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


class PortalKitApp(rumps.App):
    def __init__(self, ctx: UIContext) -> None:
        self.ctx = ctx
        self.icons = ensure_icons(ctx.state_dir / "icons")
        super().__init__(
            name="PortalKit", icon=str(self.icons["offline"]),
            template=True, quit_button=None,
        )
        self.template = True
        self._hdr_tag = rumps.MenuItem("PortalKit — 空闲")
        self._hdr_detail = rumps.MenuItem("正在等待首次检查…")
        self.menu = [
            self._hdr_tag, self._hdr_detail,
            None,
            rumps.MenuItem("重新检查网络", key="r", callback=self._on_check),
            rumps.MenuItem("立即认证", callback=self._on_authenticate),
            rumps.MenuItem("强制刷新会话", callback=self._on_refresh_session),
            rumps.MenuItem("取消当前任务", callback=self._on_cancel),
            rumps.MenuItem("检查更新…", callback=self._on_check_updates),
            None,
            rumps.MenuItem("添加 / 确认可信网络…", callback=self._on_onboarding),
            rumps.MenuItem("录入 / 更新凭据…", callback=self._on_credentials),
            rumps.MenuItem("管理可信网络…", callback=self._on_manage),
            rumps.MenuItem("诊断与日志…", callback=self._on_diagnostics),
            rumps.MenuItem("设置…", callback=self._on_settings),
            None,
            rumps.MenuItem("退出 PortalKit", key="q", callback=rumps.quit_application),
        ]
        self._holder = StateHolder()
        self.ctx._holder = self._holder
        self.ctx.request_check = lambda: self.worker.submit("check")
        self.ctx.request_authenticate = lambda: self.worker.submit("authenticate")
        self.ctx.open_credentials = self._on_credentials
        self.ctx.on_settings_changed = lambda: self.worker.submit("settings_changed")
        self.ctx.logger = self.ctx.engine._log  # noqa: SLF001
        self.worker = EngineWorker(ctx.engine, ctx.settings, self._holder)
        self.worker.start()
        self.worker.submit("check")
        self._windows: dict[str, object] = {}
        self._last_notify_key: tuple | None = None
        self._last_rendered: str | None = None
        self._timer = rumps.Timer(self._tick, 1)
        self._timer.start()

    # ------------------------------------------------------------ callbacks

    def _on_check(self, _sender=None) -> None:
        self.worker.submit("check")

    def _on_authenticate(self, _sender=None) -> None:
        self.worker.submit("authenticate")

    def _on_refresh_session(self, _sender=None) -> None:
        self.worker.submit("refresh-session")

    def _on_check_updates(self, _sender=None) -> None:
        from portalkit import __version__
        from portalkit.ui.updates import check_for_update

        info = check_for_update(__version__)
        if info is None:
            _confirm_update_box("检查更新", "无法查询 GitHub Release（网络不可达或超时）。", "好")
        elif info.has_update:
            _confirm_update_box(
                "发现新版本",
                f"最新版本 {info.latest_tag}，当前 {__version__}。\n{info.url}",
                "打开 Releases 页面",
                open_url=info.url,
            )
        else:
            _confirm_update_box("已是最新", f"当前版本 {__version__} 已是最新。", "好")

    def _on_cancel(self, _sender=None) -> None:
        self.worker.submit("cancel")

    def _on_onboarding(self, _sender=None) -> None:
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

    def _on_manage(self, _sender=None) -> None:
        if "manage" not in self._windows:
            self._windows["manage"] = ManagerWindow(self.ctx)
        self._windows["manage"].show()

    def _on_diagnostics(self, _sender=None) -> None:
        if "diagnostics" not in self._windows:
            self._windows["diagnostics"] = DiagnosticsWindow(self.ctx)
        self._windows["diagnostics"].show()

    def _on_settings(self, _sender=None) -> None:
        if "settings" not in self._windows:
            self._windows["settings"] = SettingsWindow(self.ctx)
        self._windows["settings"].show()

    # ------------------------------------------------------------ ui refresh

    def _tick(self, _timer) -> None:
        try:
            self._tick_inner()
        except Exception as exc:  # noqa: BLE001 — 计时回调兜底，避免静默死亡
            import traceback

            print(f"[portalkit-ui] tick error: {type(exc).__name__}: {exc}", flush=True)
            traceback.print_exc()

    def _tick_inner(self) -> None:
        state, snapshot, busy, detection = self._holder.get()
        if detection is not None and "onboarding" in self._windows:
            onboarding = self._windows["onboarding"]
            if onboarding.win.isVisible():
                onboarding.present_with_detection(detection)
                self._holder.set_detection(None)
                return
        self.icon = self.icons[icon_for_state(state)]
        if state is None:
            return
        tag = _TAG_BY_PHASE.get(state.phase, state.phase.value)
        self._hdr_tag.title = f"PortalKit — {tag}"
        detail = state.detail or state.message_key
        # 网络名：SSID 优先（定位授权时），缺省网关·接口摘要
        label = network_label(snapshot) if snapshot else None
        show_iface = state.interface and not (snapshot and snapshot.ssid)
        iface = f" · {state.interface}" if show_iface else ""
        self._hdr_detail.title = (
            f"{label} · {detail}{iface}" if label else f"{detail}{iface}"
        )[:140]
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
        rumps.notification(
            title="PortalKit",
            subtitle=_TAG_BY_PHASE.get(state.phase, state.phase.value),
            message=(state.detail or state.message_key)[:120],
        )


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
    app = PortalKitApp(build_context())
    try:
        app.run()
    finally:
        app.worker.submit("quit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
