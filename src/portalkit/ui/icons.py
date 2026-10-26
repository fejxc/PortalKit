"""菜单栏状态模板图标（AppKit 绘制，深浅色菜单栏自适应）。

设计语言（用户提供的设计稿，2026-10-26）：圆角"门/拱门"轮廓（portal 意象）
+ 内部状态元素。按 macOS 菜单栏规范使用单色 template image——系统自动适配
深浅色菜单栏；状态不能只靠颜色区分（UI_UX_SPEC §9），因此六个形态各异：
空闲(点) / 检测中(弧) / 认证中(盾) / 已联网(实心圆) / 需处理(叹号三角) / 离线(×)。

ICON_VERSION 变更会使缓存失效（确保新版设计覆盖旧 PNG）。
"""

from __future__ import annotations

from pathlib import Path

from portalkit.models import Phase, StateSnapshot

ICON_VERSION = "v2-door"
ICON_NAMES = ("idle", "busy", "auth", "ok", "warn", "offline")


def _stroke_door() -> None:
    """画 ∩ 形门/拱轮廓（圆角、圆头笔画）。"""
    from AppKit import NSBezierPath, NSColor

    path = NSBezierPath.bezierPath()
    path.setLineWidth_(2.2)
    path.setLineCapStyle_(2)  # NSRoundLineCapStyle
    path.moveToPoint_((3.6, 2.0))
    path.lineToPoint_((3.6, 12.0))
    path.appendBezierPathWithArcFromPoint_toPoint_radius_((3.6, 15.4), (9.0, 15.4), 3.4)
    path.lineToPoint_((9.0, 15.4))
    path.appendBezierPathWithArcFromPoint_toPoint_radius_((14.4, 15.4), (14.4, 12.0), 3.4)
    path.lineToPoint_((14.4, 2.0))
    NSColor.blackColor().setStroke()
    path.stroke()


def _dot(x: float, y: float, r: float, fill: bool = True) -> None:
    from AppKit import NSBezierPath, NSColor, NSMakeRect

    path = NSBezierPath.bezierPathWithOvalInRect_(NSMakeRect(x - r, y - r, 2 * r, 2 * r))
    if fill:
        NSColor.blackColor().setFill()
        path.fill()
    else:
        NSColor.blackColor().setStroke()
        path.setLineWidth_(1.8)
        path.stroke()


def _draw_idle() -> None:
    _stroke_door()
    _dot(9.0, 5.2, 1.7, fill=False)  # 底部空心点：待机


def _draw_busy() -> None:
    from AppKit import NSBezierPath, NSColor

    _stroke_door()
    arc = NSBezierPath.bezierPath()
    arc.setLineWidth_(2.0)
    arc.appendBezierPathWithArcWithCenter_radius_startAngle_endAngle_(
        (9.0, 5.6), 3.2, 150.0, 30.0  # 逆时针经顶部(90°)的上弧（检测中）
    )
    NSColor.blackColor().setStroke()
    arc.stroke()


def _draw_auth() -> None:
    from AppKit import NSBezierPath, NSColor, NSMakePoint

    _stroke_door()
    shield = NSBezierPath.bezierPath()
    shield.moveToPoint_((9.0, 10.2))
    shield.lineToPoint_((12.6, 8.6))
    shield.lineToPoint_((12.6, 5.8))
    shield.appendBezierPathWithArcFromPoint_toPoint_radius_((9.0, 2.6), (5.4, 5.8), 1.2)
    shield.lineToPoint_((5.4, 8.6))
    shield.closePath()
    NSColor.blackColor().setStroke()
    shield.setLineWidth_(1.6)
    shield.stroke()
    _dot(9.0, 6.6, 1.0)  # 盾心（认证中）


def _draw_ok() -> None:
    _stroke_door()
    _dot(9.0, 5.6, 3.0)  # 实心圆：已联网


def _draw_warn() -> None:
    from AppKit import NSAttributedString, NSBezierPath, NSColor, NSFont, NSMakePoint

    _stroke_door()
    tri = NSBezierPath.bezierPath()
    tri.moveToPoint_((9.0, 9.8))
    tri.lineToPoint_((12.2, 3.0))
    tri.lineToPoint_((5.8, 3.0))
    tri.closePath()
    NSColor.blackColor().setStroke()
    tri.setLineWidth_(1.5)
    tri.stroke()
    attrs = {"NSFont": NSFont.boldSystemFontOfSize_(7.0), "NSColor": NSColor.blackColor()}
    NSAttributedString.alloc().initWithString_attributes_("!", attrs).drawAtPoint_(
        NSMakePoint(7.9, 3.4)
    )


def _draw_offline() -> None:
    from AppKit import NSBezierPath, NSColor

    _stroke_door()
    cross = NSBezierPath.bezierPath()
    cross.setLineWidth_(2.0)
    cross.moveToPoint_((6.8, 3.4))
    cross.lineToPoint_((11.2, 7.8))
    cross.moveToPoint_((11.2, 3.4))
    cross.lineToPoint_((6.8, 7.8))
    NSColor.blackColor().setStroke()
    cross.stroke()


_DRAWERS = {
    "idle": _draw_idle,
    "busy": _draw_busy,
    "auth": _draw_auth,
    "ok": _draw_ok,
    "warn": _draw_warn,
    "offline": _draw_offline,
}


def ensure_icons(cache_dir: Path) -> dict[str, Path]:
    """生成(如缺)并返回各状态 PNG 路径。18×18pt 模板图。"""
    from AppKit import NSBitmapImageFileTypePNG, NSBitmapImageRep, NSImage

    cache_dir.mkdir(parents=True, exist_ok=True)
    # 旧版本图标清理（设计升级后避免残留）
    for stale in cache_dir.glob("status-*.png"):
        if ICON_VERSION not in stale.name:
            stale.unlink(missing_ok=True)
    paths: dict[str, Path] = {}
    for name in ICON_NAMES:
        path = cache_dir / f"status-{name}-{ICON_VERSION}.png"
        paths[name] = path
        if path.exists():
            continue
        image = NSImage.alloc().initWithSize_((18.0, 18.0))
        image.lockFocus()
        _DRAWERS[name]()
        image.unlockFocus()
        image.setTemplate_(True)
        rep = NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())
        png = rep.representationUsingType_properties_(NSBitmapImageFileTypePNG, {})
        png.writeToFile_atomically_(str(path), True)
    return paths


def icon_for_state(state: StateSnapshot | None) -> str:
    """StateSnapshot → 菜单栏图标名（形态优先，不依赖颜色）。"""
    if state is None:
        return "offline"
    if not state.interface or state.link.value == "DISCONNECTED":
        return "offline"
    if state.phase in (Phase.PROBING, Phase.MATCHING, Phase.RETRY_BACKOFF):
        return "busy"  # 检测中
    if state.phase in (Phase.AUTHENTICATING, Phase.VERIFYING):
        return "auth"  # 认证中
    if state.phase in (Phase.WAITING_USER, Phase.TRUST_REQUIRED, Phase.DEGRADED, Phase.ERROR):
        return "warn"  # 需处理
    if state.phase == Phase.IDLE:
        return "idle"
    return "ok"  # ONLINE_*
