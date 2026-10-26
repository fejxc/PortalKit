"""菜单栏状态模板图标（AppKit 绘制，深浅色自适应 template image）。

状态不能只靠颜色表达（UI_UX_SPEC §9）——五种形态（实心圆/圆环/感叹/叉/斜线）
本身即为区分；颜色语义由菜单内文字与语义色补充。
"""

from __future__ import annotations

from pathlib import Path

from portalkit.models import Phase, StateSnapshot

ICON_NAMES = ("ok", "busy", "warn", "error", "offline")


def _draw_circle(fill: bool) -> None:
    from AppKit import NSBezierPath, NSColor, NSMakeRect

    path = NSBezierPath.bezierPathWithOvalInRect_(NSMakeRect(3, 3, 12, 12))
    if fill:
        NSColor.blackColor().setFill()
        path.fill()
    else:
        NSColor.blackColor().setStroke()
        path.setLineWidth_(2.0)
        path.stroke()


def _draw_warn() -> None:
    from AppKit import NSAttributedString, NSBezierPath, NSColor, NSFont, NSMakeRect, NSMakePoint

    path = NSBezierPath.bezierPath()
    path.moveToPoint_(NSMakePoint(9, 15.5))
    path.lineToPoint_(NSMakePoint(16.5, 2.5))
    path.lineToPoint_(NSMakePoint(1.5, 2.5))
    path.closePath()
    NSColor.blackColor().setStroke()
    path.setLineWidth_(1.6)
    path.stroke()
    attrs = {
        "NSFont": NSFont.boldSystemFontOfSize_(9.5),
        "NSColor": NSColor.blackColor(),
    }
    text = NSAttributedString.alloc().initWithString_attributes_("!", attrs)
    text.drawAtPoint_(NSMakePoint(7.2, 4.2))


def _draw_error() -> None:
    from AppKit import NSBezierPath, NSColor, NSMakePoint, NSMakeRect

    NSColor.blackColor().setStroke()
    circle = NSBezierPath.bezierPathWithOvalInRect_(NSMakeRect(2.5, 2.5, 13, 13))
    circle.setLineWidth_(2.0)
    circle.stroke()
    cross = NSBezierPath.bezierPath()
    cross.setLineWidth_(2.0)
    cross.moveToPoint_(NSMakePoint(6.2, 6.2))
    cross.lineToPoint_(NSMakePoint(11.8, 11.8))
    cross.moveToPoint_(NSMakePoint(11.8, 6.2))
    cross.lineToPoint_(NSMakePoint(6.2, 11.8))
    cross.stroke()


def _draw_offline() -> None:
    from AppKit import NSBezierPath, NSColor, NSMakePoint, NSMakeRect

    NSColor.blackColor().setStroke()
    circle = NSBezierPath.bezierPathWithOvalInRect_(NSMakeRect(2.5, 2.5, 13, 13))
    circle.setLineWidth_(2.0)
    circle.stroke()
    line = NSBezierPath.bezierPath()
    line.setLineWidth_(2.0)
    line.moveToPoint_(NSMakePoint(3.5, 3.5))
    line.lineToPoint_(NSMakePoint(14.5, 14.5))
    line.stroke()


_DRAWERS = {
    "ok": lambda: _draw_circle(fill=True),
    "busy": lambda: _draw_circle(fill=False),
    "warn": _draw_warn,
    "error": _draw_error,
    "offline": _draw_offline,
}


def ensure_icons(cache_dir: Path) -> dict[str, Path]:
    """生成(如缺)并返回各状态 PNG 路径。18×18pt @1x 足够菜单栏使用。"""
    from AppKit import NSBitmapImageFileTypePNG, NSBitmapImageRep, NSImage

    cache_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name in ICON_NAMES:
        path = cache_dir / f"status-{name}.png"
        paths[name] = path
        if path.exists():
            continue
        image = NSImage.alloc().initWithSize_((18.0, 18.0))
        image.lockFocus()
        _DRAWERS[name]()
        image.unlockFocus()
        image.setTemplate_(True)
        tiff = image.TIFFRepresentation()
        rep = NSBitmapImageRep.imageRepWithData_(tiff)
        png = rep.representationUsingType_properties_(NSBitmapImageFileTypePNG, {})
        png.writeToFile_atomically_(str(path), True)
    return paths


def icon_for_state(state: StateSnapshot | None) -> str:
    """StateSnapshot → 图标名。形态优先于颜色（无障碍要求）。"""
    if state is None:
        return "offline"
    if not state.interface or state.link.value == "DISCONNECTED":
        return "offline"
    if state.phase in (
        Phase.PROBING, Phase.MATCHING, Phase.AUTHENTICATING,
        Phase.VERIFYING, Phase.RETRY_BACKOFF,
    ):
        return "busy"
    if state.phase in (Phase.WAITING_USER, Phase.TRUST_REQUIRED, Phase.DEGRADED):
        return "warn"
    if state.phase == Phase.ERROR:
        return "error"
    return "ok"
