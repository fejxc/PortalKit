"""菜单栏状态图标：单色拱门素材（PortalKit_Monochrome_Icons_v2）。

设计语言：统一拱门轮廓 + 五互斥状态（offline × / checking ↻ / online • /
action ! / unknown ?），与 App Logo 同一形状语言——比多形态彩色版更安静。

接入（素材包 docs/IMPLEMENTATION.md）：PNG 以 `NSImage.isTemplate = true`
装载，由 macOS 按菜单栏明暗自动着色——黑白两套 PNG 中只使用 black 版
（template 规范：黑色 + alpha），**不要**在深色模式手动切换白色图标。
显示 18×18 pt，36 px PNG 作为 2x representation 提供 Retina 清晰度。

动画：checking 的 8 帧（素材建议 100–150ms/帧）仅在后台确有网络任务时
轮换；尊重系统"降低动态效果"设置（静态 checking 图）。
"""

from __future__ import annotations

import sys
from pathlib import Path

from portalkit.models import Phase, StateSnapshot

ICON_NAMES = ("offline", "checking", "online", "action", "unknown")
CHECKING_FRAMES = 8
ANIM_INTERVAL_S = 0.12  # 素材建议 100–150 ms/帧


def _project_assets_dir() -> Path:
    """素材目录：开发态=仓库 assets；打包态=PyInstaller 解包目录。"""
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        candidate = base / "assets" / "monochrome"
        if candidate.exists():
            return candidate
        return Path(sys.executable).parent.parent / "Resources" / "assets" / "monochrome"
    return Path(__file__).resolve().parents[3] / "assets" / "monochrome"


def assets_dir() -> Path:
    return _project_assets_dir()


def _load_template(png_18: Path, png_36: Path | None) -> object:
    """装载 18pt template NSImage；36px 作为 2x representation（Retina）。"""
    from AppKit import NSImage

    image = NSImage.alloc().initWithContentsOfFile_(str(png_18))
    if image is None:
        raise RuntimeError(f"图标缺失: {png_18}")
    if png_36 and png_36.exists():
        rep = NSImage.alloc().initWithContentsOfFile_(str(png_36))
        if rep is not None:
            for r in rep.representations():
                r.setSize_((18.0, 18.0))
                image.addRepresentation_(r)
    image.setSize_((18.0, 18.0))
    image.setTemplate_(True)
    image.setName_(None)
    return image


def load_status_images(resource_dir: Path | None = None) -> dict[str, object]:
    """返回五状态 template NSImage dict。资源缺失抛错（构建期即可发现）。"""
    root = resource_dir or assets_dir()
    black = root / "png" / "black"
    images: dict[str, object] = {}
    for name in ICON_NAMES:
        images[name] = _load_template(
            black / f"{name}_18.png", black / f"{name}_36.png"
        )
    return images


def load_checking_frames(resource_dir: Path | None = None) -> list[object]:
    """checking 动画 8 帧（同样 template）。缺失时返回空列表→用静态图。"""
    root = resource_dir or assets_dir()
    frames_dir = root / "png" / "frames"
    frames: list[object] = []
    for index in range(CHECKING_FRAMES):
        path = frames_dir / f"checking_{index:02d}_36.png"
        if not path.exists():
            return []
        frames.append(_load_template(path, None))
    return frames


def reduce_motion_enabled() -> bool:
    """系统"降低动态效果"开启时用静态 checking 图（素材包接入要求）。"""
    try:
        from AppKit import NSWorkspace

        return bool(NSWorkspace.sharedWorkspace().accessibilityDisplayShouldReduceMotion)
    except Exception:  # noqa: BLE001 — 查询失败按不降级处理
        return False


def icon_for_state(state: StateSnapshot | None) -> str:
    """StateSnapshot → 素材状态名（素材包 Status Mapping 的落地）。

    offline  <- 无可用物理网络
    checking <- 检测/认证/重试/验证执行中
    online   <- 物理出口验证通过的联网（唯一 online 来源，绝不看单一状态码）
    action   <- 需要用户操作或明确的认证失败
    unknown  <- 证据不足 / 无活跃检查
    """
    if state is None:
        return "unknown"
    if not state.interface or state.link.value == "DISCONNECTED":
        return "offline"
    if state.phase in (
        Phase.PROBING, Phase.MATCHING, Phase.AUTHENTICATING,
        Phase.VERIFYING, Phase.RETRY_BACKOFF, Phase.DEBOUNCING,
    ):
        return "checking"
    if state.phase in (Phase.WAITING_USER, Phase.TRUST_REQUIRED, Phase.DEGRADED, Phase.ERROR):
        return "action"
    if state.phase == Phase.IDLE:
        return "unknown"
    if state.phase in (Phase.ONLINE_AUTHENTICATED, Phase.ONLINE_NO_AUTH):
        return "online"
    return "unknown"
