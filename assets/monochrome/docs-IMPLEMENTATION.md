# macOS 使用说明（提供给 Zcode）

## App Icon
优先把 `app/PortalKit_darkplate.svg` 导出到 Xcode AppIcon asset catalog 各尺寸。它是灰黑单色、无白边的圆角形状。需要无底的 logo，则用 `PortalKit_transparent_black.svg`；不要给图标额外增加底层白色方形。

## Menu Bar Status Image
优先使用 `svg/black/` 中同名 SVG 作为设计源，转换到 NSImage 或 PDF vector asset。运行时 `NSImage.isTemplate = true`，由 macOS 根据浅色/深色菜单栏自动着色。

建议显示尺寸约 18 × 18 pt，2× Retina 时对应 36 × 36 px；实际请按项目的 NSStatusItem 高度微调。不要直接渲染大号 App logo 的带底图块作为菜单栏图标。

Swift/ObjC 伪代码：
```swift
let image = NSImage(named: "portalkit-online")!
image.isTemplate = true
image.size = NSSize(width: 18, height: 18)
statusItem.button?.image = image
```

rumps/PyObjC：使用 AppKit 的 NSStatusItem 和 NSImage 模板图像，优先走统一状态映射；不要在深色模式手动固定黑色图标。

## Status Mapping
```text
offline  <- physical network unavailable
checking <- detecting / authenticating / retrying / verifying
online   <- verified internet access through physical interface
 action  <- needs user interaction or definitive authentication failure
unknown  <- insufficient evidence, no active check
```

不要依赖单纯 HTTP 响应 200、401 或认证脚本退出码映射 online。必须由物理出口验证的最终结论决定。

## Animation
`checking_frame_00.svg` ... `checking_frame_07.svg` 可制作环形进度旋转。建议每帧 100–150 ms，循环仅在后台确实执行网络任务时启用；注意用户降低动态效果的系统设置。若使用静态图标，则使用 checking.svg。
