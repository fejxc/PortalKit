# -*- mode: python ; coding: utf-8 -*-
"""PortalKit 独立 .app 打包规格（PyInstaller）。

产物：自包含的 PortalKit.app——内嵌解释器、pyobjc/rumps 与全部依赖，
目标机器无需安装 Python。构建：`.venv/bin/pyinstaller --clean -y scripts/portalkit.spec`。
"""

import os

ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
# 版本由构建脚本从 pyproject.toml 注入（PORTALKIT_VERSION），本地直跑用开发号
VERSION = os.environ.get("PORTALKIT_VERSION", "0.0.0-dev")

a = Analysis(
    [os.path.join(ROOT, "src", "portalkit", "ui", "menubar.py")],
    pathex=[os.path.join(ROOT, "src")],
    binaries=[],
    datas=[
        # 单色菜单栏素材：运行时按 _MEIPASS/assets/monochrome 装载
        (os.path.join(ROOT, "assets", "monochrome", "png"), os.path.join("assets", "monochrome", "png")),
    ],
    hiddenimports=["rumps"],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PortalKit",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # LSUIElement 菜单栏应用，无控制台
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="PortalKit",
)

app = BUNDLE(
    coll,
    name="PortalKit.app",
    icon=None,  # 构建脚本随后注入已生成的 AppIcon.icns 并改写 Info.plist
    info_plist={
        "CFBundleName": "PortalKit",
        "CFBundleDisplayName": "PortalKit",
        "CFBundleIdentifier": "com.fejxc.portalkit",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSUIElement": True,  # 纯菜单栏应用：无 Dock 图标
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": "Local build",
    },
)
