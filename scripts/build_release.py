#!/usr/bin/env python3
"""PortalKit 发布构建（本地与 GitHub Actions 共用）。

流程：pyproject 读取版本 → PyInstaller 独立打包 → 注入 AppIcon/版本 →
ad-hoc 签名 → codesign 校验 → ditto 压缩为可分发的 zip。

用法：python scripts/build_release.py [输出目录]（默认 build/release）
产物：build/release/PortalKit-<版本>-macos-arm64.zip

不做部署（/Applications 安装是 `portalkit app install` 的职责）。
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from portalkit.ui.appbundle import _make_icns, _sign_bundle  # noqa: E402

APP_NAME = "PortalKit"


def project_version() -> str:
    data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _run(args: list[str], **kwargs) -> None:
    subprocess.run(args, check=True, **kwargs)


def build(out_dir: Path) -> Path:
    version = project_version()
    build_dir = PROJECT_ROOT / "build"
    icns = build_dir / "appicon.icns"
    if not _make_icns(PROJECT_ROOT / "assets" / "appicon.png", icns, build_dir):
        raise RuntimeError("AppIcon.icns 生成失败")

    env = {**os.environ, "PORTALKIT_VERSION": version}
    _run(
        [
            sys.executable, "-m", "PyInstaller", "--clean", "-y",
            str(PROJECT_ROOT / "scripts" / "portalkit.spec"),
            "--distpath", str(build_dir / "dist"),
            "--workpath", str(build_dir / "work"),
        ],
        env=env,
    )

    staged = build_dir / "dist" / f"{APP_NAME}.app"
    info_path = staged / "Contents" / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    info["CFBundleIconFile"] = "AppIcon"
    info["CFBundleShortVersionString"] = version
    info["CFBundleVersion"] = version
    info_path.write_bytes(plistlib.dumps(info))
    shutil.copyfile(icns, staged / "Contents" / "Resources" / "AppIcon.icns")
    _sign_bundle(staged)

    # 校验：签名有效 + 关键内容在位（CI 与本地同一道关卡）
    _run(["codesign", "--verify", "--deep", "--strict", str(staged)])
    exe = staged / "Contents" / "MacOS" / APP_NAME
    if not exe.exists() or exe.stat().st_size < 1_000_000:
        raise RuntimeError(f"bundle 可执行缺失或异常小: {exe}")
    _run(["plutil", "-lint", str(info_path)])

    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{APP_NAME}-{version}-macos-arm64.zip"
    if zip_path.exists():
        zip_path.unlink()
    # ditto 保留扩展属性/签名/符号链接，是 macOS .app 分发的标准打包方式
    _run(
        ["ditto", "-c", "-k", "--sequesterRsrc", "--keepParent",
         str(staged), str(zip_path)]
    )
    size_mb = zip_path.stat().st_size / 1_000_000
    print(f"[build_release] {zip_path} ({size_mb:.1f} MB, version {version})")
    return zip_path


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else PROJECT_ROOT / "build" / "release"
    build(out)
