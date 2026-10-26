"""物理网络接口枚举与快照（PRD F01：动态识别，禁止硬编码 en0）。

全部通过 macOS 系统命令（ifconfig / route / ipconfig / scutil）采样，
不依赖第三方库。采样结果只含接口名、IP、网关、DNS——不含任何凭据。
"""

from __future__ import annotations

import re
import subprocess
from functools import lru_cache

from portalkit.models import NetworkSnapshot

_PHYSICAL_IF_RE = re.compile(r"^en\d+$")


def _run(args: list[str], timeout: float = 5.0) -> str:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout if proc.returncode == 0 else ""


def list_physical_interfaces() -> list[str]:
    """返回 en* 物理接口（排除 awdl/llw0/bridge/utun——它们名字本身不含 enN）。"""

    import socket

    names = sorted(
        (name for _, name in socket.if_nameindex() if _PHYSICAL_IF_RE.fullmatch(name)),
        key=lambda n: int(n[2:]),
    )
    return names


def interface_is_up(iface: str) -> bool:
    out = _run(["ifconfig", iface])
    return "flags=" in out and "<UP" in out.split("flags=", 1)[1][:80]


def interface_ipv4(iface: str) -> str | None:
    out = _run(["ifconfig", iface])
    match = re.search(r"^\s+inet (\d+\.\d+\.\d+\.\d+) ", out, re.M)
    return match.group(1) if match else None


def default_route() -> tuple[str | None, str | None]:
    """返回 (interface, gateway)；TUN 接管默认路由时 interface 可能是 utunX。"""
    out = _run(["route", "-n", "get", "default"])
    iface = gw = None
    match = re.search(r"interface:\s+(\S+)", out)
    if match:
        iface = match.group(1)
    match = re.search(r"gateway:\s+(\S+)", out)
    if match and match.group(1) != "default":
        gw = match.group(1)
    return iface, gw


def dhcp_router(iface: str) -> str | None:
    out = _run(["ipconfig", "getoption", iface, "router"])
    out = out.strip()
    return out or None


def dhcp_dns(iface: str) -> str | None:
    """该接口 DHCP 下发的真实 DNS——TUN fake-ip 劫持系统 DNS 时仍返回内网解析器。"""
    out = _run(["ipconfig", "getoption", iface, "domain_name_server"])
    out = out.strip().splitlines()[0].strip() if out.strip() else ""
    return out or None


@lru_cache(maxsize=1)
def _wifi_device() -> str:
    out = _run(["networksetup", "-listallhardwareports"])
    match = re.search(r"Device:\s+(en\d+)\s*\n.*?Wi-Fi", out, re.S)
    if match:
        return match.group(1)
    match = re.search(r"Hardware Port:\s*Wi-Fi\s*\nDevice:\s*(en\d+)", out)
    return match.group(1) if match else "en0"


def wifi_device() -> str:
    return _wifi_device()


def wifi_ssid(iface: str) -> str | None:
    """尽力读取 SSID（macOS 14+ `ipconfig getsummary`）。

    定位权限未授权时系统会隐藏 SSID——返回 None，调用方降级为网关摘要，
    绝不为此弹权限请求（PRD：SSID 可选）。
    """
    out = _run(["ipconfig", "getsummary", iface])
    if not out:
        return None
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("SSID") and ":" in stripped:
            value = stripped.split(":", 1)[1].strip()
            if value and value != "<hidden>":
                return value
    return None


def network_label(snapshot: NetworkSnapshot) -> str:
    """菜单展示用的网络名：SSID 优先，缺省降级为网关/接口摘要。"""
    if snapshot.ssid:
        return snapshot.ssid
    if snapshot.gateway:
        return f"{snapshot.gateway} · {snapshot.interface}"
    return snapshot.interface or "未连接"


def build_snapshot(interface: str | None = None) -> NetworkSnapshot:
    """采集一次网络快照。

    interface 为空时的选择顺序：默认路由物理接口 > 第一个有 IPv4 的 en*；
    默认路由被 TUN 接管时回退枚举，保证拿到的是物理路径。
    """
    candidates = list_physical_interfaces()
    chosen = interface
    route_iface, route_gw = default_route()
    if chosen is None:
        if route_iface and _PHYSICAL_IF_RE.fullmatch(route_iface):
            chosen = route_iface
        else:
            chosen = next(
                (n for n in candidates if interface_ipv4(n)), None
            )
    if chosen is None or chosen not in candidates:
        return NetworkSnapshot(interface=None, ipv4=None, gateway=None, dns=None)

    ipv4 = interface_ipv4(chosen)
    gateway = dhcp_router(chosen)
    if gateway is None and route_iface == chosen:
        gateway = route_gw
    dns = dhcp_dns(chosen) or gateway
    return NetworkSnapshot(
        interface=chosen, ipv4=ipv4, gateway=gateway, dns=dns,
        ssid=wifi_ssid(chosen),
    )
