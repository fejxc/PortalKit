"""分层探测（决策 D3）：互联网出口多探针 + 物理链路检查。

互联网可达性沿用路由器版验证过的"多探针、至少 2 个通过"策略
（zstu/router/login.sh）：单个 204/状态码不再被当作全网在线。
所有探针都经 BoundHTTPClient 走物理接口路径，杜绝 TUN 假阳性。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from portalkit.models import InternetState
from portalkit.network.http import (
    BoundHTTPClient,
    HTTPResult,
    NetworkRequestError,
    UntrustedRedirectError,
)

MIN_ONLINE_PROBES = 2


@dataclass(frozen=True)
class InternetProbe:
    name: str
    url: str
    marker: str | None  # None 表示只看状态码
    expect_status: int


# 全部 HTTP（80 端口）——captive portal 只劫持明文 HTTP；HTTPS 探针会绕过门户。
INTERNET_PROBES: tuple[InternetProbe, ...] = (
    InternetProbe("gstatic-204", "http://connectivitycheck.gstatic.com/generate_204", None, 204),
    InternetProbe("msft-connecttest", "http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test", 200),
    InternetProbe("apple-captive", "http://captive.apple.com/hotspot-detect.html", "Success", 200),
    InternetProbe("neverssl", "http://neverssl.com/", "<!DOCTYPE", 200),
)

INTERNET_PROBE_HOSTS = frozenset(
    {p.url.split("/")[2] for p in INTERNET_PROBES}
)


@dataclass
class InternetCheckResult:
    state: InternetState
    passed: int
    total: int
    evidence: tuple[str, ...] = field(default_factory=tuple)
    redirect_host: str | None = None  # 探针被劫持跳转到的宿主（门户线索）

    @property
    def reachable(self) -> bool:
        return self.state == InternetState.REACHABLE


def _probe_once(client: BoundHTTPClient, probe: InternetProbe) -> tuple[bool, HTTPResult | None, str | None]:
    try:
        result = client.request(probe.url)
    except UntrustedRedirectError as exc:
        # 被劫持跳转到探针白名单之外 = 门户存在的强线索（但不是唯一判定）。
        try:
            return False, None, exc.url.split("/")[2]
        except IndexError:
            return False, None, None
    except NetworkRequestError:
        return False, None, None
    except Exception:  # noqa: BLE001 — 单探针异常不影响整体判定
        return False, None, None
    ok = result.status == probe.expect_status
    if ok and probe.marker:
        ok = probe.marker in result.text
    redirect = None
    if result.url and result.url.split("/")[2] != probe.url.split("/")[2]:
        redirect = result.url.split("/")[2]
    return ok, result, redirect


def check_internet(interface: str | None, dns: str | None, timeout: float = 5.0) -> InternetCheckResult:
    """经指定物理接口（绑定 + 按接口 DNS）执行互联网多探针。"""
    client = BoundHTTPClient(
        interface=interface,
        dns_resolver=dns,
        timeout=timeout,
        allowed_hosts=INTERNET_PROBE_HOSTS,
    )
    evidence: list[str] = []
    passed = 0
    redirect_host = None
    for probe in INTERNET_PROBES:
        ok, result, redirect = _probe_once(client, probe)
        evidence.append(
            f"{probe.name}:{'pass' if ok else 'fail'}"
            + (f"(http{result.status})" if result else "(unreachable)")
        )
        if redirect and redirect_host is None:
            redirect_host = redirect
        if ok:
            passed += 1
    if passed >= MIN_ONLINE_PROBES:
        state = InternetState.REACHABLE
    elif passed > 0:
        state = InternetState.UNKNOWN  # 部分可达，降级存疑
    else:
        state = InternetState.BLOCKED
    return InternetCheckResult(
        state=state, passed=passed, total=len(INTERNET_PROBES),
        evidence=tuple(evidence), redirect_host=redirect_host,
    )
