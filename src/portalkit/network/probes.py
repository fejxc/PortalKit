"""分层探测（决策 D3）：互联网出口多探针 + 物理链路检查。

互联网可达性沿用路由器版验证过的"多探针、至少 2 个通过"策略
（zstu/router/login.sh）：单个 204/状态码不再被当作全网在线。
所有探针都经 BoundHTTPClient 走物理接口路径，杜绝 TUN 假阳性。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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
    InternetProbe("neverssl", "http://neverssl.com/", "NeverSSL", 200),
)

INTERNET_PROBE_HOSTS = frozenset(
    {p.url.split("/")[2] for p in INTERNET_PROBES}
)


@dataclass(frozen=True)
class LayerEvidence:
    probe: str
    layer: str
    outcome: str
    detail: str


@dataclass
class InternetCheckResult:
    state: InternetState
    passed: int
    total: int
    evidence: tuple[str, ...] = field(default_factory=tuple)
    redirect_host: str | None = None  # 探针被劫持跳转到的宿主（门户线索）

    layers: tuple[LayerEvidence, ...] = ()

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
    if ok and probe.name == "msft-connecttest":
        ok = result.text.strip() == probe.marker
    if ok and probe.name == "apple-captive":
        body = result.text.lower()
        ok = "<title>success</title>" in body and "<body>success</body>" in body
    redirect = None
    if result.url and result.url.split("/")[2] != probe.url.split("/")[2]:
        redirect = result.url.split("/")[2]
        ok = False
    return ok, result, redirect


def check_internet(interface: str | None, dns: str | None, timeout: float = 5.0) -> InternetCheckResult:
    """经指定物理接口（绑定 + 按接口 DNS）执行互联网多探针。

    探针相互独立、并发执行（各自持有独立 client：CookieJar / cert_sink /
    evidence 均非线程安全，绝不共享）；结果按固定顺序聚合，证据可复现。
    """
    if not interface:
        # 无物理接口时绝不使用默认路由探针授予在线。
        return InternetCheckResult(InternetState.UNKNOWN, 0, len(INTERNET_PROBES),
                                   ("physical-interface:missing",))

    def make_client() -> BoundHTTPClient:
        return BoundHTTPClient(
            interface=interface,
            dns_resolver=dns,
            timeout=timeout,
            allowed_hosts=INTERNET_PROBE_HOSTS | {"1.1.1.1", "223.5.5.5"},
        )

    @dataclass
    class _ProbeOutcome:
        probe: InternetProbe
        ok: bool
        result: HTTPResult | None
        redirect: str | None
        connected: bool
        dns_trace: tuple[str, ...]
        direct: bool

    def run_probe(probe: InternetProbe, *, direct=False, headers=None) -> _ProbeOutcome:
        client = make_client()
        start = len(client.evidence)
        if direct:
            try:
                result = client.request(probe.url, headers=headers)
                ok = result.status == probe.expect_status and bool(probe.marker and probe.marker in result.text)
                redirect = None
            except UntrustedRedirectError as exc:
                result, ok, redirect = None, False, exc.url.split("/")[2]
            except NetworkRequestError:
                result, ok, redirect = None, False, None
        else:
            ok, result, redirect = _probe_once(client, probe)
        dns_trace = tuple(client.evidence[start:])
        connected = bool(result or redirect or client.cert_sink.get("tcp_connected"))
        return _ProbeOutcome(probe, ok, result, redirect, connected, dns_trace, direct)

    # ---- 域名探针并发（各自 DNS 回退链独立计时，整体耗时 = 最慢单探针）
    outcomes: list[_ProbeOutcome] = []
    with ThreadPoolExecutor(max_workers=len(INTERNET_PROBES)) as pool:
        futures = {pool.submit(run_probe, p): p for p in INTERNET_PROBES}
        for future in futures:
            outcomes.append(future.result())

    evidence: list[str] = []
    layers: list[LayerEvidence] = []
    passed = 0
    redirect_host = None
    any_tcp_pass = False

    for oc in outcomes:
        for entry in oc.dns_trace:
            evidence.append(f"{oc.probe.name}:{entry}")
            layer, outcome = entry.split(":", 1)
            layers.append(LayerEvidence(oc.probe.name, layer, outcome.split("(")[0], outcome))
        if oc.direct:
            layers.append(LayerEvidence(oc.probe.name, "dns", "skip", "IP direct"))
            evidence.append(f"{oc.probe.name}:dns:skip(ip-direct)")
        tcp_outcome = "pass" if oc.connected else (
            "skip" if oc.dns_trace and not any(":pass" in e for e in oc.dns_trace) else "fail"
        )
        layers.append(LayerEvidence(oc.probe.name, "tcp", tcp_outcome, "connect"))
        evidence.append(f"{oc.probe.name}:tcp:{tcp_outcome}")
        detail = f"http{oc.result.status}" if oc.result else ("redirect" if oc.redirect else "no-response")
        layers.append(LayerEvidence(oc.probe.name, "http", "pass" if oc.ok else "fail", detail))
        evidence.append(f"{oc.probe.name}:http:{'pass' if oc.ok else 'fail'}({detail})")
        if oc.redirect and redirect_host is None:
            redirect_host = oc.redirect
        if oc.connected and tcp_outcome == "pass":
            any_tcp_pass = True
        # IP 直连是恢复诊断，单个 404 / TCP connect 不能授予联网。
        if oc.ok and not oc.direct:
            passed += 1

    partial = passed > 0 or any_tcp_pass
    if passed < MIN_ONLINE_PROBES:
        # 固定 IP 仅用于诊断，Host 保留服务名；Ali 的 404 只记录 HTTP 层。
        direct_probes = (
            (InternetProbe("ip-cloudflare", "http://1.1.1.1/cdn-cgi/trace", "h=one.one.one.one", 200), "one.one.one.one"),
            (InternetProbe("ip-alidns", "http://223.5.5.5/", None, 404), "223.5.5.5"),
        )
        with ThreadPoolExecutor(max_workers=len(direct_probes)) as pool:
            futures = {pool.submit(run_probe, p, direct=True, headers={"Host": host}): p
                       for p, host in direct_probes}
            for future in futures:
                oc = future.result()
                evidence.append(f"{oc.probe.name}:dns:skip(ip-direct)")
                layers.append(LayerEvidence(oc.probe.name, "dns", "skip", "IP direct"))
                tcp_outcome = "pass" if oc.connected else "fail"
                layers.append(LayerEvidence(oc.probe.name, "tcp", tcp_outcome, "connect"))
                evidence.append(f"{oc.probe.name}:tcp:{tcp_outcome}")
                detail = f"http{oc.result.status}" if oc.result else ("redirect" if oc.redirect else "no-response")
                layers.append(LayerEvidence(oc.probe.name, "http", "pass" if oc.ok else "fail", detail))
                evidence.append(f"{oc.probe.name}:http:{'pass' if oc.ok else 'fail'}({detail})")
                if oc.connected and tcp_outcome == "pass":
                    any_tcp_pass = True
        partial = passed > 0 or any_tcp_pass

    state = (InternetState.REACHABLE if passed >= MIN_ONLINE_PROBES else
             InternetState.UNKNOWN if partial else InternetState.BLOCKED)
    return InternetCheckResult(
        state=state, passed=passed, total=len(INTERNET_PROBES),
        evidence=tuple(evidence), redirect_host=redirect_host, layers=tuple(layers),
    )
