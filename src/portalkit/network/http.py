"""BoundHTTPClient：所有门户与探测请求的唯一出口（决策 D1）。

能力（迁移自 zjlib v2.0 已验证实现并扩展）：

- **物理绑定**：socket 设 `IP_BOUND_IF`（macOS）钉在指定物理网卡，
  Clash TUN 接管默认路由时仍从物理路径出入（迁移自
  `zjlib-wifi/zjlib/wifi_login.py` 的 `_bound_create_connection`）。
- **按接口 DNS**：目标是域名时先经物理接口的 DHCP 解析器解析（见
  network/dns.py），避免 fake-ip；URL 用解析后的 IP 重建并显式带 Host 头。
- **禁代理**：opener 层 `ProxyHandler({})`，环境残留代理变量不影响。
- **受控重定向**：携带凭据的请求阶段 redirect 只允许落在
  ``allowed_hosts`` 内，越界目标抛 `UntrustedRedirectError`，
  决不带 Cookie/凭据跟随未知目标（SECURITY_AND_NETWORK §1/§8）。
- **Cookie 隔离**：每实例独立 CookieJar；Cookie 按域隔离天然不跨宿主发送。
- **证书指纹捕获**：TLS 连接记录叶证书 SHA-256，供信任记录做 pinning。
- **TLS 策略**：`tls_verify=False` 仅用于已知的自签门户（zjlib），
  并由指纹校验补偿；域名 + 校验开启 + 接口绑定的组合 P0 不支持（显式报错）。
"""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.cookiejar import CookieJar

from portalkit.network.dns import dns_query_a, is_ip_literal

MAX_BODY_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT = 8.0

# macOS netinet/in.h: IP_BOUND_IF=25。注意：部分第三方/新版 CPython 构建
# 不暴露 socket.IP_BOUND_IF（本机 Homebrew 3.14 实测缺失），不能 hasattr 判断，
# 否则绑定静默失效、TUN 下请求仍会进隧道（Phase 0 审计 F6 的补充发现）。
_IP_BOUND_IF = getattr(socket, "IP_BOUND_IF", 25)

_USER_AGENT = "Mozilla/5.0 PortalKit/0.1"


class UntrustedRedirectError(RuntimeError):
    """重定向目标不在允许集合内；凭据绝不发往该目标。"""

    def __init__(self, url: str) -> None:
        super().__init__(f"重定向到未授权目标，已停止: {url}")
        self.url = url


class NetworkRequestError(RuntimeError):
    """网络层失败（DNS / 连接 / 超时）。reason 已剥离敏感查询串。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class HTTPResult:
    status: int
    url: str
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    peer_cert_sha256: str | None = None

    @property
    def host(self) -> str:
        return urllib.parse.urlsplit(self.url).hostname or ""


def _redact_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    if not parts.query:
        return url
    return parts._replace(query="<redacted>").geturl()


def _bound_create_connection(interface_name: str, cert_sink: dict):
    """生成替代 socket.create_connection 的工厂（zjlib 同款思路）。"""
    ifindex = socket.if_nametoindex(interface_name)

    def create_connection(address, timeout=None, source_address=None):
        host, port = address
        af, socktype, proto, _, sock_addr = socket.getaddrinfo(
            host, port, socket.AF_INET, socket.SOCK_STREAM
        )[0]
        sock = socket.socket(af, socktype, proto)
        if source_address:
            sock.bind(source_address)
        sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, ifindex)
        if timeout is not None:
            sock.settimeout(timeout)
        cert_sink["sock"] = sock
        sock.connect(sock_addr)
        return sock

    return create_connection


class _BoundHTTPConnection(http.client.HTTPConnection):
    interface_name = ""
    cert_sink: dict = {}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.interface_name:
            self._create_connection = _bound_create_connection(
                self.interface_name, type(self).cert_sink
            )


class _BoundHTTPSConnection(
    _BoundHTTPConnection, http.client.HTTPSConnection
):
    peer_cert_sha256: str | None = None

    def connect(self) -> None:  # noqa: D102 — 覆盖以捕获对端证书
        sink = type(self).cert_sink
        sink["sock"] = None
        sock = self._create_connection(
            (self.host, self.port), self.timeout, self.source_address
        )
        server_hostname = self.host if not is_ip_literal(self.host) else None
        if server_hostname is None and getattr(self._context, "check_hostname", False):
            # P0 不支持"https + IP 直连 + 证书校验"组合：IP 门户（zjlib）
            # 必须走 tls_verify=False 并以信任记录的证书指纹补偿。
            raise ssl.SSLError("https to IP literal requires tls_verify=False (use fingerprint pinning)")
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)
        der = self.sock.getpeercert(binary_form=True)
        if der:
            self.peer_cert_sha256 = hashlib.sha256(der).hexdigest()
            sink["peer_cert_sha256"] = self.peer_cert_sha256


class _ControlledRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str] | None) -> None:
        super().__init__()
        self._allowed = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        host = urllib.parse.urlsplit(newurl).hostname or ""
        if self._allowed is not None and host not in self._allowed:
            raise UntrustedRedirectError(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _make_connection_classes(
    interface: str | None, cert_sink: dict
) -> tuple[type, type]:
    if interface is None:
        return http.client.HTTPConnection, http.client.HTTPSConnection

    http_cls = type(
        f"_BoundHTTP_{interface}",
        (_BoundHTTPConnection,),
        {"interface_name": interface, "cert_sink": cert_sink},
    )
    https_cls = type(
        f"_BoundHTTPS_{interface}",
        (_BoundHTTPSConnection,),
        {"interface_name": interface, "cert_sink": cert_sink},
    )
    return http_cls, https_cls


@dataclass
class _ClientSpec:
    interface: str | None
    timeout: float
    tls_verify: bool
    allowed_hosts: frozenset[str] | None
    max_redirects: int
    cookie_jar: CookieJar
    resolved_dns: dict[str, str]  # host -> ip 缓存（按接口解析结果）


class BoundHTTPClient:
    """一次会话/一个阶段的 HTTP 客户端。跨阶段不复用（Cookie 生命周期隔离）。"""

    def __init__(
        self,
        interface: str | None = None,
        dns_resolver: str | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        tls_verify: bool = True,
        allowed_hosts: frozenset[str] | None = None,
        max_redirects: int = 5,
        cookie_jar: CookieJar | None = None,
    ) -> None:
        self._spec = _ClientSpec(
            interface=interface,
            timeout=timeout,
            tls_verify=tls_verify,
            allowed_hosts=frozenset(allowed_hosts) if allowed_hosts else None,
            max_redirects=max_redirects,
            cookie_jar=cookie_jar or CookieJar(),
            resolved_dns={},
        )
        self._dns = dns_resolver
        self.cert_sink: dict = {}

    # ------------------------------------------------------------------ URL

    def _resolve(self, host: str) -> str:
        """把域名解析为直连 IP（接口绑定 + 物理 DNS）；IP 字面量原样返回。"""
        if is_ip_literal(host) or self._spec.interface is None:
            return host
        cached = self._spec.resolved_dns.get(host)
        if cached:
            return cached
        resolver = self._dns
        if not resolver:
            raise NetworkRequestError(
                f"接口 {self._spec.interface} 无可用 DNS 解析器，无法解析 {host}"
            )
        ip = dns_query_a(host, resolver, self._spec.interface)
        if not ip:
            raise NetworkRequestError(f"按接口 DNS 解析失败: {host}")
        self._spec.resolved_dns[host] = ip
        return ip

    def _prepare(self, url: str, headers: dict[str, str]) -> str:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname or ""
        if self._spec.interface is None or is_ip_literal(host):
            return url
        ip = self._resolve(host)
        netloc = ip if parts.port is None else f"{ip}:{parts.port}"
        new = parts._replace(netloc=netloc).geturl()
        # 显式 Host 头保留原始主机名（http.client 检测到 Host 头会跳过自动注入）
        headers.setdefault(
            "Host", host if parts.port is None else f"{host}:{parts.port}"
        )
        return new

    # --------------------------------------------------------------- opener

    def _build_opener(self) -> urllib.request.OpenerDirector:
        spec = self._spec
        if spec.tls_verify:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()  # noqa: SLF001 — 自签门户（zjlib），指纹 pinning 补偿

        http_cls, https_cls = _make_connection_classes(spec.interface, self.cert_sink)

        http_handler = urllib.request.HTTPHandler()
        http_handler.http_open = lambda req: self._do_open(  # type: ignore[method-assign]
            http_cls, req
        )
        https_handler = urllib.request.HTTPSHandler(context=context)
        https_handler.https_open = lambda req: self._do_open(  # type: ignore[method-assign]
            https_cls, req, context=context
        )
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _ControlledRedirectHandler(spec.allowed_hosts),
            http_handler,
            https_handler,
            urllib.request.HTTPCookieProcessor(spec.cookie_jar),
        )

    def _do_open(self, connection_class, req, context=None):
        # 与 urllib Handler.do_open 相同的骨架，但强制使用绑定的连接类，
        # 并把 context 透传给连接构造器（否则连接类回退到默认 verified context）。
        if context is None:
            return urllib.request.HTTPHandler().do_open(connection_class, req)
        return urllib.request.HTTPSHandler(context=context).do_open(
            connection_class, req, context=context
        )

    # -------------------------------------------------------------- request

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        referer: str | None = None,
        timeout: float | None = None,
    ) -> HTTPResult:
        import time

        merged: dict[str, str] = {
            "User-Agent": _USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
        if referer:
            merged["Referer"] = referer
        if data is not None:
            merged.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )
        if headers:
            merged.update(headers)

        target = self._prepare(url, merged)
        if isinstance(data, str):
            data = data.encode("utf-8")
        req = urllib.request.Request(target, data=data, headers=merged, method=method)
        started = time.monotonic()
        try:
            with self._build_opener().open(
                req, timeout=timeout or self._spec.timeout
            ) as resp:
                body = resp.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
                charset = resp.headers.get_content_charset() or "utf-8"
                result = HTTPResult(
                    status=resp.status,
                    url=resp.geturl(),
                    text=body.decode(charset, errors="replace"),
                    headers={k: v for k, v in resp.headers.items()},
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                    peer_cert_sha256=self.cert_sink.get("peer_cert_sha256"),
                )
        except urllib.error.HTTPError as exc:
            # 非 2xx 是有效的协议信号（zjlib 404=已认证），交调用方分支处理。
            try:
                raw = exc.read(MAX_BODY_BYTES + 1)[:MAX_BODY_BYTES]
                charset = exc.headers.get_content_charset() or "utf-8"
                text = raw.decode(charset, errors="replace")
                resp_headers = {k: v for k, v in exc.headers.items()}
            except Exception:  # noqa: BLE001 — body 读取失败不影响状态码语义
                text, resp_headers = "", {}
            result = HTTPResult(
                status=exc.code,
                url=exc.filename or target,
                text=text,
                headers=resp_headers,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                peer_cert_sha256=self.cert_sink.get("peer_cert_sha256"),
            )
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", exc)
            raise NetworkRequestError(
                f"网络请求失败: {type(reason).__name__} ({_redact_url(url)})"
            ) from exc
        except (OSError, http.client.HTTPException) as exc:
            raise NetworkRequestError(
                f"网络请求失败: {type(exc).__name__} ({_redact_url(url)})"
            ) from exc

        if (
            self._spec.allowed_hosts is not None
            and result.host
            and result.host not in self._spec.allowed_hosts
        ):
            raise UntrustedRedirectError(result.url)
        return result

    # --------------------------------------------------------------- helper

    def post_form(
        self,
        url: str,
        body: str | bytes,
        *,
        referer: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> HTTPResult:
        return self.request(
            url,
            method="POST",
            data=body,
            referer=referer,
            headers=headers,
        )


def urlencode_exactly(fields: dict[str, str]) -> str:
    """标准 urlencode（zjlib 提交路径用：字段值是未编码原文）。"""
    return urllib.parse.urlencode(fields)
