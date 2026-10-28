"""zstu 适配器 — 浙江理工大学校园网 ePortal。

迁移自 `~/Documents/zjlib-wifi/zstu/mac/wifi_login.py` v1.0（审计报告 §4）：

1. GET discovery（默认 connectivitycheck.gstatic.com/generate_204）触发门户
   302 → 带 wlanuserip/mac/url 会话参数的 index.jsp 入口。**204 = 已在线**。
   会话参数不可硬编码——query 为空直接拒绝（沿用原脚本约束）。
2. GET 入口保留 JSESSIONID；POST `InterFace.do?method=pageInfo` 读
   passwordEncrypt 开关 + 动态 RSA 公钥；`method=getServices` 读服务列表。
3. POST `method=login`：字段双重 encodeURIComponent；passwordEncrypt=true 时
   以 security.js 同款无填充 RSA 加密 `password+">"+mac`。
4. 成功判定：JSON `result=="success"`（结构化，比 zjlib 启发式稳健）。
   validCodeUrl → INTERACTION_REQUIRED（转人工，不破解）。

原脚本无接口绑定（审计 F7）；本实现统一由 core BoundHTTPClient 提供
绑定 + 按接口 DNS，消除 fake-ip 风险。
"""

from __future__ import annotations

import html
import json
import re
import urllib.parse
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import quote, unquote, urljoin, urlsplit

from portalkit.adapters.base import AdapterContext, AuthResult, Credentials, DetectionResult, ProtocolVerifyResult
from portalkit.models import AuthCode
from portalkit.network.http import HTTPResult, NetworkRequestError, UntrustedRedirectError

ADAPTER_ID = "zstu"
API_VERSION = 1

DEFAULT_DISCOVERY_URL = "http://connectivitycheck.gstatic.com/generate_204"
# 发现候选：连通性检测域名常被校园网**白名单放行**（认证前也 204 = 假在线），
# 非白名单 HTTP 站会被 AC 302 到带新鲜会话参数的门户入口——后者才是
# 白名单环境下唯一可靠的发现途径（2026-10-28 浙理工现场）。
DISCOVERY_CANDIDATES: tuple[str, ...] = (
    DEFAULT_DISCOVERY_URL,
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://neverssl.com/",
    "http://example.com/",
)
_JS_URI_SAFE = "-_.!~*'()"


class _PortalProtocolError(RuntimeError):
    """门户响应不符合预期（改版 / 会话失效 / 需要交互）。"""

    def __init__(self, message: str, code: AuthCode = AuthCode.UNKNOWN_ERROR) -> None:
        super().__init__(message)
        self.code = code


class _AlreadyOnline(RuntimeError):
    pass


# ---------------------------------------------------------------- encoding

def js_encode_uri_component(value: str) -> str:
    return quote(str(value), safe=_JS_URI_SAFE, encoding="utf-8", errors="strict")


def js_double_encode(value: str) -> str:
    return js_encode_uri_component(js_encode_uri_component(value))


# --------------------------------------------------------------------- RSA

def js_code_units(value: str) -> list[int]:
    raw = value.encode("utf-16-le", errors="surrogatepass")
    return [raw[i] | (raw[i + 1] << 8) for i in range(0, len(raw), 2)]


def js_reverse(value: str) -> list[int]:
    # JavaScript split("").reverse() 反转 UTF-16 code unit，不是 Python 码点。
    return list(reversed(js_code_units(value)))


def rsa_encrypt_js(value: str, exponent_hex: str, modulus_hex: int | str) -> str:
    """复现 security.js RSAUtils.encryptedString 的无填充 RSA（原样迁移）。"""
    exponent_hex = exponent_hex.strip().lower().removeprefix("0x")
    if isinstance(modulus_hex, str):
        modulus_hex = modulus_hex.strip().lower().removeprefix("0x")
    exponent = int(exponent_hex, 16)
    modulus = int(modulus_hex, 16) if isinstance(modulus_hex, str) else int(modulus_hex)
    if exponent <= 0 or modulus <= 0:
        raise _PortalProtocolError("门户下发的 RSA 公钥无效", AuthCode.PORTAL_CHANGED)

    digit_count = (modulus.bit_length() + 15) // 16
    chunk_size = 2 * (digit_count - 1)
    if chunk_size <= 0:
        raise _PortalProtocolError("RSA 模数太短", AuthCode.PORTAL_CHANGED)

    units = js_reverse(value)
    while len(units) % chunk_size:
        units.append(0)

    blocks: list[str] = []
    for start in range(0, len(units), chunk_size):
        chunk = units[start : start + chunk_size]
        block = 0
        for index in range(0, chunk_size, 2):
            low = chunk[index]
            high = chunk[index + 1]
            digit = low + (high << 8)
            block |= digit << (16 * (index // 2))
        encrypted = pow(block, exponent, modulus)
        encoded = format(encrypted, "x")
        encoded = encoded.zfill((len(encoded) + 3) // 4 * 4)
        blocks.append(encoded)
    return " ".join(blocks)


# ------------------------------------------------------------------ config

@dataclass(frozen=True)
class PortalConfig:
    entry_url: str
    query_string: str
    login_endpoint: str
    password_encrypt: bool
    public_exponent: str
    public_modulus: str
    service: str
    service_required: bool


def _raw_query_string(url: str) -> str:
    query = urlsplit(url).query
    if not query:
        raise _PortalProtocolError(
            "认证入口缺少查询参数（wlanuserip/mac/url 为会话参数，不可硬编码）",
            AuthCode.PORTAL_CHANGED,
        )
    return query


def _raw_query_param(query: str, name: str) -> str:
    for item in query.split("&"):
        key, sep, value = item.partition("=")
        if sep and unquote(key) == name:
            return value
    return ""


def _endpoint_for(entry_url: str, method: str) -> str:
    return f"{urljoin(entry_url, './InterFace.do')}?method={method}"


def _post_interface(client, url: str, fields: dict[str, str], referer: str) -> HTTPResult:
    # AuthInterFace.js 手工拼接已编码字段；不能再 urlencode（防二次编码）。
    body = "&".join(f"{js_encode_uri_component(k)}={v}" for k, v in fields.items())
    return client.request(url, method="POST", data=body, referer=referer)


def _parse_json(result: HTTPResult, label: str) -> dict:
    if result.status != 200:
        raise _PortalProtocolError(f"{label}: HTTP {result.status}", AuthCode.NETWORK_ERROR)
    try:
        value = json.loads(result.text.lstrip("\ufeff"))
    except json.JSONDecodeError as exc:
        raise _PortalProtocolError(f"{label}: 返回非 JSON", AuthCode.PORTAL_CHANGED) from exc
    if not isinstance(value, dict):
        raise _PortalProtocolError(f"{label}: JSON 非对象", AuthCode.PORTAL_CHANGED)
    return value


def _html_attribute(fragment: str, attribute: str) -> str:
    match = re.search(
        rf"\b{re.escape(attribute)}\s*=\s*(['\"])(.*?)\1", fragment or "", re.I | re.S
    )
    return html.unescape(match.group(2)) if match else ""


def bootstrap(client, entry_url: str, check_generation) -> tuple[PortalConfig, str]:
    """建立会话并收集 pageInfo/getServices；返回 (config, query)。"""
    entry = client.request(entry_url)
    if entry.status == 204:
        raise _AlreadyOnline()
    if entry.status != 200:
        raise _PortalProtocolError(
            f"认证入口 HTTP {entry.status}", AuthCode.NETWORK_ERROR
        )
    if "设备未注册" in entry.text:
        raise _PortalProtocolError("门户提示设备未注册", AuthCode.INTERACTION_REQUIRED)

    final_url = entry.url
    query = _raw_query_string(final_url)
    check_generation()

    page_info_url = _endpoint_for(final_url, "pageInfo")
    encoded_query = js_encode_uri_component(query)
    page_info = _parse_json(
        _post_interface(client, page_info_url, {"queryString": encoded_query}, final_url),
        "pageInfo",
    )
    check_generation()

    services_url = _endpoint_for(final_url, "getServices") + "&queryString=" + encoded_query
    services = _parse_json(
        client.request(services_url, method="POST", data=b"", referer=final_url),
        "getServices",
    )
    check_generation()

    default_service = _html_attribute(str(services.get("defaultService") or ""), "value")
    options: list[str] = []
    service_json = services.get("serviceJson")
    if isinstance(service_json, str):
        try:
            service_json = json.loads(service_json)
        except json.JSONDecodeError:
            service_json = []
    if isinstance(service_json, list):
        for item in service_json:
            if isinstance(item, dict) and item.get("serviceName") is not None:
                name = str(item["serviceName"])
                if name not in options:
                    options.append(name)
    service_required = str(services.get("isService")).strip().lower() in {"true", "1", "yes", "on"}
    if not default_service and len(options) == 1 and service_required:
        default_service = options[0]

    exponent = str(page_info.get("publicKeyExponent") or "")
    modulus = str(page_info.get("publicKeyModulus") or "")
    password_encrypt = str(page_info.get("passwordEncrypt")).strip().lower() in {"true", "1", "yes", "on"}
    if password_encrypt and (not exponent or not modulus):
        raise _PortalProtocolError("要求 RSA 但未下发完整公钥", AuthCode.PORTAL_CHANGED)

    return PortalConfig(
        entry_url=final_url,
        query_string=query,
        login_endpoint=_endpoint_for(final_url, "login"),
        password_encrypt=password_encrypt,
        public_exponent=exponent,
        public_modulus=modulus,
        service=default_service,
        service_required=service_required,
    ), query


def build_login_payload(config: PortalConfig, username: str, password: str, mac: str) -> dict[str, str]:
    portal_password = password
    effective_encrypt = config.password_encrypt or len(js_code_units(password)) > 150
    if config.password_encrypt and len(js_code_units(password)) < 150:
        portal_password = rsa_encrypt_js(password + ">" + mac, config.public_exponent, config.public_modulus)
    return {
        "userId": js_double_encode(username),
        "password": js_double_encode(portal_password),
        "service": js_double_encode(config.service),
        "queryString": js_double_encode(config.query_string),
        "operatorPwd": js_double_encode(""),
        "operatorUserId": js_double_encode(""),
        # doauthen() 未对验证码做 encodeURIComponent——保持页面行为
        "validcode": "",
        "passwordEncrypt": js_double_encode("true" if effective_encrypt else "false"),
    }


def _classify_login_result(result: HTTPResult) -> AuthResult:
    try:
        value = json.loads(result.text.lstrip("\ufeff"))
    except json.JSONDecodeError:
        return AuthResult(AuthCode.PORTAL_CHANGED, "error.portal_changed",
                          evidence=(f"login: non-json http {result.status}",))
    if not isinstance(value, dict):
        return AuthResult(AuthCode.PORTAL_CHANGED, "error.portal_changed",
                          evidence=("login: json non-object",))
    if str(value.get("result", "")).lower() == "success":
        keepalive = value.get("keepaliveInterval") or value.get("keepaliveMinutes")
        try:
            minutes = int(keepalive) if keepalive not in (None, "", 0, "0") else None
        except (TypeError, ValueError):
            minutes = None
        return AuthResult(AuthCode.SUCCESS, "status.authenticating_done",
                          evidence=(f"login http {result.status} result=success",),
                          keepalive_minutes=minutes)
    message = re.sub(r"\s+", " ", str(value.get("message") or "")).strip()[:160]
    if value.get("validCodeUrl"):
        return AuthResult(AuthCode.INTERACTION_REQUIRED, "error.interaction_required",
                          evidence=("portal requires validcode",))
    lowered = message.lower()
    if any(token in lowered for token in ("密码", "用户名", "password", "username", "账号")):
        return AuthResult(AuthCode.INVALID_CREDENTIALS, "error.invalid_creds",
                          evidence=(message,))
    return AuthResult(AuthCode.UNKNOWN_ERROR, "status.action_required",
                      evidence=(message or f"result={value.get('result')}",),
                      recovery_hint=f"门户返回：{message or '未知原因'}" if message else "")


class ZstuAdapter:
    id = ADAPTER_ID
    name = "浙江理工大学"
    api_version = API_VERSION

    def __init__(self, discovery_url: str = DEFAULT_DISCOVERY_URL,
                 entry_url: str | None = None,
                 discovery_candidates: tuple[str, ...] | None = None) -> None:
        self._discovery_url = discovery_url
        # 门户入口完整 URL（含会话参数）：校园网白名单放行探针域名时
        # discovery 会返回 204（假在线），此时用 entry 直连门户引导会话。
        self._entry_url = entry_url
        # 发现候选：构造参数优先（测试注入 / 现场覆盖），通用候选殿后。
        self._discovery_candidates = (
            (discovery_url,) + (discovery_candidates or DISCOVERY_CANDIDATES)
        )

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _portal_host_of(url: str) -> str | None:
        parts = urlsplit(url)
        if "eportal" in parts.path:
            return parts.hostname
        return None

    def _discover(self, ctx: AdapterContext, *, strict_hosts: frozenset[str] | None):
        """discovery → 302 → ePortal 入口。strict_hosts 非 None 时禁止跳出该集合。

        多候选依次尝试：连通性检测域名被白名单放行(204)时改试非白名单
        HTTP 站——AC 对未认证设备的 302 携带新鲜会话参数，是白名单环境
        下唯一可靠的入口来源（2026-10-28 浙理工现场）。"""
        # detect/verify 阶段无凭据，allowed=None 允许观察跳转链（作为证据记录）；
        # authenticate 阶段传入 {portal_host, discovery_host}，跳转越界立即终止。
        # 构造参数指定的 discovery_url 优先(测试注入/现场覆盖),通用候选殿后。
        client = ctx.client_factory(strict_hosts, tls_verify=True)
        candidates = self._discovery_candidates
        for url in candidates:
            try:
                result = client.request(url)
            except NetworkRequestError:
                continue  # 该候选不可达，试下一个
            if result.status == 204:
                continue  # 候选直通(被放行)——试下一个找门户
            if result.status == 404:
                continue  # 候选不存在(测试/环境无此站)——试下一个
            return client, result
        return client, None  # 全部候选直通(204)——"假在线"弱信号,由调用方按语义处理

    # -------------------------------------------------------------- detect

    def detect(self, ctx: AdapterContext) -> DetectionResult:
        try:
            client, result = self._discover(ctx, strict_hosts=None)
        except NetworkRequestError as exc:
            return DetectionResult(matched=False, adapter_id=ADAPTER_ID,
                                   evidence=(f"discovery unreachable: {exc.reason}",))
        except UntrustedRedirectError as exc:
            host = self._portal_host_of(exc.url)
            return self._match_redirect(host, exc.url, cert=None, extra=("redirect to unlisted host",))
        if result is None or result.status == 204:
            # 探测域名被白名单放行的"假在线"：配置了门户入口 URL 时直接
            # 探测门户（可能伺服登录页=待认证）；未配置则如实报未匹配。
            if result is None and self._entry_url:
                try:
                    entry_client = ctx.client_factory(None, tls_verify=True)
                    entry_result = entry_client.request(self._entry_url)
                    return self._match_redirect(
                        self._portal_host_of(entry_result.url), entry_result.url,
                        cert=entry_result.peer_cert_sha256,
                    )
                except (NetworkRequestError, UntrustedRedirectError):
                    pass
            return DetectionResult(matched=False, adapter_id=ADAPTER_ID,
                                   evidence=("all discovery candidates 204 = online; no entry url",))
        host = self._portal_host_of(result.url)
        return self._match_redirect(host, result.url, cert=result.peer_cert_sha256)

    def _match_redirect(self, host: str | None, url: str, *, cert: str | None,
                        extra: tuple[str, ...] = ()) -> DetectionResult:
        if host is None:
            return DetectionResult(matched=False, adapter_id=ADAPTER_ID,
                                   evidence=("no eportal redirect observed",) + extra)
        path = urlsplit(url).path
        already = path.endswith("success.jsp")
        fingerprint = sha256(f"{host}|{'success' if already else 'login'}".encode()).hexdigest()[:16]
        port = urlsplit(url).port or (443 if urlsplit(url).scheme == "https" else 80)
        return DetectionResult(
            matched=True, adapter_id=ADAPTER_ID,
            portal_scheme=urlsplit(url).scheme, portal_host=host, portal_port=port,
            fingerprint=fingerprint, already_authenticated=already, needs_trust=True,
            evidence=(f"eportal path: {path}",) + extra,
            observed_cert_sha256=cert,
        )

    # --------------------------------------------------------- authenticate

    def authenticate(self, ctx: AdapterContext, creds: Credentials) -> AuthResult:
        try:
            # 先做一次无凭据发现以确定门户宿主，再以严格 allowed_hosts 重建客户端。
            client0, probe = self._discover(ctx, strict_hosts=None)
            # discovery 全候选直通（探测域名被白名单放行）是"假在线"弱证据——
            # 在 authenticate 上下文不可信；配置了门户入口 URL 时直连入口引导
            # 会话（2026-10-28 浙理工现场：gstatic 204 但门户伺服登录页）。
            if probe is None and self._entry_url:
                ctx.check_generation()
                probe = client0.request(self._entry_url)
            if probe is None:
                return AuthResult(AuthCode.ALREADY_AUTHENTICATED, "status.no_auth",
                                  evidence=("all discovery 204 = online",))
            portal_host = self._portal_host_of(probe.url)
            if portal_host is None:
                return AuthResult(AuthCode.PORTAL_CHANGED, "error.portal_changed",
                                  evidence=("discovery did not reach eportal",))
            discovery_host = urlsplit(self._discovery_url).hostname or ""
            allowed = frozenset({portal_host, discovery_host})
            ctx.check_generation()

            client = ctx.client_factory(allowed, tls_verify=True)
            config, query = bootstrap(
                client, probe.url, ctx.check_generation
            )
        except _AlreadyOnline:
            return AuthResult(AuthCode.ALREADY_AUTHENTICATED, "status.no_auth",
                              evidence=("discovery 204 = online",))
        except _PortalProtocolError as exc:
            if exc.code == AuthCode.NETWORK_ERROR:
                return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                                  evidence=(str(exc),))
            return AuthResult(exc.code, "error.portal_changed" if exc.code == AuthCode.PORTAL_CHANGED
                              else "error.interaction_required", evidence=(str(exc),))
        except NetworkRequestError as exc:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(exc.reason,))
        except UntrustedRedirectError as exc:
            return AuthResult(AuthCode.UNTRUSTED_TARGET, "error.untrusted_target",
                              evidence=(f"redirect away from portal: {urlsplit(exc.url).hostname}",))

        mac = _raw_query_param(query, "mac") or "111111111"
        if config.service_required and not config.service:
            return AuthResult(AuthCode.INTERACTION_REQUIRED, "error.interaction_required",
                              evidence=("portal requires service selection",))
        try:
            payload = build_login_payload(config, creds.username, creds.password, mac)
        except _PortalProtocolError as exc:
            return AuthResult(exc.code, "error.portal_changed", evidence=(str(exc),))

        try:
            ctx.check_generation()
            result = _post_interface(client, config.login_endpoint, payload, config.entry_url)
        except NetworkRequestError as exc:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(exc.reason,))
        except UntrustedRedirectError as exc:
            return AuthResult(AuthCode.UNTRUSTED_TARGET, "error.untrusted_target",
                              evidence=(f"redirect away from portal: {urlsplit(exc.url).hostname}",))
        return _classify_login_result(result)

    # ------------------------------------------------------- verify_protocol

    def verify_protocol(self, ctx: AdapterContext) -> ProtocolVerifyResult:
        try:
            client, result = self._discover(ctx, strict_hosts=None)
        except NetworkRequestError as exc:
            return ProtocolVerifyResult(None, (f"discovery failed: {type(exc).__name__}",))
        if result is None or result.status == 204:
            if result is None and self._entry_url:
                entry_result = client.request(self._entry_url)
                path = urlsplit(entry_result.url).path
                if path.endswith("success.jsp"):
                    return ProtocolVerifyResult(True, ("entry success.jsp = session valid",))
                if path.endswith("index.jsp"):
                    return ProtocolVerifyResult(False, ("entry index.jsp = session invalid",))
            return ProtocolVerifyResult(True, ("discovery 204 = online",))
        path = urlsplit(result.url).path
        if path.endswith("success.jsp"):
            return ProtocolVerifyResult(True, ("eportal success.jsp = session valid",))
        if path.endswith("index.jsp"):
            return ProtocolVerifyResult(False, ("eportal index.jsp = session invalid",))
        return ProtocolVerifyResult(None, (f"discovery http {result.status}",))
