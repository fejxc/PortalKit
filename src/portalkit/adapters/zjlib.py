"""zjlib 适配器 — 浙江图书馆 Wi-Fi（Online Service 门户）。

迁移自 `~/Documents/zjlib-wifi/zjlib/wifi_login.py` v2.0（审计报告 §3），
HTTP 流程与字段集与真实门户 debug HTML 交叉验证一致：

1. GET 入口 `https://2.2.1.1:8443/cn/index.html`（自签 HTTPS）。
   **404 = 已认证**（门户只在未认证状态伺服登录页）。
2. 入口页 iframe 定位登录页 `/cn/login.html`，解析 HTML form。
3. 按门户 Mac 端 submitFunc() 的 XHR 字段提交：
   username / password / RedirectUrl / anonymous / anonymousurl /
   checkbox / checkbox1 / accesscode。
4. 成功判定沿用内容启发式，但降级为"待验证"信号——已联网只由
   core 物理出口验证授予（决策 D4）。

安全注记：门户为自签证书，客户端 tls_verify=False；补偿措施是
TrustRecord.cert_sha256 指纹 pinning（首次信任时采集，此后不匹配即
PORTAL_CHANGED 暂停自动提交）。
"""

from __future__ import annotations

import html.parser
import re
import urllib.parse
from dataclasses import dataclass, field
from hashlib import sha256

from portalkit.adapters.base import AdapterContext, AuthResult, Credentials, DetectionResult, ProtocolVerifyResult
from portalkit.models import AuthCode
from portalkit.network.http import HTTPResult, NetworkRequestError

ADAPTER_ID = "zjlib"
API_VERSION = 1

DEFAULT_ENTRY_URL = "https://2.2.1.1:8443/cn/index.html"

_SUCCESS_TOKENS = (
    "auth_success.html", "success", "logout", "user has online",
    "已登录", "认证成功", "登录成功", "用户已在线",
)
_CRED_ERROR_TOKENS = ("用户名", "密码", "username", "password", "账号")


@dataclass
class Form:
    action: str = ""
    method: str = "GET"
    inputs: list[dict[str, str]] = field(default_factory=list)


class _PortalParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.iframes: list[str] = []
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag, attrs):
        attr = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag == "iframe" and attr.get("src"):
            self.iframes.append(attr["src"])
        elif tag == "form":
            self._current = Form(
                action=attr.get("action", ""),
                method=(attr.get("method", "GET") or "GET").upper(),
            )
        elif tag == "input" and self._current is not None:
            self._current.inputs.append(attr)

    def handle_endtag(self, tag):
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def _parse(html_text: str) -> _PortalParser:
    parser = _PortalParser()
    parser.feed(html_text)
    return parser


def _find_login_page(entry_url: str, entry_html: str) -> str:
    parser = _parse(entry_html)
    for src in parser.iframes:
        if "login" in src.lower():
            return urllib.parse.urljoin(entry_url, src)
    if parser.iframes:
        return urllib.parse.urljoin(entry_url, parser.iframes[0])
    return entry_url


def _pick_form(forms: list[Form]) -> Form | None:
    for form in forms:
        names = " ".join(
            (i.get("name", "") + " " + i.get("id", "")).lower() for i in form.inputs
        )
        if any(w in names for w in ("user", "account", "login", "name", "pass", "pwd")):
            return form
    return forms[0] if forms else None


def _build_ajax_payload(form: Form, username: str, password: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in form.inputs:
        key = (item.get("name") or item.get("id") or "").strip()
        if not key:
            continue
        values[key] = (
            item.get("value") or "on" if item.get("type", "text").lower() == "checkbox" else item.get("value", "")
        )
    # 与 /cn/login.html submitFunc() Mac 分支一致；缺失 RedirectUrl/anonymous 会被判非法请求。
    return {
        "username": username,
        "password": password,
        "RedirectUrl": values.get("RedirectUrl", ""),
        "anonymous": values.get("anonymous", "DISABLE"),
        "anonymousurl": "",
        "checkbox": values.get("checkbox", "on"),
        "checkbox1": values.get("checkbox1", "on"),
        "accesscode": values.get("accesscode", ""),
    }


def _fingerprint(login_html: str, host: str) -> str:
    parser = _parse(login_html)
    form = _pick_form(parser.forms)
    names = sorted(
        (i.get("name") or i.get("id") or "") for i in (form.inputs if form else [])
    )
    return sha256(f"{host}|{','.join(names)}".encode()).hexdigest()[:16]


def _looks_successful(text: str, final_url: str) -> bool:
    lowered = text.lower()
    if any(t in lowered for t in _SUCCESS_TOKENS):
        return True
    if "error" in lowered or "失败" in text or "错误" in text:
        return False
    return "login" not in final_url.lower() and "login" not in lowered[:2000]


class ZjlibAdapter:
    id = ADAPTER_ID
    name = "浙江图书馆"
    api_version = API_VERSION

    def __init__(self, entry_url: str = DEFAULT_ENTRY_URL) -> None:
        self._entry_url = entry_url

    # ------------------------------------------------------------- helpers

    def _portal_endpoint(self) -> tuple[str, str, int]:
        parts = urllib.parse.urlsplit(self._entry_url)
        host = parts.hostname or "2.2.1.1"
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return parts.scheme or "https", host, port

    def _client(self, ctx: AdapterContext):
        scheme, host, port = self._portal_endpoint()
        # 无凭据阶段（detect）允许跨到 iframe 登录页宿主；两者同宿主。
        return ctx.client_factory(frozenset({host}), tls_verify=False)

    # -------------------------------------------------------------- detect

    def detect(self, ctx: AdapterContext) -> DetectionResult:
        scheme, host, port = self._portal_endpoint()
        client = self._client(ctx)
        try:
            ctx.check_generation()
            result = client.request(self._entry_url)
        except NetworkRequestError as exc:
            return DetectionResult(
                matched=False, adapter_id=ADAPTER_ID,
                evidence=(f"portal unreachable: {exc.reason}",),
            )
        if result.status == 404:
            # 门户只在未认证状态伺服登录页；404 = 门户可达且会话有效。
            return DetectionResult(
                matched=True, adapter_id=ADAPTER_ID,
                portal_scheme=scheme, portal_host=host, portal_port=port,
                already_authenticated=True, needs_trust=True,
                evidence=(f"entry http {result.status} (portal semantics: 404=authenticated)",),
                observed_cert_sha256=result.peer_cert_sha256,
            )
        if result.status != 200:
            return DetectionResult(
                matched=False, adapter_id=ADAPTER_ID,
                evidence=(f"entry http {result.status}",),
            )
        login_page = _find_login_page(result.url, result.text)
        try:
            ctx.check_generation()
            login_result = client.request(login_page, referer=result.url)
        except NetworkRequestError as exc:
            return DetectionResult(
                matched=False, adapter_id=ADAPTER_ID,
                evidence=(f"login page unreachable: {exc.reason}",),
            )
        form = _pick_form(_parse(login_result.text).forms)
        if form is None:
            return DetectionResult(
                matched=False, adapter_id=ADAPTER_ID,
                evidence=("login page has no usable form (portal redesign?)",),
            )
        return DetectionResult(
            matched=True, adapter_id=ADAPTER_ID,
            portal_scheme=scheme, portal_host=host, portal_port=port,
            fingerprint=_fingerprint(login_result.text, host),
            needs_trust=True,
            evidence=(
                f"iframe login page: {urllib.parse.urlsplit(login_page).path}",
                "form fields: " + ",".join(sorted(
                    (i.get("name") or i.get("id") or "") for i in form.inputs if i.get("name") or i.get("id")
                )),
            ),
            observed_cert_sha256=login_result.peer_cert_sha256 or result.peer_cert_sha256,
        )

    # --------------------------------------------------------- authenticate

    def authenticate(self, ctx: AdapterContext, creds: Credentials) -> AuthResult:
        _, host, _ = self._portal_endpoint()
        client = self._client(ctx)
        try:
            ctx.check_generation()
            entry = client.request(self._entry_url)
        except NetworkRequestError as exc:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(exc.reason,))
        if entry.status == 404:
            # 门户语义 404=会话有效，但在 authenticate 上下文（物理路径已知不通，
            # 由 core 前置探针过滤在线场景 / 用户主动要求认证）里该弱证据不可信：
            # 会话可能已按 IP 过期。照常提交登录以刷新会话；"已在线不重复提交"
            # (A03) 由 check/auto_run 的互联网探针保证，不在此处拦截。
            pass
        elif entry.status != 200:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(f"entry http {entry.status}",))

        login_page = _find_login_page(entry.url, entry.text)
        try:
            ctx.check_generation()
            login = client.request(login_page, referer=entry.url)
        except NetworkRequestError as exc:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(exc.reason,))
        if login.status != 200:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(f"login page http {login.status}",))
        form = _pick_form(_parse(login.text).forms)
        if form is None:
            return AuthResult(AuthCode.PORTAL_CHANGED, "error.portal_changed",
                              evidence=("login form disappeared",))

        action_url = urllib.parse.urljoin(login.url, form.action or login.url)
        method = form.method if form.method in {"GET", "POST"} else "POST"
        payload = _build_ajax_payload(form, creds.username, creds.password)
        body: str | None = urllib.parse.urlencode(payload)
        url = action_url
        if method == "GET":
            url = action_url + ("&" if "?" in action_url else "?") + body
            body = None
        try:
            ctx.check_generation()
            result = client.request(
                url, method=method, data=body, referer=login.url,
                headers={"Origin": f"https://{host}"} if method == "POST" else None,
            )
        except NetworkRequestError as exc:
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(exc.reason,))

        if result.status not in (200, 302):
            return AuthResult(AuthCode.NETWORK_ERROR, "error.network", retryable=True,
                              evidence=(f"submit http {result.status}",))
        if _looks_successful(result.text, result.url):
            return AuthResult(AuthCode.SUCCESS, "status.authenticating_done",
                              evidence=(f"submit http {result.status}, success markers seen",))
        snippet = re.sub(r"\s+", " ", result.text).strip()[:160]
        lowered = result.text.lower()
        if any(t in lowered for t in _CRED_ERROR_TOKENS) and (
            "error" in lowered or "失败" in result.text or "错误" in result.text
        ):
            return AuthResult(AuthCode.INVALID_CREDENTIALS, "error.invalid_creds",
                              evidence=("portal reported credential error", snippet))
        return AuthResult(AuthCode.UNKNOWN_ERROR, "status.action_required",
                          evidence=("no success marker", snippet))

    # ------------------------------------------------------- verify_protocol

    def verify_protocol(self, ctx: AdapterContext) -> ProtocolVerifyResult:
        client = self._client(ctx)
        try:
            result = client.request(self._entry_url)
        except NetworkRequestError:
            return ProtocolVerifyResult(None, ("portal unreachable",))
        if result.status == 404:
            return ProtocolVerifyResult(True, ("entry 404 = session active",))
        if result.status == 200:
            return ProtocolVerifyResult(False, ("entry 200 = login page served (not authenticated)",))
        return ProtocolVerifyResult(None, (f"entry http {result.status}",))
