"""zstu 适配器：假 ePortal 全流程回归（发现/公钥/RSA 提交/错误分类）。"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, unquote

from conftest import make_ctx
from portalkit.adapters.base import Credentials
from portalkit.adapters.zstu import ZstuAdapter
from portalkit.models import AuthCode
from test_rsa import _test_key

_N, _E, _D = _test_key()

PAGE_INFO = {
    "passwordEncrypt": "true",
    "publicKeyExponent": format(_E, "x"),
    "publicKeyModulus": format(_N, "x"),
    "prefixName": "false",
    "validCodeUrl": "",
}
SERVICES = {"isService": "false", "defaultService": "", "serviceJson": "[]"}


def _adapter(portal):
    return ZstuAdapter(discovery_url=portal.url("/generate_204"))


def _routes(portal, *, login_result=None, redirect_to="index"):
    def discovery(p, r, q):
        target = "/eportal/index.jsp?wlanuserip=10.1.2.3&mac=AA-BB-CC-DD-EE-FF&url=http%3A%2F%2Fexample.com%2F"
        if redirect_to == "success":
            target = "/eportal/success.jsp?userIndex=abc123"
        return (302, {"Location": p.url(target)}, "")

    portal.route("GET", "/generate_204", discovery)
    portal.route("GET", "/eportal/index.jsp", lambda p, r, q: (
        200, {"Set-Cookie": "JSESSIONID=FAKE123; Path=/eportal"},
        "<html>ePortal login page</html>",
    ))
    portal.route("GET", "/eportal/success.jsp", lambda p, r, q: (200, {}, "success"))

    def interface(p, r, q):
        method = q.get("method", "")
        if method == "pageInfo":
            return 200, {}, PAGE_INFO
        if method == "getServices":
            return 200, {}, SERVICES
        if method == "login":
            return 200, {}, login_result or {"result": "success", "keepaliveInterval": 1440}
        return 404, {}, {}

    portal.route("POST", "/eportal/InterFace.do", interface)


def _decrypt_password_field(portal) -> str:
    login_reqs = [r for r in portal.requests if r["path"] == "/eportal/InterFace.do"
                  and "method=login" in r["raw"]]
    assert login_reqs, "no login submit captured"
    fields = {}
    for pair in login_reqs[0]["body"].split("&"):
        key, _, value = pair.partition("=")
        fields[key] = value
    # password 字段 = double_encode(rsa_hex)
    cipher_hex = unquote(unquote(fields["password"]))
    blocks = cipher_hex.split(" ")
    digit_count = (_N.bit_length() + 15) // 16
    chunk_size = 2 * (digit_count - 1)
    units: list[int] = []
    for block_hex in blocks:
        raw = pow(int(block_hex, 16), _D, _N).to_bytes(chunk_size, "little")
        units.extend(raw)  # ASCII 密码下每字节即一个 UTF-16 unit（security.js 语义）
    while units and units[-1] == 0:
        units.pop()
    original = units[::-1]
    return bytes(b for u in original for b in (u & 0xFF, (u >> 8) & 0xFF)).decode("utf-16-le")


def test_detect_matches_eportal_via_discovery_redirect(portal):
    _routes(portal)
    result = _adapter(portal).detect(make_ctx(portal))
    assert result.matched
    assert result.portal_host == "127.0.0.1"
    assert result.already_authenticated is False
    assert any("index.jsp" in ev for ev in result.evidence)


def test_detect_success_jsp_means_session_valid(portal):
    _routes(portal, redirect_to="success")
    result = _adapter(portal).detect(make_ctx(portal))
    assert result.matched
    assert result.already_authenticated


def test_detect_204_without_entry_reports_not_matched(portal):
    """探测域名被白名单放行(假在线)且未配置门户入口 → 如实报未匹配;
    引擎此时回退探针结论(门户在场否决由引擎负责)。"""
    portal.route("GET", "/generate_204", lambda p, r, q: (204, {}, ""))
    result = _adapter(portal).detect(make_ctx(portal))
    assert not result.matched
    assert any("204" in ev for ev in result.evidence)


def test_detect_204_with_entry_probes_portal(portal):
    """配置了门户入口 URL 时,假在线直接探测门户 → 可识别登录页。"""
    adapter = ZstuAdapter(
        discovery_url=portal.url("/generate_204"),
        entry_url=portal.url("/eportal/index.jsp?wlanuserip=x&mac=y&url=z"),
    )
    portal.route("GET", "/generate_204", lambda p, r, q: (204, {}, ""))
    portal.route("GET", "/eportal/index.jsp", lambda p, r, q: (200, {}, "<html>eportal</html>"))
    result = adapter.detect(make_ctx(portal))
    assert result.matched and not result.already_authenticated


def test_authenticate_success_and_rsa_roundtrip(portal):
    _routes(portal)
    result = _adapter(portal).authenticate(make_ctx(portal), Credentials("stu001", "s3cret-pw"))
    assert result.code == AuthCode.SUCCESS
    assert result.keepalive_minutes == 1440
    decrypted = _decrypt_password_field(portal)
    assert decrypted == "s3cret-pw>AA-BB-CC-DD-EE-FF"
    # 会话 Cookie 在同一客户端内保持
    login_reqs = [r for r in portal.requests if "method=login" in r["raw"]]
    assert login_reqs[0]["headers"].get("cookie") == "JSESSIONID=FAKE123"


def test_authenticate_invalid_credentials(portal):
    _routes(portal, login_result={"result": "fail", "message": "用户名或密码错误"})
    result = _adapter(portal).authenticate(make_ctx(portal), Credentials("stu", "bad"))
    assert result.code == AuthCode.INVALID_CREDENTIALS


def test_authenticate_validcode_interaction_required(portal):
    _routes(portal, login_result={
        "result": "fail", "message": "验证码错误",
        "validCodeUrl": "http://127.0.0.1/eportal/captcha.jsp",
    })
    result = _adapter(portal).authenticate(make_ctx(portal), Credentials("stu", "pw"))
    assert result.code == AuthCode.INTERACTION_REQUIRED


def test_authenticate_discovery_204_already_online(portal):
    portal.route("GET", "/generate_204", lambda p, r, q: (204, {}, ""))
    result = _adapter(portal).authenticate(make_ctx(portal), Credentials("stu", "pw"))
    assert result.code == AuthCode.ALREADY_AUTHENTICATED


def test_authenticate_missing_query_params_rejected(portal):
    # 门户入口缺会话参数（wlanuserip/mac/url）→ 拒绝提交而非猜测
    portal.route("GET", "/generate_204", lambda p, r, q: (
        302, {"Location": p.url("/eportal/index.jsp")}, ""))
    portal.route("GET", "/eportal/index.jsp", lambda p, r, q: (200, {}, "<html>eportal</html>"))
    portal.route("POST", "/eportal/InterFace.do", lambda p, r, q: (200, {}, PAGE_INFO))
    result = _adapter(portal).authenticate(make_ctx(portal), Credentials("stu", "pw"))
    assert result.code == AuthCode.PORTAL_CHANGED


def test_verify_protocol_semantics(portal):
    adapter = _adapter(portal)
    portal.route("GET", "/generate_204", lambda p, r, q: (204, {}, ""))
    assert adapter.verify_protocol(make_ctx(portal)).session_valid is True
    _routes(portal, redirect_to="success")
    assert adapter.verify_protocol(make_ctx(portal)).session_valid is True
    _routes(portal, redirect_to="index")
    assert adapter.verify_protocol(make_ctx(portal)).session_valid is False
