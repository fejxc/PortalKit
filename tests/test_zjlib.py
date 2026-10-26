"""zjlib 适配器：假门户全流程回归（404/200/改版/凭据错误语义）。"""

from __future__ import annotations

from conftest import make_ctx
from portalkit.adapters.base import Credentials
from portalkit.adapters.zjlib import ZjlibAdapter
from portalkit.models import AuthCode

ENTRY_HTML = """<html><body>
<iframe src="/cn/login.html" width="100%"></iframe>
</body></html>"""

LOGIN_HTML = """<html><body><form name="LoginForm" action="/cn/login" method="post">
<input type="text" name="username" id="username" value="">
<input type="password" name="password" id="password" value="">
<input type="hidden" name="RedirectUrl" value="">
<input type="hidden" name="anonymous" value="DISABLE">
<input type="hidden" name="anonymousurl" value="">
<input type="checkbox" name="checkbox" value="on" checked>
<input type="checkbox" name="checkbox1" value="on" checked>
<input type="hidden" name="accesscode" value="">
</form></body></html>"""

SUCCESS_HTML = "<html>window.location='auth_success.html';</html>"
CRED_ERROR_HTML = "<html>Error: 用户名或密码错误，请重新输入。</html>"
GENERIC_ERROR_HTML = "<html>system error page</html>"


def _adapter(portal):
    return ZjlibAdapter(entry_url=portal.url("/cn/index.html"))


def _routes(portal, *, login_page=LOGIN_HTML, submit_html=SUCCESS_HTML, entry_status=200):
    portal.route("GET", "/cn/index.html", lambda p, r, q: (entry_status, {}, ENTRY_HTML))
    portal.route("GET", "/cn/login.html", lambda p, r, q: (200, {}, login_page))
    portal.route(
        "POST", "/cn/login",
        lambda p, r, q: (200, {}, submit_html if r["body"].endswith("accesscode=on") or True else submit_html),
    )


def test_detect_matches_portal_and_records_fingerprint(portal):
    _routes(portal)
    adapter = _adapter(portal)
    result = adapter.detect(make_ctx(portal))
    assert result.matched
    assert result.adapter_id == "zjlib"
    assert result.portal_host == "127.0.0.1"
    assert result.fingerprint
    assert not result.already_authenticated
    assert any("form fields" in ev for ev in result.evidence)


def test_detect_404_means_already_authenticated(portal):
    _routes(portal, entry_status=404)
    adapter = _adapter(portal)
    result = adapter.detect(make_ctx(portal))
    assert result.matched
    assert result.already_authenticated


def test_detect_unreachable_returns_not_matched(portal):
    adapter = ZjlibAdapter(entry_url="http://127.0.0.1:9/cn/index.html")
    result = adapter.detect(make_ctx(portal))
    assert not result.matched
    assert any("unreachable" in ev for ev in result.evidence)


def test_detect_form_missing_maps_to_portal_changed(portal):
    _routes(portal, login_page="<html><body>redesigned</body></html>")
    adapter = _adapter(portal)
    result = adapter.detect(make_ctx(portal))
    assert not result.matched
    assert any("no usable form" in ev for ev in result.evidence)


def test_authenticate_success_submits_full_xhr_fields(portal):
    _routes(portal)
    adapter = _adapter(portal)
    result = adapter.authenticate(make_ctx(portal), Credentials("u1", "p1"))
    assert result.code == AuthCode.SUCCESS
    login_post = portal.requests_to("/cn/login")[0]
    body = login_post["body"]
    for field in ("username=u1", "password=p1", "RedirectUrl=", "anonymous=DISABLE",
                  "checkbox=on", "checkbox1=on", "accesscode="):
        assert field in body, field
    assert login_post["headers"]["content-type"].startswith("application/x-www-form-urlencoded")


def test_authenticate_credential_error_classified(portal):
    _routes(portal, submit_html=CRED_ERROR_HTML)
    adapter = _adapter(portal)
    result = adapter.authenticate(make_ctx(portal), Credentials("u1", "bad"))
    assert result.code == AuthCode.INVALID_CREDENTIALS


def test_authenticate_unknown_error_is_not_claimed_as_success(portal):
    _routes(portal, submit_html=GENERIC_ERROR_HTML)
    adapter = _adapter(portal)
    result = adapter.authenticate(make_ctx(portal), Credentials("u1", "p1"))
    assert result.code == AuthCode.UNKNOWN_ERROR
    # 失败结果绝不含"成功"语义
    assert result.code != AuthCode.SUCCESS


def test_authenticate_entry_404_already_authenticated(portal):
    _routes(portal, entry_status=404)
    adapter = _adapter(portal)
    result = adapter.authenticate(make_ctx(portal), Credentials("u1", "p1"))
    assert result.code == AuthCode.ALREADY_AUTHENTICATED
    assert portal.requests_to("/cn/login") == []  # 未提交任何表单


def test_verify_protocol_semantics(portal):
    adapter = _adapter(portal)
    _routes(portal, entry_status=404)
    assert adapter.verify_protocol(make_ctx(portal)).session_valid is True
    _routes(portal, entry_status=200)
    assert adapter.verify_protocol(make_ctx(portal)).session_valid is False
