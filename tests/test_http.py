"""BoundHTTPClient：回环绑定、代理隔离、受控重定向、Cookie 持久化。"""

from __future__ import annotations

import pytest

from portalkit.network.http import (
    BoundHTTPClient,
    NetworkRequestError,
    UntrustedRedirectError,
)


def test_loopback_binding(portal):
    portal.route("GET", "/ping", lambda p, r, q: (200, {}, "pong"))
    client = BoundHTTPClient(interface="lo0")
    result = client.request(portal.url("/ping"))
    assert result.status == 200
    assert result.text == "pong"


def test_nonexistent_interface_fails_closed(portal):
    portal.route("GET", "/ping", lambda p, r, q: (200, {}, "pong"))
    client = BoundHTTPClient(interface="en99999")
    with pytest.raises(NetworkRequestError):
        client.request(portal.url("/ping"))


def test_proxy_environment_is_ignored(portal, monkeypatch):
    portal.route("GET", "/ping", lambda p, r, q: (200, {}, "pong"))
    monkeypatch.setenv("http_proxy", "http://10.255.255.1:9")
    monkeypatch.setenv("https_proxy", "http://10.255.255.1:9")
    monkeypatch.setenv("all_proxy", "socks5://10.255.255.1:9")
    client = BoundHTTPClient()
    result = client.request(portal.url("/ping"))
    assert result.status == 200


def test_cross_host_redirect_blocked_when_credentials_phase(portal):
    def redir(p, r, q):
        return (302, {"Location": "http://evil.example/next"}, "")

    portal.route("GET", "/start", redir)
    client = BoundHTTPClient(allowed_hosts={"127.0.0.1"})
    with pytest.raises(UntrustedRedirectError):
        client.request(portal.url("/start"))
    # 请求确实落在假门户，但从未跟到 evil.example
    assert portal.requests_to("/start")


def test_allowed_same_host_redirect_follows(portal):
    portal.route("GET", "/start", lambda p, r, q: (
        302, {"Location": portal.url("/landing")}, ""))
    portal.route("GET", "/landing", lambda p, r, q: (200, {}, "landed"))
    client = BoundHTTPClient(allowed_hosts={"127.0.0.1"})
    result = client.request(portal.url("/start"))
    assert result.status == 200
    assert result.text == "landed"


def test_cookie_persists_within_client(portal):
    portal.route("POST", "/login", lambda p, r, q: (
        200, {"Set-Cookie": "JSESSIONID=SESS42; Path=/"}, "ok"))
    portal.route("GET", "/whoami", lambda p, r, q: (
        200, {}, p.requests[-1]["headers"].get("cookie", "<none>")))
    client = BoundHTTPClient()
    client.request(portal.url("/login"), method="POST", data="a=1")
    result = client.request(portal.url("/whoami"))
    assert "JSESSIONID=SESS42" in result.text


def test_url_query_not_logged_in_errors(portal):
    # 网络错误信息必须脱敏 query（可能含会话参数）
    client = BoundHTTPClient()
    with pytest.raises(NetworkRequestError) as excinfo:
        client.request("http://127.0.0.1:9/secret?wlanuserip=10.1.1.1&mac=AA")
    assert "wlanuserip" not in str(excinfo.value)
    assert "AA" not in str(excinfo.value)
