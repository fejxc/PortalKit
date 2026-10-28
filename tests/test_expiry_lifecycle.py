"""会话过期自动重登全链路（假门户 + 真引擎 + 真适配器，无 Keychain/真实网络）。

覆盖"会话真过期"场景的每个环节：
1. 在线且会话有效 → 不提交凭据（A03）；
2. 门户重新伺服登录页（= 会话过期）+ 物理路径断 → auto_run 自动完成
   识别 → 提交 → 物理验证 → 已联网；
3. 恰好一次凭据提交，账号密码来自凭据服务。
真实门户上的同型验证（zjlib 现场）在下次现场补齐。
"""

from __future__ import annotations

from portalkit.adapters import AdapterRegistry
from portalkit.adapters.base import Credentials
from portalkit.adapters.zjlib import ZjlibAdapter
from portalkit.core.engine import Engine
from portalkit.core.retry import RetryPolicy
from portalkit.core.trust import TrustRecord, TrustRegistry
from portalkit.diagnostics.logging import RedactedLogger
from portalkit.models import InternetState, NetworkSnapshot, Phase
from portalkit.network.probes import InternetCheckResult

ENTRY_HTML = """<html><body>
<iframe src="/cn/login.html" width="100%"></iframe>
</body></html>"""

LOGIN_HTML = """<html><body><form name="LoginForm" action="/cn/login" method="post">
<input type="text" name="username" value="">
<input type="password" name="password" value="">
<input type="hidden" name="RedirectUrl" value="">
<input type="hidden" name="anonymous" value="DISABLE">
<input type="checkbox" name="checkbox" value="on" checked>
</form></body></html>"""

SUCCESS_HTML = "<html>window.location='auth_success.html';</html>"


def _online(passed=4):
    return InternetCheckResult(state=InternetState.REACHABLE, passed=passed, total=4,
                               evidence=("online",))


def _blocked():
    return InternetCheckResult(state=InternetState.BLOCKED, passed=0, total=4,
                               evidence=("blocked",))


def test_session_expiry_triggers_auto_relogin(portal, monkeypatch, tmp_path):
    import portalkit.core.engine as engine_module
    from test_engine import FakeMonitor, MemoryCredentials

    ENTRY, LOGIN, SUBMIT = "/cn/index.html", "/cn/login.html", "/cn/login"
    state = {"expired": False}

    def entry(_p, _r, _q):
        if not state["expired"]:
            return 404, {}, ""  # 门户"已认证"语义：入口 404
        return 200, {}, ENTRY_HTML  # 过期后重新伺服登录页

    portal.route("GET", ENTRY, entry)
    portal.route("GET", LOGIN, lambda p, r, q: (200, {}, LOGIN_HTML))

    def submit(_p, _r, _q):
        state["expired"] = False  # 登录成功 → 门户恢复"已认证"语义（与现实一致）
        return 200, {}, SUCCESS_HTML

    portal.route("POST", SUBMIT, submit)

    adapter = ZjlibAdapter(entry_url=portal.url(ENTRY))
    # 接口用 lo0：适配器走真实 socket 绑定，只有回环接口能连到 127.0.0.1 假门户
    monitor = FakeMonitor(
        NetworkSnapshot(interface="lo0", ipv4="127.0.0.1", gateway=None, dns=None)
    )
    scripted = [_online(), _online(), _blocked(), _online(), _online()]
    monkeypatch.setattr(
        engine_module, "check_internet", lambda i, d, timeout=5.0: scripted.pop(0)
    )

    trust = TrustRegistry(tmp_path / "trust")
    trust.add(TrustRecord(
        adapter_id="zjlib", portal_host="127.0.0.1", portal_port=portal.port,
        scheme="http", allowed_hosts=("127.0.0.1",), auto_auth=True,
    ))
    engine = Engine(
        monitor=monitor,
        registry=AdapterRegistry([adapter]),
        trust=trust,
        credentials=MemoryCredentials({("zjlib", "127.0.0.1"): Credentials("u1", "p1")}),
        logger=RedactedLogger(),
        retry_policy=RetryPolicy(max_attempts=3, delays_s=(0.0, 0.0, 0.0)),
        state_dir=tmp_path / "state",
    )

    # 1) 在线且会话有效：不提交凭据（A03）
    s1 = engine.auto_run()
    assert s1.phase == Phase.ONLINE_NO_AUTH
    assert portal.requests_to(SUBMIT) == []

    # 2) 会话过期：门户 200 + 出口断 → 全自动重登 → 已联网
    state["expired"] = True
    s2 = engine.auto_run()
    assert s2.phase == Phase.ONLINE_AUTHENTICATED
    assert s2.portal.value == "AUTHENTICATED"
    assert s2.internet.value == "REACHABLE"
    submits = portal.requests_to(SUBMIT)
    assert len(submits) == 1, "过期后应恰好一次凭据提交"
    assert "username=u1" in submits[0]["body"]
    assert "password=p1" in submits[0]["body"]  # 假门户本地断言；日志侧已脱敏

    # 3) 恢复在线后再 auto_run：不再提交（A03 回归）
    scripted.append(_online())
    scripted.append(_online())
    s3 = engine.auto_run()
    assert s3.phase == Phase.ONLINE_NO_AUTH
    assert len(portal.requests_to(SUBMIT)) == 1
