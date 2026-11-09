"""通用 ePortal 适配器与站点配置：加校园 = 一份配置（v1.3 参数化目标）。

协议语义回归仍由 test_zstu.py 承担（EPortalAdapter 直接继承其实现）；
这里验证参数化本身：id 传播、host_hint 过滤、站点配置加载与容错。
"""

from __future__ import annotations

import json

import pytest

from conftest import make_ctx
from fakeserver import FakePortalServer
from portalkit.adapters import default_registry
from portalkit.adapters.base import Credentials
from portalkit.adapters.eportal import EPortalAdapter
from portalkit.adapters.eportal_sites import (
    adapter_from_site,
    adapters_from_sites,
    load_site_configs,
    validate_site,
)
from portalkit.models import AuthCode


def _adapter(portal, **kwargs):
    base = dict(
        adapter_id="xxu",
        name="测试大学",
        discovery_url=portal.url("/generate_204"),
        discovery_candidates=tuple(portal.url(p) for p in ("/connecttest.txt", "/ns")),
    )
    base.update(kwargs)
    return EPortalAdapter(**base)


def _routes(portal, *, login_json=None):
    portal.route("GET", "/generate_204", lambda p, r, q: (
        302, {"Location": p.url("/eportal/index.jsp?wlanuserip=10.1.2.3&mac=AA-BB-CC-DD-EE-FF&url=x")}, ""))
    portal.route("GET", "/eportal/index.jsp", lambda p, r, q: (200, {}, "<html>eportal</html>"))

    def interface(p, r, q):
        method = q.get("method", "")
        if method == "pageInfo":
            return 200, {}, {"passwordEncrypt": "false", "validCodeUrl": ""}
        if method == "getServices":
            return 200, {}, {"isService": "false", "defaultService": "", "serviceJson": "[]"}
        if method == "login":
            return 200, {}, login_json or {"result": "success"}
        return 404, {}, {}

    portal.route("POST", "/eportal/InterFace.do", interface)


def test_generic_adapter_full_flow_with_own_id(portal):
    """识别与认证全程携带站点自身 id（信任/凭据按 id 隔离的前提）。"""
    _routes(portal)
    adapter = _adapter(portal)
    detection = adapter.detect(make_ctx(portal))
    assert detection.matched
    assert detection.adapter_id == "xxu"

    result = adapter.authenticate(make_ctx(portal), Credentials("u1", "p1"))
    assert result.code == AuthCode.SUCCESS
    assert adapter.id == "xxu" and adapter.name == "测试大学"


def test_host_hint_blocks_foreign_portal(portal):
    """同网另一个 ePortal 门户（宿主不同）→ host_hint 过滤，不得误配。"""
    _routes(portal)
    adapter = _adapter(portal, host_hint="10.20.30.40")
    detection = adapter.detect(make_ctx(portal))
    assert not detection.matched
    assert any("site hint" in ev for ev in detection.evidence)


def test_host_hint_accepts_matching_portal(portal):
    """宿主与 hint 一致（假门户即 127.0.0.1）→ 正常匹配。"""
    _routes(portal)
    adapter = _adapter(portal, host_hint="127.0.0.1")
    assert adapter.detect(make_ctx(portal)).matched


# ------------------------------------------------------------------ sites

def test_validate_site_accepts_and_normalizes():
    site = validate_site({"id": "xxu", "name": "某某大学",
                          "entry_url": "http://10.0.0.1:8080/eportal/index.jsp",
                          "host_hint": "10.0.0.1"})
    assert site["id"] == "xxu" and site["entry_url"].startswith("http")
    bare = validate_site({"id": "b-1", "name": "校区B"})
    assert bare["entry_url"] == "" and bare["host_hint"] == ""


@pytest.mark.parametrize("raw", [
    {"id": "XXU", "name": "大写拒绝"},
    {"id": "x", "name": "太短"},
    {"id": "xxu", "name": ""},
    {"id": "xxu", "name": "x" * 41},
    {"id": "xxu", "name": "n", "entry_url": "ftp://10.0.0.1/x"},
    {"id": "xxu", "name": "n", "host_hint": "http://10.0.0.1"},
    {"id": "xxu", "name": "n", "host_hint": "10.0.0.1/x"},
    "not-a-dict",
])
def test_validate_site_rejects_bad_entries(raw):
    with pytest.raises(ValueError):
        validate_site(raw)


def test_load_site_configs_skips_invalid_and_duplicates(tmp_path, capsys):
    (tmp_path / "eportal_sites.json").write_text(json.dumps([
        {"id": "aa", "name": "A 大学"},
        {"id": "aa", "name": "重复 id"},
        {"id": "BAD", "name": "非法 id"},
        {"id": "bb", "name": "B 大学"},
    ]), encoding="utf-8")
    sites = load_site_configs(tmp_path)
    assert [s["id"] for s in sites] == ["aa", "bb"]
    assert "已跳过" in capsys.readouterr().err


def test_load_site_configs_missing_or_broken_file(tmp_path, capsys):
    assert load_site_configs(tmp_path / "nope") == []
    (tmp_path / "eportal_sites.json").write_text("{broken", encoding="utf-8")
    assert load_site_configs(tmp_path) == []
    assert "无法解析" in capsys.readouterr().err


def test_adapters_from_sites_roundtrip(tmp_path):
    (tmp_path / "eportal_sites.json").write_text(json.dumps([
        {"id": "cc", "name": "C 大学", "entry_url": "https://portal.c.edu.cn/eportal/index.jsp",
         "host_hint": "portal.c.edu.cn"},
    ]), encoding="utf-8")
    adapters = adapters_from_sites(tmp_path)
    assert len(adapters) == 1
    assert adapters[0].id == "cc"
    assert adapters[0].name == "C 大学"
    assert adapters[0]._entry_url.endswith("index.jsp")
    assert adapter_from_site({"id": "dd", "name": "D 大学"}).id == "dd"


def test_default_registry_tolerates_broken_sites(tmp_path, capsys):
    """站点配置损坏绝不阻断注册表构建（启动路径红线）。"""
    (tmp_path / "eportal_sites.json").write_text("not json at all", encoding="utf-8")
    reg = default_registry(tmp_path)
    assert set(reg.ids()) >= {"zjlib", "zstu"}
