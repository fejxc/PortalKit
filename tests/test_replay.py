"""现场证据回放：fixtures/*.json 在 FakePortalServer 上声明式重放。

把现场事故固化成回归用例（格式与工作流见 tests/fixtures/README.md）。
新增 fixture 只需落一个 JSON——本测试自动发现并重放。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import make_ctx
from fakeserver import FakePortalServer
from portalkit.adapters.base import Credentials
from portalkit.adapters.zjlib import ZjlibAdapter
from portalkit.adapters.zstu import ZstuAdapter
from portalkit.models import AuthCode

FIXTURES = sorted((Path(__file__).parent / "fixtures").glob("*.json"))

_REQUIRED = {"name", "scenario", "adapter", "routes", "run", "expect"}


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    missing = _REQUIRED - data.keys()
    assert not missing, f"{path.name} 缺少字段: {sorted(missing)}"
    assert data["adapter"] in {"zstu", "zjlib"}, data["adapter"]
    assert data["run"] in {"detect", "authenticate"}, data["run"]
    assert data["scenario"], "scenario 必须说明现场背景"
    return data


def _route_handler(spec: dict):
    def handler(p, r, q):
        detail = spec
        if "by_method" in spec:
            detail = spec["by_method"].get(q.get("method", ""))
            if detail is None:
                return 404, {}, {}
        status = int(detail.get("status", 200))
        headers: dict[str, str] = {}
        if "redirect" in detail:
            loc = str(detail["redirect"])
            headers["Location"] = loc if loc.startswith("http") else p.url(loc)
        if "json" in detail:
            return status, headers, detail["json"]
        return status, headers, str(detail.get("body", ""))

    return handler


def _build_adapter(portal: FakePortalServer, data: dict):
    if data["adapter"] == "zstu":
        return ZstuAdapter(
            discovery_url=portal.url("/generate_204"),
            discovery_candidates=tuple(
                portal.url(p) for p in ("/connecttest.txt", "/ns", "/ex")
            ),
            entry_url=portal.url(data["entry_url"]) if data.get("entry_url") else None,
        )
    return ZjlibAdapter(entry_url=portal.url(data["entry_url"]))


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_replay_field_evidence(path: Path):
    data = _load(path)
    portal = FakePortalServer()
    try:
        for spec in data["routes"]:
            portal.route(spec.get("method", "GET"), spec["path"], _route_handler(spec))
        adapter = _build_adapter(portal, data)
        expect = data["expect"]
        if data["run"] == "detect":
            result = adapter.detect(make_ctx(portal))
            if "matched" in expect:
                assert result.matched is expect["matched"], data["scenario"]
            if "already_authenticated" in expect:
                assert result.already_authenticated is expect["already_authenticated"]
        else:
            result = adapter.authenticate(
                make_ctx(portal), Credentials("fixture-user", "fixture-pass")
            )
            assert result.code == AuthCode(expect["code"]), data["scenario"]
            if "recovery_hint" in expect:
                assert expect["recovery_hint"] in (result.recovery_hint or "")
        for denied in expect.get("no_request_to", []):
            assert portal.requests_to(denied) == [], \
                f"{data['name']}: 不允许请求 {denied}"
        for required in expect.get("request_to", []):
            assert portal.requests_to(required), \
                f"{data['name']}: 缺少对 {required} 的请求"
    finally:
        portal.stop()


def test_fixtures_exist():
    assert FIXTURES, "tests/fixtures/ 下必须有现场回放用例"
