"""更新检查：版本比较纯函数 + API 解析（不联网）。"""

from __future__ import annotations

from portalkit.ui.updates import check_for_update, is_newer


def test_is_newer_semantics():
    assert is_newer("v1.0.1", "1.0.0")
    assert is_newer("v1.1.0", "1.0.9")
    assert is_newer("1.0", "1.0.0") is False  # 1.0 == 1.0.0
    assert is_newer("v1.0.0", "1.0.0") is False
    assert is_newer("v0.9", "1.0.0") is False
    assert is_newer("garbage", "1.0.0") is False


def test_check_for_update_parses_release_payload(monkeypatch):
    import io
    import urllib.request

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    payload = (
        b'{"tag_name": "v1.2.0", "html_url": "https://github.com/fejxc/PortalKit/releases/tag/v1.2.0"}'
    )

    def fake_urlopen(request, timeout):
        return FakeResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    info = check_for_update("1.0.1")
    assert info is not None
    assert info.has_update and info.latest_tag == "v1.2.0"

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert check_for_update("1.0.1") is None  # 网络失败静默为 None
