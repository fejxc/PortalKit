"""信任记录生命周期字段:上次连接 / 会话寿命学习(1.2.0)。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from portalkit.core.trust import TrustRecord, TrustRegistry
from portalkit.models import utc_now_iso


def _record(tmp_registry: TrustRegistry, **overrides) -> TrustRecord:
    base = dict(
        adapter_id="zjlib", portal_host="2.2.1.1", portal_port=8443,
        scheme="https", allowed_hosts=("2.2.1.1",),
    )
    base.update(overrides)
    return tmp_registry.add(TrustRecord(**base))


def test_touch_connected_persists(tmp_path):
    registry = TrustRegistry(tmp_path)
    _record(registry)
    ts = utc_now_iso()
    registry.touch_connected("zjlib", "2.2.1.1", ts)
    loaded = TrustRegistry(tmp_path).lookup("zjlib", "2.2.1.1")
    assert loaded.last_connected_at == ts


def test_note_auth_success_records_lifetime_sample(tmp_path):
    registry = TrustRegistry(tmp_path)
    _record(registry)
    t0 = datetime.now(timezone.utc)
    registry.note_auth_success("zjlib", "2.2.1.1", t0.isoformat())
    # 间隔 < 1h(快速刷新)不计入样本
    registry.note_auth_success("zjlib", "2.2.1.1", (t0 + timedelta(minutes=20)).isoformat())
    loaded = TrustRegistry(tmp_path).lookup("zjlib", "2.2.1.1")
    assert loaded.session_lifetime_samples == ()
    # 间隔 >= 1h(真实重登)计入:18h - 20min = 17.67h
    registry.note_auth_success("zjlib", "2.2.1.1", (t0 + timedelta(hours=18)).isoformat())
    loaded = TrustRegistry(tmp_path).lookup("zjlib", "2.2.1.1")
    assert len(loaded.session_lifetime_samples) == 1
    assert abs(loaded.session_lifetime_samples[0] - 17.67) < 0.1


def test_lifetime_samples_capped_and_median(tmp_path):
    registry = TrustRegistry(tmp_path)
    _record(registry)
    t = datetime.now(timezone.utc)
    # 11 次调用,累计时间差 = 12,14,16,…,30(首次无样本)→ 10 个样本,中位数 21
    hours = (10, 22, 36, 52, 70, 90, 112, 136, 162, 190, 220)
    for h in hours:
        registry.note_auth_success("zjlib", "2.2.1.1", (t + timedelta(hours=h)).isoformat())
    loaded = TrustRegistry(tmp_path).lookup("zjlib", "2.2.1.1")
    assert len(loaded.session_lifetime_samples) == 10
    assert registry.median_session_lifetime_hours("zjlib", "2.2.1.1") == 21.0
    assert registry.median_session_lifetime_hours("zjlib", "missing") is None


def test_learned_predicted_expiry(tmp_path):
    registry = TrustRegistry(tmp_path)
    _record(registry)
    engine_like_registry = registry
    t0 = datetime.now(timezone.utc)
    engine_like_registry.note_auth_success("zjlib", "2.2.1.1", t0.isoformat())
    engine_like_registry.note_auth_success("zjlib", "2.2.1.1",
                                           (t0 + timedelta(hours=20)).isoformat())
    median = engine_like_registry.median_session_lifetime_hours("zjlib", "2.2.1.1")
    assert median is not None and 19 <= median <= 21
