"""本地使用统计：计数、耗时样本、跨天重置、持久化、IO 异常免疫。"""

from __future__ import annotations

import json

from portalkit.diagnostics.stats import LocalStats


def test_counts_and_average(tmp_path):
    stats = LocalStats(tmp_path / "stats.json")
    stats.record_check()
    stats.record_check()
    stats.record_auth("success", 1800)
    stats.record_auth("success", 2200)
    stats.record_auth("network_error", 4000)
    summary = stats.summary_today()
    assert "今日检查 2 次" in summary
    assert "自动认证 3 次（成功 2 · 失败 1）" in summary
    assert "平均耗时 2.7s" in summary


def test_empty_stats_summary_is_blank(tmp_path):
    assert LocalStats(tmp_path / "s.json").summary_today() == ""


def test_persistence_roundtrip(tmp_path):
    path = tmp_path / "stats.json"
    LocalStats(path).record_auth("success", 1500)
    reloaded = LocalStats(path)
    assert "自动认证 1 次（成功 1 · 失败 0）" in reloaded.summary_today()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["durations_ms"] == [1500]


def test_day_rollover_resets(tmp_path):
    path = tmp_path / "stats.json"
    stats = LocalStats(path)
    stats.record_auth("success", 1000)
    # 手工把存储日期改成昨天
    data = json.loads(path.read_text(encoding="utf-8"))
    data["date"] = "2020-01-01"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert LocalStats(path).summary_today() == ""


def test_max_duration_samples_kept(tmp_path):
    path = tmp_path / "stats.json"
    stats = LocalStats(path, max_durations=3)
    for ms in (1000, 2000, 3000, 4000, 5000):
        stats.record_auth("success", ms)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["durations_ms"] == [3000, 4000, 5000]


def test_unwritable_path_never_raises(tmp_path):
    stats = LocalStats(tmp_path / "no-such-dir" / "s.json")
    stats.record_check()  # 目录缺失 → 保存失败被吞
    stats.record_auth("success", 100)
    assert "自动认证 1 次" in stats.summary_today()


def test_telemetry_summary_aggregates_and_flags_none(tmp_path):
    """遥测摘要：只含当日聚合计数；无数据返回 None（请求侧不带头）。"""
    stats = LocalStats(tmp_path / "stats.json")
    assert stats.telemetry_summary() is None  # 无任何数据
    stats.record_check()
    summary = stats.telemetry_summary()
    assert summary == {"checks": 1, "auth_total": 0, "auth_ok": 0, "auth_fail": 0}
    stats.record_auth("success", 800)
    stats.record_auth("invalid_credentials", 900)
    summary = stats.telemetry_summary()
    assert summary["auth_total"] == 2
    assert summary["auth_ok"] == 1
    assert summary["auth_fail"] == 1
    assert summary["top_fail_code"] == "invalid_credentials"
    # 摘要绝不包含任何标识/主机/自由文本字段
    assert set(summary) <= {"checks", "auth_total", "auth_ok", "auth_fail", "top_fail_code"}
