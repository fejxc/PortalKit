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
