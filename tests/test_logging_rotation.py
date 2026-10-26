"""日志轮转：超限滚动、保留份数上限、脱敏在轮转后依然生效。"""

from __future__ import annotations

import json

from portalkit.diagnostics.logging import RedactedLogger


def test_rotation_caps_size_and_keeps_backups(tmp_path):
    sink = tmp_path / "events.jsonl"
    logger = RedactedLogger(sink_path=sink, max_bytes=2000, backups=2)
    for index in range(200):
        logger.event("filler", index=index, payload="x" * 60)
    assert sink.exists()
    assert sink.stat().st_size < 10_000  # 超限即滚动，主文件不会无限膨胀
    rotated = sorted(tmp_path.glob("events.jsonl.*"))
    assert len(rotated) <= 2
    # 所有滚动文件仍是合法 JSON Lines
    for path in (sink, *rotated):
        for line in path.read_text(encoding="utf-8").splitlines():
            json.loads(line)


def test_secrets_redacted_across_rotation(tmp_path):
    sink = tmp_path / "events.jsonl"
    logger = RedactedLogger(sink_path=sink, max_bytes=1500, backups=2)
    logger.register_secret("SuperSecret123")
    for index in range(120):
        logger.event("probe", index=index, note="contains SuperSecret123 here")
    for path in tmp_path.glob("events.jsonl*"):
        assert "SuperSecret123" not in path.read_text(encoding="utf-8")
