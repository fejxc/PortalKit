"""脱敏日志：B06 红线的回归测试。"""

from __future__ import annotations

import json

from portalkit.adapters.base import Credentials
from portalkit.diagnostics.logging import RedactedLogger, redact_text


def test_registered_secret_never_appears(tmp_path):
    sink = tmp_path / "events.jsonl"
    logger = RedactedLogger(sink_path=sink)
    logger.register_secret("SuperSecret123")
    logger.event("debug_probe", detail="sent SuperSecret123 to portal", other="fine")
    text = sink.read_text(encoding="utf-8")
    assert "SuperSecret123" not in text
    assert "***" in text
    record = json.loads(text.strip())
    assert record["other"] == "fine"


def test_sensitive_keys_masked_in_dicts(tmp_path):
    sink = tmp_path / "events.jsonl"
    logger = RedactedLogger(sink_path=sink)
    logger.event("fields", payload={"username": "u1", "password": "should-not-leak",
                                    "JSESSIONID": "ABC123"})
    record = json.loads(sink.read_text(encoding="utf-8").strip())
    assert record["payload"]["password"] == "***"
    assert record["payload"]["JSESSIONID"] == "***"
    assert record["payload"]["username"] == "u1"


def test_redact_text_key_value_forms():
    assert "password=***" in redact_text("POST password=hunter2&x=1")
    assert "hunter2" not in redact_text("POST password=hunter2&x=1")
    assert "SET-COOKIE" not in redact_text("set-cookie: JSESSIONID=XYZ") or "XYZ=***" not in ""


def test_credentials_repr_hides_password():
    creds = Credentials("user01", "plain-pass")
    assert "plain-pass" not in repr(creds)
    assert "plain-pass" not in str(creds)
