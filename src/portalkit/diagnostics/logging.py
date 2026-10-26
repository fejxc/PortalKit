"""脱敏结构化日志（SECURITY §5）。

- 默认级别只记录：时间、阶段、适配器、结果码、HTTP 状态、耗时、接口摘要。
- 绝不记录：密码、Cookie/JSESSIONID、userIndex、完整带 query 的 URL、请求体。
- `register_secret()` 的值在序列化时替换为 ***；响应体摘要额外过正则清洗。
- 输出 JSON Lines：文件（诊断模式）或 stderr（CLI 调试）。
"""

from __future__ import annotations

import json
import re
import sys
import threading
from pathlib import Path
from typing import Any

from portalkit.models import utc_now_iso

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|validcode|accesscode|jsessionid|cookie|authorization|userindex|token)",
    re.I,
)
_SECRET_VALUE_RE = re.compile(r"[^&\s\"']+")


def redact_text(text: str, max_len: int = 200) -> str:
    """对响应体/错误摘要做键值清洗 + 截断。"""
    scrubbed = _SENSITIVE_KEY_RE.sub(
        lambda m: m.group(0) + "=***", text
    )
    # 键=值 形态：键名命中即遮蔽值
    scrubbed = re.sub(
        r"(" + _SENSITIVE_KEY_RE.pattern + r")\s*[=:]\s*(" + _SECRET_VALUE_RE.pattern + r")",
        lambda m: m.group(1) + "=***",
        scrubbed,
        flags=re.I,
    )
    scrubbed = re.sub(r"\s+", " ", scrubbed).strip()
    return scrubbed[:max_len]


class RedactedLogger:
    """JSON Lines 结构化日志。secret 登记后任何字段值中的出现都会被打码。"""

    def __init__(self, sink_path: Path | None = None, echo_stderr: bool = False) -> None:
        self._sink = sink_path
        self._echo = echo_stderr
        self._secrets: set[str] = set()
        self._lock = threading.Lock()

    def register_secret(self, value: str) -> None:
        if value:
            self._secrets.add(value)

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            out = value
            for secret in self._secrets:
                if secret in out:
                    out = out.replace(secret, "***")
            return out
        if isinstance(value, dict):
            return {
                k: ("***" if _SENSITIVE_KEY_RE.search(str(k)) else self._scrub(v))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self._scrub(v) for v in value]
        return value

    def event(self, event: str, *, level: str = "info", **fields: Any) -> None:
        record = {"ts": utc_now_iso(), "level": level, "event": event}
        record.update(self._scrub(fields))
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock:
            if self._sink is not None:
                self._sink.parent.mkdir(parents=True, exist_ok=True)
                with self._sink.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            if self._echo:
                print(line, file=sys.stderr)
