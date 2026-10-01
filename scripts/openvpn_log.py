from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from pathlib import Path

RESET_MARKER = "SIGUSR1[soft,connection-reset]"
DEFAULT_TAIL_BYTES = 1_048_576

_ISO = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\b")
_CTIME = re.compile(r"^([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4})\b")


def _parse_ts(line: str) -> datetime | None:
    match = _ISO.match(line)
    if match:
        return datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
    match = _CTIME.match(line)
    if match:
        return datetime.strptime(" ".join(match.group(1).split()), "%a %b %d %H:%M:%S %Y")
    return None


def reset_times(text: str) -> list[datetime]:
    times: list[datetime] = []
    for line in text.splitlines():
        if RESET_MARKER not in line:
            continue
        ts = _parse_ts(line)
        if ts is not None:
            times.append(ts)
    return times


def read_tail(path: Path | str, tail_bytes: int = DEFAULT_TAIL_BYTES) -> str:
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - tail_bytes))
        return f.read().decode("utf-8", errors="replace")


def count_recent_resets(
    path: Path | str,
    *,
    window_secs: float,
    now: datetime | None = None,
    tail_bytes: int = DEFAULT_TAIL_BYTES,
) -> int:
    try:
        text = read_tail(path, tail_bytes)
    except FileNotFoundError:
        return 0
    cutoff = (now or datetime.now()) - timedelta(seconds=window_secs)
    return sum(1 for ts in reset_times(text) if ts >= cutoff)
