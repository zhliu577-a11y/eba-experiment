"""Shared result and environment helpers for experiment modules."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def environment_record() -> dict[str, Any]:
    return {
        "captured_at": utc_now(),
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_result(
    experiment_dir: str,
    payload: dict[str, Any],
    *,
    title: str,
    summary_lines: list[str],
) -> Path:
    result_dir = ROOT / "experiments" / experiment_dir / "results" / "latest"
    result_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "experiment": experiment_dir,
        "title": title,
        "environment": environment_record(),
        **payload,
    }
    result_json = result_dir / "summary.json"
    result_json.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    markdown = [f"# {title}", "", f"- Generated: `{payload['environment']['captured_at']}`"]
    markdown.extend(f"- {line}" for line in summary_lines)
    markdown.extend(["", "Raw structured result: `summary.json`.", ""])
    (result_dir / "summary.md").write_text("\n".join(markdown), encoding="utf-8")
    return result_json


def profile_value(profile: str, *, smoke: int, standard: int, full: int) -> int:
    if profile == "smoke":
        return smoke
    if profile == "standard":
        return standard
    if profile == "full":
        return full
    raise ValueError(f"unknown profile: {profile}")
