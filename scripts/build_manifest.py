"""Build a SHA-256 manifest for the complete local experiment artifact."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.common import environment_record, file_digest, utc_now

INCLUDE_ROOTS = [
    ROOT / "src",
    ROOT / "experiments",
    ROOT / "tests",
    ROOT / "docs",
    ROOT / "scripts",
    ROOT / "results",
]
INCLUDE_FILES = [
    ROOT / "README.md",
    ROOT / "requirements.txt",
    ROOT / "pyproject.toml",
    ROOT / "Paper1_Revised_Full_EN (5).pdf",
]


def main() -> int:
    paths: set[Path] = set(INCLUDE_FILES)
    for root in INCLUDE_ROOTS:
        for path in root.rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                paths.add(path)
    files = {
        str(path.relative_to(ROOT)).replace("\\", "/"): file_digest(path)
        for path in sorted(paths)
    }
    manifest = {
        "created_at": utc_now(),
        "root": str(ROOT),
        "environment": environment_record(),
        "file_count": len(files),
        "files": files,
    }
    output = ROOT / "artifact_manifest.json"
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
