"""Run one or more experiments and write a top-level execution manifest."""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from experiments.E0_consistency_interoperability import experiment as e0
from experiments.E1_evidence_integrity import experiment as e1
from experiments.E2_attributability import experiment as e2
from experiments.E3_acceptance_soundness import experiment as e3
from experiments.E4_third_party_determinism import experiment as e4
from experiments.E5_availability_liveness import experiment as e5
from experiments.E6_performance_scale import experiment as e6
from experiments.E7_formal_verification import experiment as e7
from experiments.E8_payload_privacy import experiment as e8

EXPERIMENTS = {
    "E0": e0,
    "E1": e1,
    "E2": e2,
    "E3": e3,
    "E4": e4,
    "E5": e5,
    "E6": e6,
    "E7": e7,
    "E8": e8,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--profile",
        choices=["smoke", "standard", "full"],
        default="standard",
        help="sample-size profile; E0 and E7 always use their fixed protocols",
    )
    parser.add_argument(
        "--experiments",
        nargs="*",
        choices=sorted(EXPERIMENTS),
        default=sorted(EXPERIMENTS),
    )
    args = parser.parse_args()

    manifest: dict[str, object] = {
        "started_at": datetime.now(UTC).isoformat(),
        "profile": args.profile,
        "experiments": {},
    }
    failed = False
    for name in args.experiments:
        started = time.perf_counter()
        try:
            module = EXPERIMENTS[name]
            if name in {"E0", "E7"}:
                result = module.run()
            else:
                result = module.run(profile=args.profile)
            manifest["experiments"][name] = {
                "status": "completed",
                "elapsed_seconds": time.perf_counter() - started,
                "result": result,
            }
        except Exception as error:  # pragma: no cover - failure is preserved in the artifact
            failed = True
            manifest["experiments"][name] = {
                "status": "failed",
                "elapsed_seconds": time.perf_counter() - started,
                "error_type": type(error).__name__,
                "error": str(error),
            }
    manifest["finished_at"] = datetime.now(UTC).isoformat()
    output = ROOT / "results" / f"run_{args.profile}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(output)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
