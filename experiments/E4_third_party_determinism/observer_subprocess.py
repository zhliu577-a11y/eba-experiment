"""Separate-process verifier used by E4."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from eba.crypto import IdentityResolver, public_key_from_hex  # noqa: E402
from eba.protocol import AlertVerifier  # noqa: E402
from eba.rules import RuleRegistry  # noqa: E402


def main() -> None:
    request = json.load(sys.stdin)
    resolver = IdentityResolver()
    for name, public_hex in request["bindings"].items():
        resolver.bind_public(name, public_key_from_hex(public_hex))
    registry = RuleRegistry()
    for rule_id, version in request.get("retired_rules", []):
        registry.retire(rule_id, version)
    verifier = AlertVerifier(
        resolver,
        registry,
        ttl=int(request["ttl"]),
        clock_skew=int(request["clock_skew"]),
    )
    verifier.add_anchor(request["anchor"])
    for root in request["roots"]:
        verifier.add_root(root)
    verdict = verifier.verify_alert(
        request["alert"],
        now=int(request["now"]),
        providers=request["providers"],
        local_bundle=None,
    )
    sys.stdout.write(json.dumps(verdict.as_dict(), sort_keys=True))


if __name__ == "__main__":
    main()
