from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from eba.canonical import dumps
from eba.crypto import Identity, IdentityResolver
from eba.merkle import inclusion_proof, merkle_root, verify_inclusion
from eba.protocol import (
    ACCEPT,
    UNCONFIRMED,
    AlertVerifier,
    create_session,
    issue_alert,
    make_bundle,
    proof_for_event,
)
from eba.rules import RuleRegistry


class CanonicalizationTests(unittest.TestCase):
    def test_key_order_and_literals(self) -> None:
        self.assertEqual(dumps({"b": 2, "a": 1}), '{"a":1,"b":2}')
        self.assertEqual(dumps([None, True, False]), "[null,true,false]")

    def test_merkle_round_trip(self) -> None:
        messages = [bytes.fromhex(f"{index:064x}") for index in range(9)]
        root = merkle_root(messages)
        for index, message in enumerate(messages):
            self.assertTrue(verify_inclusion(message, inclusion_proof(messages, index), root))


class ProtocolTests(unittest.TestCase):
    def test_valid_alert_and_missing_evidence(self) -> None:
        resolver = IdentityResolver()
        a = Identity.generate("a")
        b = Identity.generate("b")
        session = create_session(a, b, resolver, t_start=100, t_end=1_000)
        event = session.emit(
            "a",
            "b",
            ts=110,
            intent_meta={"target": "outside-allowlist"},
            perm_scope={"requested": ["pay"], "granted": ["read", "pay"]},
            payload=b"payload",
        )
        root, proof, _ = proof_for_event(session, "a", "a->b", 1, 1, 1)
        alert = issue_alert(
            accuser=b,
            session=session,
            event=event,
            root_attestation=root,
            proof=proof,
            rule_id="ALLOW-1",
            rule_version="v1",
            ts=111,
        )
        verifier = AlertVerifier(resolver, RuleRegistry())
        verifier.add_anchor(session.anchor)
        self.assertEqual(
            verifier.verify_alert(
                alert,
                now=111,
                providers=[make_bundle(session, event, root, proof)],
            ).decision,
            ACCEPT,
        )
        self.assertEqual(verifier.verify_alert(alert, now=111).decision, UNCONFIRMED)


if __name__ == "__main__":
    unittest.main()
