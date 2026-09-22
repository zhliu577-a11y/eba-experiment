"""E2: attributability, non-repudiation, and the shared-key negative model."""

from __future__ import annotations

import copy
from collections import Counter

from eba.crypto import Identity, IdentityResolver, sign_object, verify_object
from eba.protocol import (
    ACCEPT,
    AlertVerifier,
    create_session,
    event_hash,
    issue_alert,
    make_bundle,
    proof_for_event,
    verify_anchor,
)
from eba.rules import RuleRegistry

from experiments.common import profile_value, write_result

EXPERIMENT_DIR = "E2_attributability"


def _fixture(index: int):
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(
        a,
        b,
        resolver,
        t_start=100,
        t_end=10_000,
        sid_nonce=f"attribution-{index}".encode(),
    )
    event = session.emit(
        "a",
        "b",
        ts=110,
        intent_meta={
            "target": "outside-allowlist",
            "amount": 100,
            "delegation_depth": 1,
            "calls_in_window": 1,
            "content_policy_ok": True,
        },
        perm_scope={"requested": ["pay"], "granted": ["read", "pay"]},
        payload=b"attributable payload",
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
    return resolver, a, b, session, event, root, proof, alert, verifier


def _forged_peer_event(session, event):
    forged = copy.deepcopy(event)
    forged["sig"] = sign_object(session.session_private["b"], forged)
    return forged


def _weakened_shared_key_check(session, forged_event) -> bool:
    # Negative model N1: accept a sender signature under any participant key.
    return any(
        verify_object(session.session_public[name], forged_event) for name in ("a", "b")
    )


def run(profile: str = "standard") -> dict[str, object]:
    trials = profile_value(profile, smoke=10, standard=100, full=1_000)
    legitimate_ok = 0
    peer_forgery_rejected = 0
    key_substitution_rejected = 0
    shared_key_model_accepts = 0
    outcomes: Counter[str] = Counter()

    for index in range(trials):
        resolver, a, b, session, event, root, proof, alert, verifier = _fixture(index)
        genuine_verified = verify_object(session.session_public["a"], event)
        anchor_valid, _ = verify_anchor(session.anchor, resolver)
        from eba.crypto import public_hex

        attributed = (
            genuine_verified
            and anchor_valid
            and session.anchor["ik_a"] == a.public_hex
            and session.anchor["pk_a"] == public_hex(session.session_public["a"])
        )
        legitimate_ok += attributed

        forged = _forged_peer_event(session, event)
        forged_alert = copy.deepcopy(alert)
        forged_alert["copy_hash"] = event_hash(forged)
        forged_alert["sig"] = sign_object(b.private_key, forged_alert)
        verdict = verifier.verify_alert(
            forged_alert,
            now=111,
            providers=[make_bundle(session, forged, root, proof)],
        )
        peer_forgery_rejected += verdict.decision != ACCEPT
        outcomes[f"peer_forgery:{verdict.decision}:{verdict.reason}"] += 1
        shared_key_model_accepts += _weakened_shared_key_check(session, forged)

        replaced = copy.deepcopy(session.anchor)
        replaced["pk_a"] = session.anchor["pk_b"]
        replacement_valid, _ = verify_anchor(replaced, resolver)
        key_substitution_rejected += not replacement_valid

    result = {
        "profile": profile,
        "trials": trials,
        "legitimate_attributable": legitimate_ok,
        "legitimate_attribution_rate": legitimate_ok / trials,
        "peer_forgery_rejected": peer_forgery_rejected,
        "peer_forgery_rejection_rate": peer_forgery_rejected / trials,
        "key_substitution_rejected": key_substitution_rejected,
        "key_substitution_rejection_rate": key_substitution_rejected / trials,
        "n1_shared_key_forgery_accepts": shared_key_model_accepts,
        "n1_expected_failure_observed": shared_key_model_accepts == trials,
        "outcomes": dict(sorted(outcomes.items())),
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E2 Attributability and Non-Repudiation",
        summary_lines=[
            f"Trials: {trials}",
            f"Legitimate attribution rate: {legitimate_ok / trials:.4f}",
            f"Peer-forgery rejection rate: {peer_forgery_rejected / trials:.4f}",
            f"N1 shared-key counterexample observed: {shared_key_model_accepts == trials}",
        ],
    )
    return result
