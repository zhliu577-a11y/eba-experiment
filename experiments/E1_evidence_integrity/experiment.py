"""E1: evidence-integrity attacks against D5/D7."""

from __future__ import annotations

import copy
import random
from collections import Counter

from eba.crypto import Identity, IdentityResolver, sign_object
from eba.protocol import (
    ACCEPT,
    EQUIVOCATION_DETECTED,
    AlertVerifier,
    ChainAdmission,
    create_session,
    direction_name,
    event_hash,
    issue_alert,
    make_bundle,
    proof_for_event,
)
from eba.rules import RuleRegistry

from experiments.common import profile_value, write_result

EXPERIMENT_DIR = "E1_evidence_integrity"


def _fixture():
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(a, b, resolver, t_start=100, t_end=10_000)
    common = {
        "intent_meta": {
            "target": "outside-allowlist",
            "amount": 100,
            "delegation_depth": 1,
            "calls_in_window": 1,
            "content_policy_ok": True,
        },
        "perm_scope": {"requested": ["pay"], "granted": ["read", "pay"]},
        "payload": b"payload",
    }
    event_1 = session.emit("a", "b", ts=110, **common)
    event_2 = session.emit("a", "b", ts=111, **common)
    root, proof, _ = proof_for_event(session, "a", "a->b", 1, 2, 1)
    alert = issue_alert(
        accuser=b,
        session=session,
        event=event_1,
        root_attestation=root,
        proof=proof,
        rule_id="ALLOW-1",
        rule_version="v1",
        ts=112,
    )
    return resolver, a, b, session, event_1, event_2, root, proof, alert


def _reissue_alert_copy(alert: dict[str, object], event: dict[str, object], accuser: Identity):
    changed = copy.deepcopy(alert)
    changed["copy_hash"] = event_hash(event)
    changed["sig"] = sign_object(accuser.private_key, changed)
    return changed


def _run_case(kind: str, index: int) -> tuple[str, str]:
    resolver, a, b, session, event_1, event_2, root, proof, alert = _fixture()
    verifier = AlertVerifier(resolver, RuleRegistry())
    verifier.add_anchor(session.anchor)
    verifier.add_root(root)
    bundle = make_bundle(session, event_1, root, proof)

    if kind == "modification":
        changed_event = copy.deepcopy(event_1)
        field = ["sender", "seq", "ts", "payload_hash", "prev_hash"][index % 5]
        if field == "seq":
            changed_event[field] = int(changed_event[field]) + 100
        elif field == "ts":
            changed_event[field] = int(changed_event[field]) + 1
        else:
            changed_event[field] = "0" * 64 if field.endswith("hash") else "mallory"
        client_alert = _reissue_alert_copy(alert, changed_event, b)
        verifier.add_root(root)
        verdict = verifier.verify_alert(
            client_alert,
            now=112,
            providers=[make_bundle(session, changed_event, root, proof)],
        )
        return verdict.decision, verdict.reason

    if kind == "insertion":
        unsigned = copy.deepcopy(event_1)
        unsigned.pop("sig")
        changed_alert = _reissue_alert_copy(alert, unsigned, b)
        verdict = verifier.verify_alert(
            changed_alert,
            now=112,
            providers=[make_bundle(session, unsigned, root, proof)],
        )
        return verdict.decision, verdict.reason

    if kind == "reordering":
        reordered_bundle = make_bundle(session, event_2, root, proof)
        verdict = verifier.verify_alert(alert, now=112, providers=[reordered_bundle])
        return verdict.decision, verdict.reason

    if kind == "cross_direction_replay":
        changed = copy.deepcopy(event_1)
        changed["d"] = direction_name("b", "a")
        changed["sender"] = "b"
        changed["receiver"] = "a"
        changed_alert = _reissue_alert_copy(alert, changed, b)
        verdict = verifier.verify_alert(
            changed_alert,
            now=112,
            providers=[make_bundle(session, changed, root, proof)],
        )
        return verdict.decision, verdict.reason

    if kind == "cross_session_replay":
        other_session = create_session(
            a,
            b,
            resolver,
            t_start=100,
            t_end=10_000,
            sid_nonce=f"other-{index}".encode(),
        )
        other_event = other_session.emit(
            "a",
            "b",
            ts=110,
            intent_meta=event_1["intent_meta"],
            perm_scope=event_1["perm_scope"],
            payload=b"payload",
        )
        verifier.add_anchor(other_session.anchor)
        other_root, other_proof, _ = proof_for_event(other_session, "a", "a->b", 1, 1, 1)
        replayed_alert = issue_alert(
            accuser=b,
            session=session,
            event=other_event,
            root_attestation=root,
            proof=proof,
            rule_id="ALLOW-1",
            rule_version="v1",
            ts=112,
        )
        verdict = verifier.verify_alert(
            replayed_alert,
            now=112,
            providers=[make_bundle(session, other_event, root, proof)],
        )
        _ = (other_root, other_proof)
        return verdict.decision, verdict.reason

    if kind == "chain_head_rollback":
        admission = ChainAdmission(direction_name("a", "b"), str(session.anchor["h0_ab"]))
        public_key = session.session_public["a"]
        first = admission.admit(event_1, public_key, now=112)
        second = admission.admit(event_2, public_key, now=112)
        admission.head = str(session.anchor["h0_ab"])
        admission.seen.clear()
        replay = admission.admit(event_2, public_key, now=112)
        detected = first == "ADMITTED" and second == "ADMITTED" and replay != "ADMITTED"
        return ("UNCONFIRMED", "CHAIN_HEAD_ROLLBACK") if detected else ("ACCEPT", "MISSED")

    if kind == "conflicting_roots":
        conflicting = copy.deepcopy(root)
        conflicting["root"] = f"{(index + 1):064x}"
        conflicting["sig"] = sign_object(session.session_private["a"], conflicting)
        verifier.add_root(conflicting)
        verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    raise ValueError(f"unknown integrity case: {kind}")


def run(profile: str = "standard") -> dict[str, object]:
    trials = profile_value(profile, smoke=10, standard=100, full=1_000)
    cases = [
        "modification",
        "insertion",
        "reordering",
        "cross_direction_replay",
        "cross_session_replay",
        "chain_head_rollback",
        "conflicting_roots",
    ]
    results: dict[str, object] = {}
    for case in cases:
        decisions: Counter[str] = Counter()
        reasons: Counter[str] = Counter()
        accepted = 0
        for index in range(trials):
            decision, reason = _run_case(case, index)
            decisions[decision] += 1
            reasons[reason] += 1
            accepted += decision == ACCEPT
        results[case] = {
            "trials": trials,
            "detected": trials - accepted,
            "accepted_invalid": accepted,
            "detection_rate": (trials - accepted) / trials,
            "decisions": dict(sorted(decisions.items())),
            "reasons": dict(sorted(reasons.items())),
        }

    all_safe = all(item["accepted_invalid"] == 0 for item in results.values())
    conflict_reason_ok = (
        results["conflicting_roots"]["reasons"].get(EQUIVOCATION_DETECTED, 0) == trials
    )
    result = {
        "profile": profile,
        "trials_per_class": trials,
        "classes": results,
        "all_tampering_detected": all_safe,
        "conflicting_roots_always_typed": conflict_reason_ok,
        "seed_policy": "deterministic case index plus secure random session keys",
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E1 Evidence Integrity",
        summary_lines=[
            f"Trials per manipulation class: {trials}",
            f"Invalid accepted: {sum(item['accepted_invalid'] for item in results.values())}",
            f"All tampering detected: {all_safe}",
            f"Conflicting roots always typed: {conflict_reason_ok}",
        ],
    )
    return result
