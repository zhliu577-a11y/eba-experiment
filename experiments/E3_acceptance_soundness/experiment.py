"""E3: D9 acceptance soundness, typed failures, valid controls, and Sybil pressure."""

from __future__ import annotations

import copy
import random
from collections import Counter

from eba.crypto import Identity, IdentityResolver, sign_object
from eba.protocol import (
    ACCEPT,
    ACCUSER_SIG_INVALID,
    ANCHOR_INVALID,
    AlertStore,
    AlertVerifier,
    EQUIVOCATION_DETECTED,
    EVIDENCE_MISMATCH,
    EVIDENCE_UNAVAILABLE,
    PROOF_UNAVAILABLE,
    REJECT,
    RETRACTION_INVALID,
    RULE_NOT_VIOLATED,
    RULE_UNKNOWN,
    STALE_ALERT,
    TIME_WINDOW_INVALID,
    UNCONFIRMED,
    create_session,
    event_hash,
    issue_alert,
    issue_retraction,
    make_bundle,
    proof_for_event,
)
from eba.rules import RuleRegistry

from experiments.common import profile_value, write_result

EXPERIMENT_DIR = "E3_acceptance_soundness"


def _fixture(index: int = 0, ttl: int = 3600):
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(
        a,
        b,
        resolver,
        t_start=100,
        t_end=10_000,
        sid_nonce=f"soundness-{index}".encode(),
    )
    violating = session.emit(
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
        payload=b"payload",
    )
    allowed = session.emit(
        "a",
        "b",
        ts=111,
        intent_meta={
            "target": "vendor-trusted",
            "amount": 100,
            "delegation_depth": 1,
            "calls_in_window": 1,
            "content_policy_ok": True,
        },
        perm_scope={"requested": ["read"], "granted": ["read", "pay"]},
        payload=b"payload",
    )
    root, proof, _ = proof_for_event(session, "a", "a->b", 1, 2, 1)
    second_proof = None
    root2, second_proof, _ = proof_for_event(session, "a", "a->b", 1, 2, 2)
    alert = issue_alert(
        accuser=b,
        session=session,
        event=violating,
        root_attestation=root,
        proof=proof,
        rule_id="ALLOW-1",
        rule_version="v1",
        ts=112,
    )
    registry = RuleRegistry()
    verifier = AlertVerifier(resolver, registry, ttl=ttl)
    verifier.add_anchor(session.anchor)
    verifier.add_root(root)
    bundle = make_bundle(session, violating, root, proof)
    return {
        "resolver": resolver,
        "a": a,
        "b": b,
        "session": session,
        "violating": violating,
        "allowed": allowed,
        "root": root,
        "root2": root2,
        "proof": proof,
        "second_proof": second_proof,
        "alert": alert,
        "registry": registry,
        "verifier": verifier,
        "bundle": bundle,
    }


def _sign_alert_with_b(data: dict[str, object]) -> dict[str, object]:
    changed = copy.deepcopy(data["alert"])
    changed["sig"] = sign_object(data["b"].private_key, changed)
    return changed


def _run_attack(case: str, index: int) -> tuple[str, str]:
    data = _fixture(index, ttl=60)
    verifier = data["verifier"]
    alert = data["alert"]
    bundle = data["bundle"]
    session = data["session"]
    b = data["b"]
    a = data["a"]

    if case == "valid_control":
        verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "forged_anchor":
        forged_anchor = copy.deepcopy(session.anchor)
        forged_anchor["sig_a"] = "00" * 64
        forged_ref = verifier.add_anchor(forged_anchor)
        changed = copy.deepcopy(alert)
        changed["anchor_ref"] = forged_ref
        changed["sig"] = sign_object(b.private_key, changed)
        verdict = verifier.verify_alert(changed, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "forged_evidence":
        forged_event = copy.deepcopy(data["violating"])
        forged_event["sig"] = "00" * 64
        changed = copy.deepcopy(alert)
        changed["copy_hash"] = event_hash(forged_event)
        changed["sig"] = sign_object(b.private_key, changed)
        verdict = verifier.verify_alert(
            changed,
            now=112,
            providers=[make_bundle(session, forged_event, data["root"], data["proof"])],
        )
        return verdict.decision, verdict.reason

    if case == "altered_copy":
        changed = copy.deepcopy(alert)
        changed["copy_hash"] = f"{index:064x}"
        changed["sig"] = sign_object(b.private_key, changed)
        verdict = verifier.verify_alert(changed, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "incorrect_proof":
        changed = copy.deepcopy(alert)
        changed["inclusion_proof"] = data["second_proof"].as_dict()
        changed["sig"] = sign_object(b.private_key, changed)
        verdict = verifier.verify_alert(changed, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "conflicting_roots":
        conflicting = copy.deepcopy(data["root"])
        conflicting["root"] = f"{index + 17:064x}"
        conflicting["sig"] = sign_object(session.session_private["a"], conflicting)
        verifier.add_root(conflicting)
        verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "forged_accuser":
        forged = copy.deepcopy(alert)
        forged["sig"] = sign_object(a.private_key, forged)
        verdict = verifier.verify_alert(forged, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "mislabeled_rule":
        allowed_alert = issue_alert(
            accuser=b,
            session=session,
            event=data["allowed"],
            root_attestation=data["root2"],
            proof=data["second_proof"],
            rule_id="ALLOW-1",
            rule_version="v1",
            ts=112,
        )
        verdict = verifier.verify_alert(
            allowed_alert,
            now=112,
            providers=[
                make_bundle(
                    session,
                    data["allowed"],
                    data["root2"],
                    data["second_proof"],
                )
            ],
        )
        return verdict.decision, verdict.reason

    if case == "missing_rule":
        verifier.rule_registry.retire("ALLOW-1", "v1")
        verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "expired_alert":
        verdict = verifier.verify_alert(alert, now=200, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "future_time":
        changed = copy.deepcopy(alert)
        changed["ts"] = 120
        changed["sig"] = sign_object(b.private_key, changed)
        verdict = verifier.verify_alert(changed, now=100, providers=[bundle])
        return verdict.decision, verdict.reason

    if case == "forged_retraction":
        verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
        store = AlertStore()
        store.record(alert, verdict)
        retraction = issue_retraction(b, alert, ts=113, reason="mistake")
        retraction["sig"] = sign_object(a.private_key, retraction)
        result = store.apply_retraction(retraction, data["resolver"])
        return result.decision, result.reason

    if case == "unavailable_evidence":
        verdict = verifier.verify_alert(alert, now=112, providers=[])
        return verdict.decision, verdict.reason

    raise ValueError(f"unknown E3 case: {case}")


def _sybil_pressure(profile: str) -> dict[str, object]:
    alerts_per_fraction = profile_value(profile, smoke=50, standard=200, full=1_000)
    fractions = [0.1, 0.5, 0.9, 1.0]
    data = _fixture(999)
    resolver = data["resolver"]
    session = data["session"]
    verifier = data["verifier"]
    bundle = data["bundle"]
    report: dict[str, object] = {}
    for fraction in fractions:
        invalid_target = round(alerts_per_fraction * fraction)
        valid_target = alerts_per_fraction - invalid_target
        accepted_invalid = 0
        accepted_valid = 0
        reasons: Counter[str] = Counter()
        for index in range(alerts_per_fraction):
            sybil = Identity.generate(f"sybil-{int(fraction * 100)}-{index}")
            resolver.bind(sybil)
            if index < invalid_target:
                alert = issue_alert(
                    accuser=sybil,
                    session=session,
                    event=data["violating"],
                    root_attestation=data["root"],
                    proof=data["proof"],
                    rule_id="ALLOW-1",
                    rule_version="v1",
                    ts=112,
                )
                alert["copy_hash"] = f"{index + 1:064x}"
                alert["sig"] = sign_object(sybil.private_key, alert)
                verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
                accepted_invalid += verdict.decision == ACCEPT
                reasons[f"invalid:{verdict.reason}"] += 1
            else:
                alert = issue_alert(
                    accuser=sybil,
                    session=session,
                    event=data["violating"],
                    root_attestation=data["root"],
                    proof=data["proof"],
                    rule_id="ALLOW-1",
                    rule_version="v1",
                    ts=112,
                )
                verdict = verifier.verify_alert(alert, now=112, providers=[bundle])
                accepted_valid += verdict.decision == ACCEPT
                reasons[f"valid:{verdict.reason}"] += 1
        report[str(fraction)] = {
            "alerts": alerts_per_fraction,
            "invalid_alerts": invalid_target,
            "valid_controls": valid_target,
            "accepted_invalid": accepted_invalid,
            "invalid_acceptance_rate": accepted_invalid / invalid_target if invalid_target else 0.0,
            "accepted_valid": accepted_valid,
            "valid_acceptance_rate": accepted_valid / valid_target if valid_target else 0.0,
            "reasons": dict(sorted(reasons.items())),
        }
    return report


def run(profile: str = "standard") -> dict[str, object]:
    trials = profile_value(profile, smoke=10, standard=100, full=1_000)
    expected = {
        "valid_control": (ACCEPT, ACCEPT),
        "forged_anchor": (REJECT, ANCHOR_INVALID),
        "forged_evidence": (UNCONFIRMED, EVIDENCE_UNAVAILABLE),
        "altered_copy": (REJECT, EVIDENCE_MISMATCH),
        "incorrect_proof": (UNCONFIRMED, PROOF_UNAVAILABLE),
        "conflicting_roots": (REJECT, EQUIVOCATION_DETECTED),
        "forged_accuser": (REJECT, ACCUSER_SIG_INVALID),
        "mislabeled_rule": (REJECT, RULE_NOT_VIOLATED),
        "missing_rule": (REJECT, RULE_UNKNOWN),
        "expired_alert": (REJECT, STALE_ALERT),
        "future_time": (REJECT, TIME_WINDOW_INVALID),
        "forged_retraction": (REJECT, RETRACTION_INVALID),
        "unavailable_evidence": (UNCONFIRMED, EVIDENCE_UNAVAILABLE),
    }
    cases: dict[str, object] = {}
    total_invalid_accepts = 0
    total_valid_accepts = 0
    for case, (expected_decision, expected_reason) in expected.items():
        outcomes: Counter[tuple[str, str]] = Counter()
        for index in range(trials):
            outcomes[_run_attack(case, index)] += 1
        expected_count = outcomes[(expected_decision, expected_reason)]
        if case == "valid_control":
            total_valid_accepts += expected_count
        else:
            total_invalid_accepts += outcomes[(ACCEPT, ACCEPT)]
        cases[case] = {
            "trials": trials,
            "expected": {
                "decision": expected_decision,
                "reason": expected_reason,
            },
            "expected_count": expected_count,
            "typed_reason_rate": expected_count / trials,
            "outcomes": {
                f"{decision}:{reason}": count
                for (decision, reason), count in sorted(outcomes.items())
            },
        }

    sybil = _sybil_pressure(profile)
    sybil_monotonicity = all(
        item["accepted_invalid"] == 0 for item in sybil.values()
    ) and all(item["accepted_valid"] == item["valid_controls"] for item in sybil.values())
    result = {
        "profile": profile,
        "trials_per_attack": trials,
        "cases": cases,
        "invalid_acceptances": total_invalid_accepts,
        "valid_control_acceptances": total_valid_accepts,
        "valid_control_expected": trials,
        "sybil_pressure": sybil,
        "sybil_pressure_passed": sybil_monotonicity,
        "seed_policy": "deterministic case index plus secure random keys",
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E3 Acceptance Soundness and Framing Resistance",
        summary_lines=[
            f"Trials per attack/failure class: {trials}",
            f"Invalid alerts accepted: {total_invalid_accepts}",
            f"Valid controls accepted: {total_valid_accepts}/{trials}",
            f"Sybil pressure passed: {sybil_monotonicity}",
        ],
    )
    return result
