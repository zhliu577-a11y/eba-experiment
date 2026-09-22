"""E5: evidence availability, retrieval deadlines, and conditional liveness."""

from __future__ import annotations

import copy
import math
import random

from eba.crypto import Identity, IdentityResolver, sign_object
from eba.protocol import (
    ACCEPT,
    REJECT,
    STALE_ALERT,
    UNCONFIRMED,
    AlertVerifier,
    create_session,
    issue_alert,
    make_bundle,
    proof_for_event,
)
from eba.rules import RuleRegistry

from experiments.common import profile_value, write_result

EXPERIMENT_DIR = "E5_availability_liveness"


def _fixture(index: int, ttl: int = 60):
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(
        a,
        b,
        resolver,
        t_start=100,
        t_end=10_000,
        sid_nonce=f"availability-{index}".encode(),
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
        ts=112,
    )
    verifier = AlertVerifier(resolver, RuleRegistry(), ttl=ttl)
    verifier.add_anchor(session.anchor)
    verifier.add_root(root)
    bundle = make_bundle(session, event, root, proof)
    return resolver, session, alert, verifier, bundle


def _independent_holders(profile: str) -> dict[str, object]:
    trials = profile_value(profile, smoke=100, standard=1_000, full=5_000)
    holder_counts = [1, 2, 5]
    response_probabilities = [1.0, 0.9, 0.5, 0.1]
    rng = random.Random(20260922)
    report: dict[str, object] = {}
    for holders in holder_counts:
        for alpha in response_probabilities:
            _, session, alert, verifier, bundle = _fixture(
                holders * 100 + int(alpha * 10)
            )
            invalid_alert = copy.deepcopy(alert)
            invalid_alert["copy_hash"] = "00" * 32
            invalid_alert["sig"] = sign_object(session.b.private_key, invalid_alert)
            successful = 0
            invalid_accepts = 0
            typed_failures = 0
            for _ in range(trials):
                responses = sum(rng.random() < alpha for _ in range(holders))
                providers = [bundle for _ in range(responses)]
                verdict = verifier.verify_alert(alert, now=112, providers=providers)
                successful += verdict.decision == ACCEPT
                invalid_verdict = verifier.verify_alert(
                    invalid_alert,
                    now=112,
                    providers=providers,
                )
                invalid_accepts += invalid_verdict.decision == ACCEPT
                typed_failures += verdict.reason in {"EVIDENCE_UNAVAILABLE", "STALE_ALERT"}
            empirical = successful / trials
            theoretical = 1 - (1 - alpha) ** holders
            error = abs(empirical - theoretical)
            tolerance = max(0.03, 4 * math.sqrt(max(theoretical * (1 - theoretical), 1e-9) / trials))
            report[f"k={holders},alpha={alpha}"] = {
                "holders": holders,
                "alpha": alpha,
                "trials": trials,
                "successes": successful,
                "empirical_success_rate": empirical,
                "theoretical_success_rate": theoretical,
                "absolute_error": error,
                "within_tolerance": error <= tolerance,
                "typed_failures": typed_failures,
                "invalid_accepts": invalid_accepts,
            }
    return report


def _failure_modes() -> dict[str, object]:
    _, session, alert, verifier, bundle = _fixture(7001)
    wrong = copy.deepcopy(bundle)
    wrong["event"]["sig"] = "00" * 64
    scenarios = {
        "all_holders_offline": verifier.verify_alert(alert, now=112, providers=[]),
        "malicious_provider_only": verifier.verify_alert(alert, now=112, providers=[wrong]),
        "one_bad_one_good_provider": verifier.verify_alert(
            alert, now=112, providers=[wrong, bundle]
        ),
        "retrieval_deadline_before_ttl": verifier.verify_alert(alert, now=170, providers=[]),
        "retrieval_deadline_after_ttl": verifier.verify_alert(alert, now=173, providers=[]),
        "available_before_ttl": verifier.verify_alert(alert, now=112, providers=[bundle]),
        "available_after_ttl": verifier.verify_alert(alert, now=173, providers=[bundle]),
    }
    report = {name: verdict.as_dict() for name, verdict in scenarios.items()}
    safe = all(
        verdict["decision"] != ACCEPT
        for name, verdict in report.items()
        if name not in {"one_bad_one_good_provider", "available_before_ttl"}
    )
    return {
        "scenarios": report,
        "unavailability_safe": safe,
        "bad_provider_does_not_override_good_provider": report[
            "one_bad_one_good_provider"
        ]["decision"]
        == ACCEPT,
        "after_ttl_is_stale": report["available_after_ttl"]["reason"] == STALE_ALERT,
    }


def run(profile: str = "standard") -> dict[str, object]:
    holders = _independent_holders(profile)
    failures = _failure_modes()
    result = {
        "profile": profile,
        "independent_holders": holders,
        "all_curves_within_tolerance": all(
            item["within_tolerance"] for item in holders.values()
        ),
        "curves_have_zero_invalid_accepts": all(
            item["invalid_accepts"] == 0 for item in holders.values()
        ),
        "failure_modes": failures,
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E5 Availability and Liveness",
        summary_lines=[
            f"Holder curves within tolerance: {result['all_curves_within_tolerance']}",
            f"Curves with zero invalid accepts: {result['curves_have_zero_invalid_accepts']}",
            f"Unavailability safety: {failures['unavailability_safe']}",
            f"After-TTL result is STALE_ALERT: {failures['after_ttl_is_stale']}",
        ],
    )
    return result
