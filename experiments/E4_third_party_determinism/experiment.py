"""E4: participant and separate-process third-party verdict determinism."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from eba.crypto import Identity, IdentityResolver, hash_object, sign_object
from eba.protocol import (
    ACCEPT,
    REJECT,
    UNCONFIRMED,
    AlertVerifier,
    create_session,
    event_hash,
    issue_alert,
    make_bundle,
    proof_for_event,
)
from eba.rules import RuleRegistry

from experiments.common import profile_value, write_result

EXPERIMENT_DIR = "E4_third_party_determinism"


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
        sid_nonce=f"determinism-{index}".encode(),
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
        ts=111,
    )
    bundle = make_bundle(session, event, root, proof)
    participant = AlertVerifier(resolver, RuleRegistry())
    participant.add_anchor(session.anchor)
    participant.add_root(root)
    return resolver, b, session, event, root, proof, alert, bundle, participant


def _observer_subprocess(payload: dict[str, object]) -> dict[str, object]:
    script = Path(__file__).with_name("observer_subprocess.py")
    completed = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


def _scenario(case: str, index: int):
    resolver, b, session, event, root, proof, alert, bundle, participant = _fixture(index)
    provider_alerts = [bundle]
    local_bundle = bundle
    alert_to_use = alert
    roots = [root]
    now = 111
    if case == "complete_evidence":
        pass
    elif case == "missing_evidence":
        provider_alerts = []
        local_bundle = None
    elif case == "incorrect_evidence":
        wrong = copy.deepcopy(bundle)
        wrong["event"]["sig"] = "00" * 64
        provider_alerts = [wrong]
        local_bundle = None
    elif case == "deterministic_mismatch":
        alert_to_use = copy.deepcopy(alert)
        alert_to_use["copy_hash"] = f"{index:064x}"
        alert_to_use["sig"] = sign_object(b.private_key, alert_to_use)
    elif case == "forged_anchor":
        forged_anchor = copy.deepcopy(session.anchor)
        forged_anchor["sig_a"] = "00" * 64
        forged_anchor_ref = hash_object(forged_anchor)
        alert_to_use = copy.deepcopy(alert)
        alert_to_use["anchor_ref"] = forged_anchor_ref
        alert_to_use["sig"] = sign_object(b.private_key, alert_to_use)
        participant.anchors = {forged_anchor_ref: forged_anchor}
        roots = []
    else:
        raise ValueError(f"unknown E4 scenario: {case}")

    participant_verdict = participant.verify_alert(
        alert_to_use,
        now=now,
        providers=provider_alerts,
        local_bundle=local_bundle,
    )
    if case == "forged_anchor":
        anchor_payload = participant.anchors[next(iter(participant.anchors))]
    else:
        anchor_payload = session.anchor
    observer = _observer_subprocess(
        {
            "bindings": resolver.snapshot(),
            "anchor": anchor_payload,
            "roots": roots,
            "alert": alert_to_use,
            "providers": provider_alerts if case != "forged_anchor" else [],
            "ttl": 3600,
            "clock_skew": 2,
            "now": now,
            "retired_rules": [],
        }
    )
    return participant_verdict.as_dict(), observer


def run(profile: str = "standard") -> dict[str, object]:
    trials = profile_value(profile, smoke=3, standard=30, full=30)
    cases = [
        "complete_evidence",
        "missing_evidence",
        "incorrect_evidence",
        "deterministic_mismatch",
        "forged_anchor",
    ]
    report: dict[str, object] = {}
    all_agree = True
    for case in cases:
        agreements = 0
        participant_counts: dict[str, int] = {}
        observer_counts: dict[str, int] = {}
        for index in range(trials):
            participant, observer = _scenario(case, index)
            agrees = (
                participant["decision"] == observer["decision"]
                and participant["reason"] == observer["reason"]
            )
            agreements += agrees
            participant_key = f"{participant['decision']}:{participant['reason']}"
            observer_key = f"{observer['decision']}:{observer['reason']}"
            participant_counts[participant_key] = participant_counts.get(participant_key, 0) + 1
            observer_counts[observer_key] = observer_counts.get(observer_key, 0) + 1
        all_agree = all_agree and agreements == trials
        report[case] = {
            "trials": trials,
            "agreements": agreements,
            "agreement_rate": agreements / trials,
            "participant": participant_counts,
            "observer": observer_counts,
        }

    availability_safe = "ACCEPT" not in report["missing_evidence"]["observer"]
    result = {
        "profile": profile,
        "trials_per_scenario": trials,
        "scenarios": report,
        "all_verdicts_agree": all_agree,
        "unavailability_never_accepts": availability_safe,
        "observer_isolation": "new OS subprocess per scenario trial",
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E4 Third-Party Verdict Determinism",
        summary_lines=[
            f"Trials per scenario: {trials}",
            f"Participant/observer verdict agreement: {all_agree}",
            f"Unavailability never accepts: {availability_safe}",
            "The third-party verifier executes in a separate Python process.",
        ],
    )
    return result
