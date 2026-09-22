"""E0: canonicalization, schema, boundary, and interop consistency."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eba.canonical import canonical_bytes, dumps
from eba.crypto import Identity, IdentityResolver, public_hex
from eba.protocol import (
    ACCEPT,
    ALERT_RETRACTED,
    REJECT,
    UNCONFIRMED,
    AlertStore,
    AlertVerifier,
    ChainAdmission,
    create_session,
    direction_name,
    event_hash,
    issue_alert,
    issue_retraction,
    make_bundle,
    proof_for_event,
    verify_anchor,
)
from eba.rules import RuleRegistry

from experiments.common import write_result

EXPERIMENT_DIR = "E0_consistency_interoperability"


def _valid_alert_fixture(now: int = 110):
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(a, b, resolver, t_start=100, t_end=1_000)
    event = session.emit(
        "a",
        "b",
        ts=now,
        intent_meta={
            "target": "outside-allowlist",
            "amount": 100,
            "delegation_depth": 1,
            "calls_in_window": 1,
            "content_policy_ok": True,
        },
        perm_scope={"requested": ["pay"], "granted": ["read", "pay"]},
        payload=b"private business payload",
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
        ts=now,
    )
    bundle = make_bundle(session, event, root, proof)
    registry = RuleRegistry()
    verifier = AlertVerifier(resolver, registry)
    verifier.add_anchor(session.anchor)
    return resolver, a, b, session, event, root, alert, bundle, registry, verifier


def run() -> dict[str, object]:
    checks: list[dict[str, object]] = []

    vectors = [
        {"b": 2, "a": 1},
        [None, True, False],
        {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": "€$\u000f\nA'B\"\\\"/",
            "literals": [None, True, False],
        },
    ]
    python_vectors = [dumps(vector) for vector in vectors]
    node_script = Path(__file__).with_name("interop") / "node_verify.mjs"
    completed = subprocess.run(
        ["node", str(node_script)],
        input=json.dumps({"vectors": vectors}),
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    node_vectors = json.loads(completed.stdout)["vectors"]
    checks.append(
        {
            "name": "jcs_fixed_vectors_cross_language",
            "passed": python_vectors == node_vectors,
        }
    )

    resolver, _, b, session, event, _, alert, bundle, registry, verifier = _valid_alert_fixture()
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(canonical_bytes(event))
    signed_check = {
        "name": "ed25519_cross_language",
        "object": event,
        "signature": signature.hex(),
        "public_key": public_hex(private_key.public_key()),
    }
    completed = subprocess.run(
        ["node", str(node_script)],
        input=json.dumps({"signatures": [signed_check]}),
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )
    node_signature_valid = json.loads(completed.stdout)["signatures"][0]["valid"]
    checks.append({"name": "signature_interop", "passed": bool(node_signature_valid)})

    required_anchor = {
        "sid",
        "ik_a",
        "pk_a",
        "q_a",
        "ik_b",
        "pk_b",
        "q_b",
        "h0_ab",
        "h0_ba",
        "t_start",
        "t_end",
        "sig_a",
        "sig_b",
    }
    required_event = {
        "sid",
        "d",
        "seq",
        "ts",
        "sender",
        "receiver",
        "intent_meta",
        "perm_scope",
        "payload_hash",
        "prev_hash",
        "sig",
    }
    required_alert = {
        "accuser",
        "ts",
        "anchor_ref",
        "d",
        "seq",
        "rule_id",
        "rule_version",
        "result",
        "copy_hash",
        "root_ref",
        "inclusion_proof",
        "sig",
    }
    checks.append(
        {
            "name": "schema_required_fields",
            "passed": required_anchor.issubset(session.anchor)
            and required_event.issubset(event)
            and required_alert.issubset(alert),
        }
    )

    valid = verifier.verify_alert(alert, now=110, providers=[bundle])
    unknown_registry = RuleRegistry()
    unknown_registry.retire("ALLOW-1", "v1")
    unknown_verifier = AlertVerifier(resolver, unknown_registry)
    unknown_verifier.add_anchor(session.anchor)
    unknown = unknown_verifier.verify_alert(alert, now=110, providers=[bundle])
    checks.append(
        {
            "name": "verdict_and_reason_mapping",
            "passed": valid.decision == ACCEPT
            and unknown.decision == REJECT
            and unknown.reason == "RULE_UNKNOWN",
        }
    )

    store = AlertStore()
    fingerprint, first = store.record(alert, valid)
    duplicate_fingerprint, duplicate = store.record(alert, valid)
    checks.append(
        {
            "name": "duplicate_alert_deduplication",
            "passed": not first
            and duplicate
            and fingerprint == duplicate_fingerprint
            and len(store.records) == 1,
        }
    )

    order_session = create_session(
        session.a,
        session.b,
        resolver,
        t_start=100,
        t_end=1_000,
        sid_nonce=b"ordering",
    )
    e1 = order_session.emit(
        "a",
        "b",
        ts=120,
        intent_meta={"target": "vendor-trusted"},
        perm_scope={"requested": ["read"], "granted": ["read"]},
    )
    e2 = order_session.emit(
        "a",
        "b",
        ts=121,
        intent_meta={"target": "vendor-trusted"},
        perm_scope={"requested": ["read"], "granted": ["read"]},
    )
    admission = ChainAdmission(direction_name("a", "b"), str(order_session.anchor["h0_ab"]))
    public_key = order_session.session_public["a"]
    status_2 = admission.admit(e2, public_key, now=121)
    status_1 = admission.admit(e1, public_key, now=121)
    checks.append(
        {
            "name": "out_of_order_buffering",
            "passed": status_2 == "BUFFERED"
            and status_1 == "ADMITTED"
            and len(admission.admitted) == 2,
        }
    )

    second = create_session(
        session.a,
        session.b,
        resolver,
        t_start=200,
        t_end=2_000,
        sid_nonce=b"rotation",
    )
    checks.append(
        {
            "name": "session_rotation_separates_chains",
            "passed": second.sid != session.sid
            and second.anchor_ref != session.anchor_ref
            and second.heads[direction_name("a", "b")] != session.heads[direction_name("a", "b")],
        }
    )

    missing = verifier.verify_alert(alert, now=110, providers=[])
    checks.append(
        {
            "name": "garbage_collected_evidence_is_unconfirmed",
            "passed": missing.decision == UNCONFIRMED
            and missing.reason == "EVIDENCE_UNAVAILABLE",
        }
    )

    boundary_verifier = AlertVerifier(resolver, registry, ttl=60, clock_skew=2)
    boundary_verifier.add_anchor(session.anchor)
    before_window = boundary_verifier.verify_alert(alert, now=97, providers=[bundle])
    at_boundary = boundary_verifier.verify_alert(alert, now=108, providers=[bundle])
    checks.append(
        {
            "name": "clock_window_boundary",
            "passed": before_window.reason == "ANCHOR_EXPIRED"
            and at_boundary.decision == ACCEPT,
        }
    )

    retraction = issue_retraction(b, alert, ts=112, reason="operator corrected rule input")
    retracted = store.apply_retraction(retraction, resolver)
    record = store.records[fingerprint]
    checks.append(
        {
            "name": "retraction_preserves_original_decision",
            "passed": retracted.reason == ALERT_RETRACTED
            and record["state"] == ALERT_RETRACTED
            and record["verdict"]["decision"] == ACCEPT,
        }
    )

    passed = sum(1 for check in checks if check["passed"])
    result = {
        "profile": "fixed-vectors",
        "checks": checks,
        "passed": passed,
        "failed": len(checks) - passed,
        "jcs_python": python_vectors,
        "jcs_node": node_vectors,
        "verdict_matrix": {
            "valid": valid.as_dict(),
            "missing_evidence": missing.as_dict(),
            "unknown_rule": unknown.as_dict(),
        },
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E0 Consistency, Interoperability, and Boundary Conditions",
        summary_lines=[
            f"Checks passed: {passed}/{len(checks)}",
            "Cross-language JCS and Ed25519 checks use Python and Node.js.",
            "Missing evidence is UNCONFIRMED; unknown rule versions are REJECT(RULE_UNKNOWN).",
        ],
    )
    return result
