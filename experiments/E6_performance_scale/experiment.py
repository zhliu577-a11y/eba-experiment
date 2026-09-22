"""E6: microbenchmarks, end-to-end overhead, local scale, and wire costs."""

from __future__ import annotations

import copy
import json
import random
import time
from collections import Counter

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eba.canonical import canonical_bytes
from eba.crypto import (
    Identity,
    IdentityResolver,
    sha256,
    sign_object,
    verify_object,
)
from eba.merkle import inclusion_proof, merkle_root, verify_inclusion
from eba.metrics import summary
from eba.protocol import (
    ACCEPT,
    AlertStore,
    AlertVerifier,
    create_session,
    event_hash,
    issue_alert,
    make_bundle,
    proof_for_event,
    publish_root,
    verify_anchor,
)
from eba.rules import RuleRegistry
from eba.workloads import WorkloadEvent, benign_event, violating_event

from experiments.common import profile_value, write_result

EXPERIMENT_DIR = "E6_performance_scale"


def _measure(operation, iterations: int, warmup: int = 100) -> dict[str, object]:
    for index in range(warmup):
        operation(index)
    wall_latencies: list[float] = []
    cpu_total = 0.0
    start_all = time.perf_counter()
    for index in range(iterations):
        cpu_start = time.process_time()
        start = time.perf_counter()
        operation(index)
        wall_latencies.append(time.perf_counter() - start)
        cpu_total += time.process_time() - cpu_start
    elapsed = time.perf_counter() - start_all
    report = summary(wall_latencies)
    report.update(
        {
            "iterations": iterations,
            "latency_ms": {
                "mean": report["mean"] * 1000,
                "p50": report["p50"] * 1000,
                "p95": report["p95"] * 1000,
                "p99": report["p99"] * 1000,
            },
            "cpu_seconds_per_operation": cpu_total / iterations,
            "operations_per_second": iterations / elapsed,
        }
    )
    return report


def _microbenchmarks(micro_iterations: int):
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(a, b, resolver, t_start=0, t_end=1_000_000, sid_nonce=b"bench")
    sample_event = session.emit(
        "a",
        "b",
        ts=10,
        intent_meta={
            "target": "outside-allowlist",
            "amount": 100,
            "delegation_depth": 1,
            "calls_in_window": 1,
            "content_policy_ok": True,
        },
        perm_scope={"requested": ["pay"], "granted": ["read", "pay"]},
        payload=b"x" * 256,
    )
    root, proof, events = proof_for_event(session, "a", "a->b", 1, 1, 1)
    bundle = make_bundle(session, sample_event, root, proof)
    unsigned_event = {key: value for key, value in sample_event.items() if key != "sig"}
    canonical_event = canonical_bytes(unsigned_event)
    leaf_inputs = [bytes.fromhex(event_hash(sample_event)) for _ in range(64)]
    tree_256 = [sha256(f"{index}".encode()) for index in range(256)]
    proof_256 = inclusion_proof(tree_256, 173)
    root_256 = merkle_root(tree_256)
    registry = RuleRegistry()
    benchmarks = {
        "tee_session_key_generation": _measure(
            lambda _: Ed25519PrivateKey.generate(), micro_iterations
        ),
        "jcs_canonicalization": _measure(
            lambda _: canonical_bytes(unsigned_event), micro_iterations
        ),
        "sha256_message_hash": _measure(lambda _: sha256(canonical_event), micro_iterations),
        "audit_event_construction_sign": _measure(
            lambda index: a.private_key.sign(
                canonical_bytes(
                    {
                        **unsigned_event,
                        "seq": index + 2,
                        "ts": 10 + index,
                    }
                )
            ),
            micro_iterations,
        ),
        "audit_event_verification": _measure(
            lambda _: verify_object(session.session_public["a"], sample_event),
            micro_iterations,
        ),
        "merkle_leaf_hash": _measure(
            lambda index: sha256(b"\x00" + leaf_inputs[index % len(leaf_inputs)]),
            micro_iterations,
        ),
        "merkle_internal_hash": _measure(
            lambda index: sha256(
                b"\x01" + leaf_inputs[index % len(leaf_inputs)] + leaf_inputs[(index + 1) % 64]
            ),
            micro_iterations,
        ),
        "merkle_root_64_leaves": _measure(
            lambda _: merkle_root(leaf_inputs), micro_iterations
        ),
        "inclusion_proof_generation_256": _measure(
            lambda index: inclusion_proof(tree_256, index % len(tree_256)),
            micro_iterations,
        ),
        "inclusion_proof_verification_256": _measure(
            lambda _: verify_inclusion(
                tree_256[173],
                proof_256,
                root_256,
            ),
            micro_iterations,
        ),
        "anchor_verification": _measure(
            lambda _: verify_anchor(session.anchor, resolver),
            micro_iterations,
        ),
        "evidence_retrieval_json_roundtrip": _measure(
            lambda _: json.loads(json.dumps(bundle)), micro_iterations
        ),
        "rule_re_evaluation": _measure(
            lambda _: registry.evaluate("ALLOW-1", "v1", sample_event),
            micro_iterations,
        ),
        "single_signature_verification": _measure(
            lambda _: verify_object(session.session_public["a"], sample_event),
            micro_iterations,
        ),
    }
    _ = events
    return benchmarks


def _event_from_workload(
    session,
    sender: str,
    receiver: str,
    workload: WorkloadEvent,
    ts: int,
) -> dict[str, object]:
    return session.emit(
        sender,
        receiver,
        ts=ts,
        intent_meta=workload.intent_meta(),
        perm_scope=workload.perm_scope(),
        payload=workload.payload,
    )


def _end_to_end(interactions: int, flood_alerts: int):
    rng = random.Random(20260922)
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(a, b, resolver, t_start=0, t_end=10_000_000, sid_nonce=b"e2e")

    w1_event_latencies: list[float] = []
    w1_verify_latencies: list[float] = []
    for index in range(interactions):
        workload = benign_event(rng)
        start = time.perf_counter()
        event = _event_from_workload(session, "a", "b", workload, index + 10)
        w1_event_latencies.append(time.perf_counter() - start)
        start = time.perf_counter()
        verify_object(session.session_public["a"], event)
        w1_verify_latencies.append(time.perf_counter() - start)

    w2: dict[str, object] = {}
    for violation_rate in (0.25, 0.5, 1.0):
        rates = random.Random(f"w2-{violation_rate}")
        local_session = create_session(
            a,
            b,
            resolver,
            t_start=0,
            t_end=10_000_000,
            sid_nonce=f"w2-{violation_rate}".encode(),
        )
        event_latencies: list[float] = []
        alerts = 0
        for index in range(interactions):
            violation = rates.random() < violation_rate
            workload = violating_event(rates) if violation else benign_event(rates)
            start = time.perf_counter()
            _event_from_workload(local_session, "a", "b", workload, index + 10)
            event_latencies.append(time.perf_counter() - start)
            alerts += int(workload.is_violation)
        w2[str(violation_rate)] = {
            "interactions": interactions,
            "measured_alerts": alerts,
            "evidence_generation_latency": {
                "mean_ms": summary(event_latencies)["mean"] * 1000,
                "p95_ms": summary(event_latencies)["p95"] * 1000,
                "p99_ms": summary(event_latencies)["p99"] * 1000,
            },
        }

    flood_event = _event_from_workload(
        session,
        "a",
        "b",
        violating_event(rng),
        20,
    )
    flood_root, flood_proof, _ = proof_for_event(
        session,
        "a",
        "a->b",
        int(flood_event["seq"]),
        int(flood_event["seq"]),
        int(flood_event["seq"]),
    )
    flood_bundle = make_bundle(session, flood_event, flood_root, flood_proof)
    verifier = AlertVerifier(resolver, RuleRegistry())
    verifier.add_anchor(session.anchor)
    verifier.add_root(flood_root)
    flood_report: dict[str, object] = {}
    for fraction in (0.1, 0.5, 0.9, 1.0):
        invalid_target = round(flood_alerts * fraction)
        valid_target = flood_alerts - invalid_target
        store = AlertStore()
        accepted_invalid = 0
        accepted_valid = 0
        duplicates = 0
        previous_invalid: dict[str, object] | None = None
        start = time.perf_counter()
        cpu_start = time.process_time()
        for index in range(flood_alerts):
            accuser = a if index % 2 == 0 else b
            alert = issue_alert(
                accuser=accuser,
                session=session,
                event=flood_event,
                root_attestation=flood_root,
                proof=flood_proof,
                rule_id="ALLOW-1",
                rule_version="v1",
                ts=21,
            )
            if index < invalid_target:
                duplicate_requested = index > 0 and index % 10 == 0 and previous_invalid is not None
                if duplicate_requested:
                    alert = copy.deepcopy(previous_invalid)
                else:
                    alert["copy_hash"] = f"{index + 1:032x}" * 2
                    alert["sig"] = sign_object(accuser.private_key, alert)
                    previous_invalid = copy.deepcopy(alert)
                verdict = verifier.verify_alert(alert, now=21, providers=[flood_bundle])
                accepted_invalid += verdict.decision == ACCEPT
            else:
                verdict = verifier.verify_alert(alert, now=21, providers=[flood_bundle])
                accepted_valid += verdict.decision == ACCEPT
            _, duplicate = store.record(alert, verdict)
            duplicates += duplicate
        wall = time.perf_counter() - start
        cpu = time.process_time() - cpu_start
        flood_report[str(fraction)] = {
            "attempted": flood_alerts,
            "invalid_attempts": invalid_target,
            "valid_controls": valid_target,
            "accepted_invalid": accepted_invalid,
            "accepted_valid": accepted_valid,
            "duplicate_alerts": duplicates,
            "wall_seconds": wall,
            "cpu_seconds": cpu,
            "alerts_per_second": flood_alerts / wall,
            "cost_per_attempt_us": wall / flood_alerts * 1e6,
        }

    return {
        "W1": {
            "interactions": interactions,
            "evidence_generation_latency": {
                "mean_ms": summary(w1_event_latencies)["mean"] * 1000,
                "p50_ms": summary(w1_event_latencies)["p50"] * 1000,
                "p95_ms": summary(w1_event_latencies)["p95"] * 1000,
                "p99_ms": summary(w1_event_latencies)["p99"] * 1000,
            },
            "event_verification_latency": {
                "mean_ms": summary(w1_verify_latencies)["mean"] * 1000,
                "p95_ms": summary(w1_verify_latencies)["p95"] * 1000,
                "p99_ms": summary(w1_verify_latencies)["p99"] * 1000,
            },
        },
        "W2": w2,
        "W3": flood_report,
    }


def _third_party_path(iterations: int) -> dict[str, object]:
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(
        a,
        b,
        resolver,
        t_start=0,
        t_end=100_000,
        sid_nonce=b"third-party-path",
    )
    event = session.emit(
        "a",
        "b",
        ts=10,
        intent_meta={"target": "outside-allowlist", "amount": 100},
        perm_scope={"requested": ["pay"], "granted": ["read", "pay"]},
        payload=b"x" * 256,
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
        ts=11,
    )
    bundle = make_bundle(session, event, root, proof)
    verifier = AlertVerifier(resolver, RuleRegistry())
    verifier.add_anchor(session.anchor)
    verifier.add_root(root)
    verdict = verifier.verify_alert(alert, now=11, providers=[bundle])
    report = _measure(
        lambda _: verifier.verify_alert(alert, now=11, providers=[bundle]),
        iterations,
    )
    report.update(
        {
            "path": (
                "anchor verification, direct-provider bundle retrieval, proof "
                "verification, signature verification, and rule re-evaluation"
            ),
            "decision": verdict.decision,
            "reason": verdict.reason,
            "network_included": False,
            "participant_local_state_used": False,
        }
    )
    return report


def _wire_and_root_publication():
    resolver = IdentityResolver()
    a = Identity.generate("a")
    b = Identity.generate("b")
    session = create_session(a, b, resolver, t_start=0, t_end=100_000, sid_nonce=b"bytes")
    event = session.emit(
        "a",
        "b",
        ts=10,
        intent_meta={"target": "outside-allowlist", "amount": 100},
        perm_scope={"requested": ["pay"], "granted": ["read", "pay"]},
        payload=b"x" * 256,
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
        ts=11,
    )
    bundle = make_bundle(session, event, root, proof)
    root_events = []
    root_report: dict[str, object] = {}
    for interval in (1, 10, 100, 1000):
        local = create_session(
            a,
            b,
            resolver,
            t_start=0,
            t_end=100_000,
            sid_nonce=f"root-{interval}".encode(),
        )
        for index in range(1, max(interval, 1000) + 1):
            local.emit(
                "a",
                "b",
                ts=index + 10,
                intent_meta={"target": "vendor-trusted"},
                perm_scope={"requested": ["read"], "granted": ["read"]},
                payload=b"x",
            )
        start = time.perf_counter()
        attestation, _, _ = publish_root(local, "a", "a->b", 1, interval)
        elapsed = time.perf_counter() - start
        root_bytes = len(canonical_bytes(attestation))
        root_report[str(interval)] = {
            "root_publication_seconds": elapsed,
            "root_bytes": root_bytes,
            "amortized_bytes_per_event": root_bytes / interval,
        }
        root_events.append((interval, elapsed))
    _ = root_events
    return {
        "audit_event_bytes": len(canonical_bytes(event)),
        "revoke_advice_bytes": len(canonical_bytes(alert)),
        "root_attestation_bytes": len(canonical_bytes(root)),
        "inclusion_proof_bytes": len(canonical_bytes(proof.as_dict())),
        "bundle_bytes": len(canonical_bytes(bundle)),
        "root_publication": root_report,
    }


def run(profile: str = "standard") -> dict[str, object]:
    micro_iterations = profile_value(profile, smoke=1_000, standard=10_000, full=100_000)
    interactions = profile_value(profile, smoke=100, standard=1_000, full=10_000)
    flood_alerts = profile_value(profile, smoke=1_000, standard=10_000, full=100_000)
    micro = _microbenchmarks(micro_iterations)
    end_to_end = _end_to_end(interactions, flood_alerts)
    third_party_path = _third_party_path(interactions)
    wire = _wire_and_root_publication()
    result = {
        "profile": profile,
        "micro_iterations": micro_iterations,
        "interactions_per_condition": interactions,
        "flood_alerts_per_fraction": flood_alerts,
        "microbenchmarks": micro,
        "end_to_end": end_to_end,
        "third_party_path": third_party_path,
        "wire_and_root_publication": wire,
        "warmup_policy": "100 operations before each microbenchmark",
        "measurement_boundaries": "Python perf_counter wall time and process_time CPU time",
    }
    write_result(
        EXPERIMENT_DIR,
        result,
        title="E6 Performance, Scale, and Overhead",
        summary_lines=[
            f"Microbenchmark iterations: {micro_iterations}",
            f"Interactions per workload condition: {interactions}",
            f"Alert-flood attempts per Sybil fraction: {flood_alerts}",
            f"Third-party path mean latency: {third_party_path['latency_ms']['mean']:.3f} ms",
        ],
    )
    return result
