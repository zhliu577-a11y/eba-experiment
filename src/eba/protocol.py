"""Evidence-Backed Accusation protocol prototype (M1-M4)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonical_bytes
from .crypto import (
    Identity,
    IdentityResolver,
    b64decode_bytes,
    b64encode_bytes,
    hash_object,
    hex32,
    public_hex,
    sha256,
    sign_object,
    verify_object,
)
from .merkle import InclusionProof, inclusion_proof, merkle_root, verify_inclusion
from .rules import RuleRegistry

ACCEPT = "ACCEPT"
REJECT = "REJECT"
UNCONFIRMED = "UNCONFIRMED"

ANCHOR_UNRESOLVED = "ANCHOR_UNRESOLVED"
ANCHOR_INVALID = "ANCHOR_INVALID"
ANCHOR_EXPIRED = "ANCHOR_EXPIRED"
ROOT_UNAVAILABLE = "ROOT_UNAVAILABLE"
EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
EVIDENCE_INVALID = "EVIDENCE_INVALID"
EVIDENCE_MISMATCH = "EVIDENCE_MISMATCH"
PROOF_UNAVAILABLE = "PROOF_UNAVAILABLE"
PROOF_INVALID = "PROOF_INVALID"
EQUIVOCATION_DETECTED = "EQUIVOCATION_DETECTED"
ACCUSER_SIG_INVALID = "ACCUSER_SIG_INVALID"
RULE_NOT_VIOLATED = "RULE_NOT_VIOLATED"
RULE_UNKNOWN = "RULE_UNKNOWN"
TIME_WINDOW_INVALID = "TIME_WINDOW_INVALID"
STALE_ALERT = "STALE_ALERT"
RETRACTION_INVALID = "RETRACTION_INVALID"
ALERT_RETRACTED = "ALERT_RETRACTED"


@dataclass(frozen=True)
class VerificationResult:
    decision: str
    reason: str
    detail: str = ""
    candidate_failures: tuple[str, ...] = ()

    @property
    def accepted(self) -> bool:
        return self.decision == ACCEPT

    def as_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "detail": self.detail,
            "candidate_failures": list(self.candidate_failures),
        }


@dataclass
class ChainAdmission:
    """D5 receiver state with out-of-order buffering."""

    direction: str
    head: str
    seen: set[int] = field(default_factory=set)
    buffered: dict[int, dict[str, object]] = field(default_factory=dict)
    admitted: list[dict[str, object]] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    def admit(
        self,
        event: dict[str, object],
        public_key,
        now: int,
        clock_skew: int = 2,
    ) -> str:
        if event.get("d") != self.direction:
            self.rejected.append(("EVIDENCE_INVALID", "direction"))
            return "REJECTED"
        if not verify_object(public_key, event):
            self.rejected.append(("EVIDENCE_INVALID", "signature"))
            return "REJECTED"
        seq = int(event["seq"])
        if seq in self.seen:
            self.rejected.append(("EVIDENCE_INVALID", "replay"))
            return "REJECTED"
        if abs(now - int(event["ts"])) > clock_skew and not self.admitted:
            self.rejected.append(("TIME_WINDOW_INVALID", "clock_skew"))
            return "REJECTED"
        if event.get("prev_hash") != self.head:
            self.buffered[seq] = event
            return "BUFFERED"
        self._admit_linked(event)
        while True:
            next_seq = max(self.seen, default=0) + 1
            candidate = self.buffered.pop(next_seq, None)
            if candidate is None or candidate.get("prev_hash") != self.head:
                break
            self._admit_linked(candidate)
        return "ADMITTED"

    def _admit_linked(self, event: dict[str, object]) -> None:
        seq = int(event["seq"])
        self.seen.add(seq)
        self.admitted.append(event)
        self.head = event_hash(event)


@dataclass
class Session:
    sid: str
    a: Identity
    b: Identity
    anchor: dict[str, object]
    anchor_ref: str
    session_private: dict[str, Ed25519PrivateKey]
    session_public: dict[str, object]
    t_start: int
    t_end: int
    chains: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    heads: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        directions = (
            direction_name(self.a.name, self.b.name),
            direction_name(self.b.name, self.a.name),
        )
        for direction in directions:
            self.chains.setdefault(direction, [])
            self.heads.setdefault(direction, str(self.anchor[initial_head_field(direction)]))

    def emit(
        self,
        sender: str,
        receiver: str,
        *,
        ts: int,
        intent_meta: dict[str, object] | None = None,
        perm_scope: dict[str, object] | None = None,
        payload: bytes = b"",
        seq: int | None = None,
        prev_hash: str | None = None,
    ) -> dict[str, object]:
        direction = direction_name(sender, receiver)
        chain = self.chains[direction]
        sequence = int(seq if seq is not None else len(chain) + 1)
        event: dict[str, object] = {
            "sid": self.sid,
            "d": direction,
            "seq": sequence,
            "ts": ts,
            "sender": sender,
            "receiver": receiver,
            "intent_meta": intent_meta or {},
            "perm_scope": perm_scope or {"requested": [], "granted": []},
            "payload_hash": hex32(sha256(payload)),
            "prev_hash": prev_hash if prev_hash is not None else self.heads[direction],
        }
        event["sig"] = sign_object(self.session_private[sender], event)
        if prev_hash is None and sequence == len(chain) + 1:
            chain.append(event)
            self.heads[direction] = event_hash(event)
        return event


def direction_name(sender: str, receiver: str) -> str:
    return f"{sender}->{receiver}"


def initial_head_field(direction: str) -> str:
    sender, receiver = direction.split("->", 1)
    if sender == "a" and receiver == "b":
        return "h0_ab"
    if sender == "b" and receiver == "a":
        return "h0_ba"
    return f"h0_{sender}_{receiver}"


def event_hash(event: dict[str, object]) -> str:
    return hash_object(event)


def alert_hash(alert: dict[str, object]) -> str:
    return hash_object(alert)


def create_session(
    a: Identity,
    b: Identity,
    resolver: IdentityResolver,
    *,
    t_start: int,
    t_end: int,
    sid_nonce: bytes | None = None,
) -> Session:
    resolver.bind(a)
    resolver.bind(b)
    nonce = sid_nonce or os.urandom(32)
    sid = hex32(sha256(b"|".join([a.public_hex.encode(), b.public_hex.encode(), nonce])))
    private = {
        a.name: Ed25519PrivateKey.generate(),
        b.name: Ed25519PrivateKey.generate(),
    }
    public = {name: key.public_key() for name, key in private.items()}
    quote_a = _make_quote(a, public[a.name], sid, t_start, t_end)
    quote_b = _make_quote(b, public[b.name], sid, t_start, t_end)
    anchor: dict[str, object] = {
        "sid": sid,
        "ik_a": a.public_hex,
        "pk_a": public_hex(public[a.name]),
        "q_a": b64encode_bytes(canonical_bytes(quote_a)),
        "ik_b": b.public_hex,
        "pk_b": public_hex(public[b.name]),
        "q_b": b64encode_bytes(canonical_bytes(quote_b)),
        "h0_ab": hex32(os.urandom(32)),
        "h0_ba": hex32(os.urandom(32)),
        "t_start": t_start,
        "t_end": t_end,
    }
    unsigned = dict(anchor)
    anchor["sig_a"] = sign_object(a.private_key, unsigned)
    anchor["sig_b"] = sign_object(b.private_key, unsigned)
    return Session(
        sid=sid,
        a=a,
        b=b,
        anchor=anchor,
        anchor_ref=hash_object(anchor),
        session_private=private,
        session_public=public,
        t_start=t_start,
        t_end=t_end,
    )


def _make_quote(
    identity: Identity,
    session_public,
    sid: str,
    t_start: int,
    t_end: int,
) -> dict[str, object]:
    quote: dict[str, object] = {
        "agent": identity.name,
        "ik": identity.public_hex,
        "pk": public_hex(session_public),
        "sid": sid,
        "t_start": t_start,
        "t_end": t_end,
    }
    quote["sig"] = sign_object(identity.private_key, quote)
    return quote


def verify_anchor(
    anchor: dict[str, object],
    resolver: IdentityResolver,
) -> tuple[bool, str]:
    required = {
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
    if not required.issubset(anchor):
        return False, "missing_fields"
    key_a = resolver.resolve("a")
    key_b = resolver.resolve("b")
    if key_a is None or key_b is None:
        return False, "identity_unresolved"
    if public_hex(key_a) != anchor["ik_a"] or public_hex(key_b) != anchor["ik_b"]:
        return False, "identity_key_mismatch"
    unsigned = {key: value for key, value in anchor.items() if key not in {"sig_a", "sig_b"}}
    if not verify_object_with_field(key_a, anchor, unsigned, "sig_a"):
        return False, "anchor_signature_a"
    if not verify_object_with_field(key_b, anchor, unsigned, "sig_b"):
        return False, "anchor_signature_b"
    for name, quote_field, public_field in (
        ("a", "q_a", "pk_a"),
        ("b", "q_b", "pk_b"),
    ):
        try:
            quote = _parse_quote(str(anchor[quote_field]))
        except (ValueError, TypeError):
            return False, f"quote_{name}_shape"
        quote_key = resolver.resolve(name)
        if quote_key is None or not verify_object(quote_key, quote):
            return False, f"quote_{name}_signature"
        if (
            quote.get("agent") != name
            or quote.get("sid") != anchor["sid"]
            or quote.get("pk") != anchor[public_field]
            or quote.get("t_start") != anchor["t_start"]
            or quote.get("t_end") != anchor["t_end"]
        ):
            return False, f"quote_{name}_binding"
    return True, "ok"


def verify_object_with_field(
    public_key,
    signed_object: dict[str, object],
    unsigned: dict[str, object],
    signature_field: str,
) -> bool:
    try:
        public_key.verify(
            bytes.fromhex(str(signed_object[signature_field])),
            canonical_bytes(unsigned),
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def _parse_quote(value: str) -> dict[str, object]:
    parsed = json.loads(b64decode_bytes(value).decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("quote must be an object")
    return parsed


def publish_root(
    session: Session,
    publisher: str,
    direction: str,
    start_seq: int,
    end_seq: int,
) -> tuple[dict[str, object], InclusionProof, list[dict[str, object]]]:
    events = [
        event for event in session.chains[direction] if start_seq <= int(event["seq"]) <= end_seq
    ]
    if not events:
        raise ValueError("root range has no events")
    hashes = [bytes.fromhex(event_hash(event)) for event in events]
    root = hex32(merkle_root(hashes))
    attestation: dict[str, object] = {
        "sid": session.sid,
        "d": direction,
        "start_seq": start_seq,
        "end_seq": end_seq,
        "tree_size": len(events),
        "root": root,
        "publisher": publisher,
    }
    attestation["sig"] = sign_object(session.session_private[publisher], attestation)
    proof = inclusion_proof(hashes, 0)
    return attestation, proof, events


def proof_for_event(
    session: Session,
    publisher: str,
    direction: str,
    start_seq: int,
    end_seq: int,
    seq: int,
) -> tuple[dict[str, object], InclusionProof, dict[str, object]]:
    attestation, _, events = publish_root(session, publisher, direction, start_seq, end_seq)
    hashes = [bytes.fromhex(event_hash(event)) for event in events]
    index = seq - start_seq
    event = next(event for event in events if int(event["seq"]) == seq)
    return attestation, inclusion_proof(hashes, index), event


def issue_alert(
    *,
    accuser: Identity,
    session: Session,
    event: dict[str, object],
    root_attestation: dict[str, object],
    proof: InclusionProof,
    rule_id: str,
    rule_version: str,
    ts: int,
    result: str = "violation",
) -> dict[str, object]:
    alert: dict[str, object] = {
        "accuser": accuser.name,
        "ts": ts,
        "anchor_ref": session.anchor_ref,
        "d": event["d"],
        "seq": event["seq"],
        "rule_id": rule_id,
        "rule_version": rule_version,
        "result": result,
        "copy_hash": event_hash(event),
        "root_ref": hash_object(root_attestation),
        "inclusion_proof": proof.as_dict(),
    }
    alert["sig"] = sign_object(accuser.private_key, alert)
    return alert


def make_bundle(
    session: Session,
    event: dict[str, object],
    root_attestation: dict[str, object],
    proof: InclusionProof,
) -> dict[str, object]:
    return {
        "anchor": session.anchor,
        "event": event,
        "root_attestation": root_attestation,
        "inclusion_proof": proof.as_dict(),
    }


def issue_retraction(
    accuser: Identity,
    alert: dict[str, object],
    *,
    ts: int,
    reason: str,
) -> dict[str, object]:
    retraction: dict[str, object] = {
        "retractor": accuser.name,
        "ts": ts,
        "target": {
            "accuser": alert["accuser"],
            "anchor_ref": alert["anchor_ref"],
            "d": alert["d"],
            "seq": alert["seq"],
            "rule_id": alert["rule_id"],
            "rule_version": alert["rule_version"],
            "copy_hash": alert["copy_hash"],
        },
        "reason": reason,
    }
    retraction["sig"] = sign_object(accuser.private_key, retraction)
    return retraction


class AlertStore:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, object]] = {}

    @staticmethod
    def fingerprint(alert: dict[str, object]) -> str:
        return hash_object(
            {
                "accuser": alert["accuser"],
                "anchor_ref": alert["anchor_ref"],
                "d": alert["d"],
                "seq": alert["seq"],
                "rule_id": alert["rule_id"],
                "rule_version": alert["rule_version"],
                "copy_hash": alert["copy_hash"],
            }
        )

    def record(self, alert: dict[str, object], verdict: VerificationResult) -> tuple[str, bool]:
        fingerprint = self.fingerprint(alert)
        duplicate = fingerprint in self.records
        if not duplicate:
            self.records[fingerprint] = {
                "alert": alert,
                "verdict": verdict.as_dict(),
                "state": verdict.decision,
            }
        return fingerprint, duplicate

    def apply_retraction(
        self,
        retraction: dict[str, object],
        resolver: IdentityResolver,
    ) -> VerificationResult:
        retractor = str(retraction.get("retractor", ""))
        public_key = resolver.resolve(retractor)
        if public_key is None or not verify_object(public_key, retraction):
            return VerificationResult(REJECT, RETRACTION_INVALID, "signature_or_identity")
        target = retraction.get("target")
        if not isinstance(target, dict):
            return VerificationResult(REJECT, RETRACTION_INVALID, "target_shape")
        if target.get("accuser") != retractor:
            return VerificationResult(REJECT, RETRACTION_INVALID, "retractor_not_accuser")
        fingerprint = hash_object(target)
        record = self.records.get(fingerprint)
        if record is None:
            return VerificationResult(REJECT, RETRACTION_INVALID, "record_missing")
        record["state"] = ALERT_RETRACTED
        record["retraction"] = retraction
        return VerificationResult(ACCEPT, ALERT_RETRACTED, "original_verdict_retained")


class AlertVerifier:
    """D7/D8/D9 verifier used by both participant and observer paths."""

    def __init__(
        self,
        resolver: IdentityResolver,
        rule_registry: RuleRegistry,
        *,
        ttl: int = 3600,
        clock_skew: int = 2,
    ) -> None:
        self.resolver = resolver
        self.rule_registry = rule_registry
        self.ttl = ttl
        self.clock_skew = clock_skew
        self.anchors: dict[str, dict[str, object]] = {}
        self.roots: list[dict[str, object]] = []

    def add_anchor(self, anchor: dict[str, object]) -> str:
        reference = hash_object(anchor)
        self.anchors[reference] = anchor
        return reference

    def add_root(self, attestation: dict[str, object]) -> None:
        self.roots.append(attestation)

    def verify_alert(
        self,
        alert: dict[str, object],
        *,
        now: int,
        providers: Iterable[dict[str, object]] = (),
        local_bundle: dict[str, object] | None = None,
    ) -> VerificationResult:
        anchor_ref = str(alert.get("anchor_ref", ""))
        anchor = self.anchors.get(anchor_ref)
        if anchor is None:
            if self._age(alert, now) > self.ttl:
                return VerificationResult(REJECT, STALE_ALERT, "anchor_unresolved_after_ttl")
            return VerificationResult(UNCONFIRMED, ANCHOR_UNRESOLVED, "retry_before_ttl")

        anchor_ok, anchor_detail = verify_anchor(anchor, self.resolver)
        if not anchor_ok:
            return VerificationResult(REJECT, ANCHOR_INVALID, anchor_detail)
        if (
            now < int(anchor["t_start"]) - self.clock_skew
            or now > int(anchor["t_end"]) + self.clock_skew
        ):
            return VerificationResult(REJECT, ANCHOR_EXPIRED, "anchor_window")

        alert_time = int(alert.get("ts", -1))
        if (
            alert_time < int(anchor["t_start"]) - self.clock_skew
            or alert_time > int(anchor["t_end"]) + self.clock_skew
            or alert_time > now + self.clock_skew
            or self._age(alert, now) > self.ttl
        ):
            if self._age(alert, now) > self.ttl:
                return VerificationResult(REJECT, STALE_ALERT, "alert_ttl")
            return VerificationResult(REJECT, TIME_WINDOW_INVALID, "alert_time")

        conflict = self._find_conflicting_root(alert, anchor)
        if conflict:
            return VerificationResult(REJECT, EQUIVOCATION_DETECTED, conflict)

        candidates = list(providers)
        if local_bundle is not None:
            candidates.insert(0, local_bundle)
        failures: list[str] = []
        valid_event: dict[str, object] | None = None
        for index, bundle in enumerate(candidates):
            trusted_local = local_bundle is not None and index == 0
            ok, reason, event = self._validate_bundle(alert, anchor, bundle)
            if ok:
                valid_event = event
                break
            failures.append(reason)
            if trusted_local and reason in {
                EVIDENCE_INVALID,
                PROOF_INVALID,
                EVIDENCE_MISMATCH,
            }:
                return VerificationResult(REJECT, reason, "verified_local_candidate")

        if valid_event is None:
            if self._age(alert, now) > self.ttl:
                return VerificationResult(
                    REJECT,
                    STALE_ALERT,
                    "no_valid_candidate_after_ttl",
                    tuple(failures),
                )
            unavailable = (
                PROOF_UNAVAILABLE
                if failures and all(reason == PROOF_INVALID for reason in failures)
                else ROOT_UNAVAILABLE
                if failures and all(reason == ROOT_UNAVAILABLE for reason in failures)
                else EVIDENCE_UNAVAILABLE
            )
            return VerificationResult(
                UNCONFIRMED,
                unavailable,
                "no_valid_candidate_before_ttl",
                tuple(failures),
            )

        if alert.get("copy_hash") != event_hash(valid_event):
            return VerificationResult(REJECT, EVIDENCE_MISMATCH, "copy_hash")

        accuser_key = self.resolver.resolve(str(alert.get("accuser", "")))
        if accuser_key is None or not verify_object(accuser_key, alert):
            return VerificationResult(REJECT, ACCUSER_SIG_INVALID, "accuser_signature")

        rule_id = str(alert.get("rule_id", ""))
        rule_version = str(alert.get("rule_version", ""))
        result = self.rule_registry.evaluate(rule_id, rule_version, valid_event)
        if result is None:
            return VerificationResult(REJECT, RULE_UNKNOWN, "rule_version_missing")
        if alert.get("result") != "violation" or result != "violation":
            return VerificationResult(REJECT, RULE_NOT_VIOLATED, "local_re_evaluation")
        return VerificationResult(ACCEPT, ACCEPT, "all_d9_conditions")

    def _validate_bundle(
        self,
        alert: dict[str, object],
        anchor: dict[str, object],
        bundle: dict[str, object],
    ) -> tuple[bool, str, dict[str, object] | None]:
        try:
            event = bundle["event"]
            attestation = bundle["root_attestation"]
            proof = alert["inclusion_proof"]
            _ = bundle["inclusion_proof"]
            bundle_anchor = bundle["anchor"]
            if not all(isinstance(item, dict) for item in (event, attestation, bundle_anchor)):
                return False, EVIDENCE_INVALID, None
            if not isinstance(proof, dict):
                return False, PROOF_INVALID, None
        except KeyError:
            return False, EVIDENCE_INVALID, None

        if hash_object(bundle_anchor) != alert["anchor_ref"]:
            return False, EVIDENCE_INVALID, None
        if hash_object(attestation) != alert.get("root_ref"):
            return False, ROOT_UNAVAILABLE, None
        if event.get("sid") != anchor.get("sid") or event.get("d") != alert.get("d"):
            return False, EVIDENCE_INVALID, None
        sender = str(event.get("sender", ""))
        receiver = str(event.get("receiver", ""))
        if event.get("d") != direction_name(sender, receiver):
            return False, EVIDENCE_INVALID, None
        public_key_hex = anchor.get(f"pk_{sender}")
        if not isinstance(public_key_hex, str):
            return False, EVIDENCE_INVALID, None
        try:
            from .crypto import public_key_from_hex

            event_key = public_key_from_hex(public_key_hex)
        except ValueError:
            return False, EVIDENCE_INVALID, None
        if not verify_object(event_key, event):
            return False, EVIDENCE_INVALID, None
        event_time = int(event.get("ts", -1))
        if (
            event_time < int(anchor["t_start"]) - self.clock_skew
            or event_time > int(anchor["t_end"]) + self.clock_skew
        ):
            return False, EVIDENCE_INVALID, None
        if int(alert.get("seq", -1)) != int(event.get("seq", -2)):
            return False, EVIDENCE_INVALID, None

        root_ok, root_reason = self._verify_root_attestation(attestation, anchor, event)
        if not root_ok:
            return False, root_reason, None
        if not verify_inclusion(
            bytes.fromhex(event_hash(event)),
            proof,
            str(attestation["root"]),
        ):
            return False, PROOF_INVALID, None
        return True, "ok", event

    def _verify_root_attestation(
        self,
        attestation: dict[str, object],
        anchor: dict[str, object],
        event: dict[str, object],
    ) -> tuple[bool, str]:
        required = {
            "sid",
            "d",
            "start_seq",
            "end_seq",
            "tree_size",
            "root",
            "publisher",
            "sig",
        }
        if not required.issubset(attestation):
            return False, ROOT_UNAVAILABLE
        if (
            attestation["sid"] != anchor["sid"]
            or attestation["d"] != event["d"]
            or int(attestation["start_seq"]) > int(event["seq"])
            or int(attestation["end_seq"]) < int(event["seq"])
        ):
            return False, ROOT_UNAVAILABLE
        publisher = str(attestation["publisher"])
        public_key_hex = anchor.get(f"pk_{publisher}")
        if not isinstance(public_key_hex, str):
            return False, ROOT_UNAVAILABLE
        from .crypto import public_key_from_hex

        try:
            if not verify_object(public_key_from_hex(public_key_hex), attestation):
                return False, ROOT_UNAVAILABLE
        except ValueError:
            return False, ROOT_UNAVAILABLE
        expected_size = int(attestation["end_seq"]) - int(attestation["start_seq"]) + 1
        if int(attestation["tree_size"]) != expected_size:
            return False, ROOT_UNAVAILABLE
        return True, "ok"

    def _find_conflicting_root(
        self,
        alert: dict[str, object],
        anchor: dict[str, object],
    ) -> str | None:
        seq = int(alert.get("seq", -1))
        groups: dict[tuple[str, str, int, int], set[str]] = {}
        for attestation in self.roots:
            if (
                attestation.get("sid") != anchor.get("sid")
                or attestation.get("d") != alert.get("d")
                or int(attestation.get("start_seq", -1)) > seq
                or int(attestation.get("end_seq", -1)) < seq
            ):
                continue
            publisher = str(attestation.get("publisher", ""))
            public_key_hex = anchor.get(f"pk_{publisher}")
            if not isinstance(public_key_hex, str):
                continue
            from .crypto import public_key_from_hex

            try:
                if not verify_object(public_key_from_hex(public_key_hex), attestation):
                    continue
            except ValueError:
                continue
            key = (
                str(attestation["sid"]),
                str(attestation["d"]),
                int(attestation["start_seq"]),
                int(attestation["end_seq"]),
            )
            groups.setdefault(key, set()).add(str(attestation["root"]))
        for key, roots in groups.items():
            if len(roots) > 1:
                return f"{key[0]}:{key[1]}:{key[2]}-{key[3]}"
        return None

    @staticmethod
    def _age(alert: dict[str, object], now: int) -> int:
        return now - int(alert.get("ts", now))
