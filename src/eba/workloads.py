"""Deterministic workload generators for E6 and related experiments."""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class WorkloadEvent:
    target: str
    amount: int
    delegation_depth: int
    calls_in_window: int
    requested_scope: tuple[str, ...]
    granted_scope: tuple[str, ...]
    content_policy_ok: bool
    payload: bytes

    @property
    def is_violation(self) -> bool:
        return any(
            (
                self.target != "vendor-trusted",
                self.amount > 10_000,
                self.delegation_depth > 3,
                self.calls_in_window > 100,
                not set(self.requested_scope).issubset(self.granted_scope),
                not self.content_policy_ok,
            )
        )

    def intent_meta(self) -> dict[str, object]:
        return {
            "target": self.target,
            "amount": self.amount,
            "delegation_depth": self.delegation_depth,
            "calls_in_window": self.calls_in_window,
            "content_policy_ok": self.content_policy_ok,
        }

    def perm_scope(self) -> dict[str, object]:
        return {
            "requested": list(self.requested_scope),
            "granted": list(self.granted_scope),
        }


def benign_event(rng: random.Random, payload_size: int = 256) -> WorkloadEvent:
    scopes = rng.choice([("read",), ("read", "pay"), ("read", "pay", "delegate")])
    requested_count = rng.randint(1, len(scopes))
    return WorkloadEvent(
        target="vendor-trusted",
        amount=rng.randint(1, 9_000),
        delegation_depth=rng.randint(0, 3),
        calls_in_window=rng.randint(1, 80),
        requested_scope=scopes[:requested_count],
        granted_scope=scopes,
        content_policy_ok=True,
        payload=rng.randbytes(payload_size),
    )


def violating_event(
    rng: random.Random,
    *,
    kind: str = "allow",
    payload_size: int = 256,
) -> WorkloadEvent:
    base = benign_event(rng, payload_size)
    if kind in {"allow", "mislabel"}:
        return WorkloadEvent(**{**base.__dict__, "target": "outside-allowlist"})
    if kind == "amount":
        return WorkloadEvent(**{**base.__dict__, "amount": 10_001 + rng.randint(0, 1000)})
    if kind == "depth":
        return WorkloadEvent(**{**base.__dict__, "delegation_depth": 4})
    if kind == "rate":
        return WorkloadEvent(**{**base.__dict__, "calls_in_window": 101})
    if kind == "scope":
        requested = tuple(dict.fromkeys(base.requested_scope + ("admin",)))
        return WorkloadEvent(**{**base.__dict__, "requested_scope": requested})
    if kind == "content":
        return WorkloadEvent(**{**base.__dict__, "content_policy_ok": False})
    raise ValueError(f"unknown workload kind: {kind}")
