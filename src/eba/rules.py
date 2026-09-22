"""Versioned deterministic rules used by the evaluation workloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .crypto import hash_object

Event = dict[str, object]
RulePredicate = Callable[[Event], bool]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    version: str
    observability_class: str
    predicate: RulePredicate

    @property
    def key(self) -> tuple[str, str]:
        return self.rule_id, self.version


class RuleRegistry:
    """Resolves exact rule versions and re-evaluates them locally."""

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self._rules: dict[tuple[str, str], Rule] = {}
        self.allowlist = allowlist or {
            "vendor-trusted",
            "buyer-account-1",
            "procurement-supplier-a",
        }
        self.register_rules()

    def register(self, rule: Rule) -> None:
        self._rules[rule.key] = rule

    def register_rules(self) -> None:
        self.register(
            Rule("ALLOW-1", "v1", "O1", lambda event: self._target(event) in self.allowlist)
        )
        self.register(Rule("SCOPE-1", "v1", "O1", self._scope_ok))
        self.register(Rule("AMOUNT-1", "v1", "O1", self._amount_ok))
        self.register(Rule("DEPTH-1", "v1", "O1", self._depth_ok))
        self.register(Rule("RATE-1", "v1", "O1", self._rate_ok))
        self.register(Rule("CONTENT-1", "v1", "O2", self._content_ok))

    def retire(self, rule_id: str, version: str) -> None:
        self._rules.pop((rule_id, version), None)

    def resolve(self, rule_id: str, version: str) -> Rule | None:
        return self._rules.get((rule_id, version))

    def evaluate(self, rule_id: str, version: str, event: Event) -> str | None:
        rule = self.resolve(rule_id, version)
        if rule is None:
            return None
        return "ok" if rule.predicate(event) else "violation"

    def manifest(self) -> dict[str, object]:
        entries = [
            {
                "rule_id": rule.rule_id,
                "rule_version": rule.version,
                "observability_class": rule.observability_class,
                "predicate_hash": hash_object(
                    {
                        "rule_id": rule.rule_id,
                        "rule_version": rule.version,
                        "class": rule.observability_class,
                    }
                ),
            }
            for rule in sorted(self._rules.values(), key=lambda value: value.key)
        ]
        return {
            "rules": entries,
            "allowlist": sorted(self.allowlist),
            "cap": 10_000,
            "d_max": 3,
            "r_max": 100,
        }

    @staticmethod
    def _target(event: Event) -> str:
        return str(event["intent_meta"].get("target", ""))

    @staticmethod
    def _scope_ok(event: Event) -> bool:
        scope = set(event["perm_scope"].get("granted", []))
        requested = set(event["perm_scope"].get("requested", []))
        return requested.issubset(scope)

    @staticmethod
    def _amount_ok(event: Event) -> bool:
        return int(event["intent_meta"].get("amount", 0)) <= 10_000

    @staticmethod
    def _depth_ok(event: Event) -> bool:
        return int(event["intent_meta"].get("delegation_depth", 0)) <= 3

    @staticmethod
    def _rate_ok(event: Event) -> bool:
        return int(event["intent_meta"].get("calls_in_window", 0)) <= 100

    @staticmethod
    def _content_ok(event: Event) -> bool:
        return bool(event["intent_meta"].get("content_policy_ok", True))


def all_rule_versions(registry: RuleRegistry) -> list[tuple[str, str]]:
    return sorted(registry._rules)
