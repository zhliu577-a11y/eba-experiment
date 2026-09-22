"""Cryptographic helpers used by the EBA prototype."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonical_bytes, without_signature


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hex32(data: bytes) -> str:
    if len(data) != 32:
        raise ValueError("hex32 requires 32 bytes")
    return data.hex()


def hash_object(value: object) -> str:
    return hex32(sha256(canonical_bytes(value)))


def public_bytes(key: Ed25519PublicKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_hex(key: Ed25519PublicKey) -> str:
    return public_bytes(key).hex()


def public_key_from_hex(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


def sign_object(private_key: Ed25519PrivateKey, value: dict[str, object]) -> str:
    message = canonical_bytes(without_signature(value))
    return private_key.sign(message).hex()


def verify_object(public_key: Ed25519PublicKey, value: dict[str, object]) -> bool:
    try:
        signature = bytes.fromhex(str(value["sig"]))
        public_key.verify(signature, canonical_bytes(without_signature(value)))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def b64encode_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64decode_bytes(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


@dataclass(frozen=True)
class Identity:
    """Long-term identity material for one agent."""

    name: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, name: str) -> "Identity":
        private_key = Ed25519PrivateKey.generate()
        return cls(name=name, private_key=private_key, public_key=private_key.public_key())

    @property
    def public_hex(self) -> str:
        return public_hex(self.public_key)


class IdentityResolver:
    """A0 identity-binding stand-in."""

    def __init__(self) -> None:
        self._bindings: dict[str, Ed25519PublicKey] = {}

    def bind(self, identity: Identity) -> None:
        self._bindings[identity.name] = identity.public_key

    def bind_public(self, name: str, public_key: Ed25519PublicKey) -> None:
        self._bindings[name] = public_key

    def resolve(self, name: str) -> Ed25519PublicKey | None:
        return self._bindings.get(name)

    def snapshot(self) -> dict[str, str]:
        return {name: public_hex(key) for name, key in sorted(self._bindings.items())}
