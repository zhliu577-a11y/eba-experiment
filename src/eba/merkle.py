"""SHA-256 Merkle tree and inclusion proofs."""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import hex32, sha256


@dataclass(frozen=True)
class InclusionProof:
    index: int
    tree_size: int
    siblings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "tree_size": self.tree_size,
            "siblings": list(self.siblings),
        }


def leaf_hash(value: bytes) -> bytes:
    return sha256(b"\x00" + value)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def _levels(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        return [[sha256(b"")]]
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level: list[bytes] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(node_hash(left, right))
        levels.append(next_level)
    return levels


def merkle_root(message_hashes: list[bytes]) -> bytes:
    leaves = [leaf_hash(value) for value in message_hashes]
    return _levels(leaves)[-1][0]


def inclusion_proof(message_hashes: list[bytes], index: int) -> InclusionProof:
    if index < 0 or index >= len(message_hashes):
        raise IndexError("proof index outside tree")
    leaves = [leaf_hash(value) for value in message_hashes]
    levels = _levels(leaves)
    siblings: list[bytes] = []
    cursor = index
    for level in levels[:-1]:
        sibling = cursor + 1 if cursor % 2 == 0 else cursor - 1
        siblings.append(level[sibling] if sibling < len(level) else level[cursor])
        cursor //= 2
    return InclusionProof(
        index=index,
        tree_size=len(message_hashes),
        siblings=tuple(hex32(item) for item in siblings),
    )


def verify_inclusion(
    message_hash: bytes,
    proof: InclusionProof | dict[str, object],
    expected_root: str | bytes,
) -> bool:
    if isinstance(proof, dict):
        try:
            proof = InclusionProof(
                index=int(proof["index"]),
                tree_size=int(proof["tree_size"]),
                siblings=tuple(str(item) for item in proof["siblings"]),
            )
        except (KeyError, TypeError, ValueError):
            return False
    if proof.index < 0 or proof.tree_size <= 0 or proof.index >= proof.tree_size:
        return False
    cursor = leaf_hash(message_hash)
    index = proof.index

    # Rebuild the shape of the tree from its declared size. Odd nodes are duplicated.
    level_sizes = [proof.tree_size]
    while level_sizes[-1] > 1:
        level_sizes.append((level_sizes[-1] + 1) // 2)
    if len(proof.siblings) != len(level_sizes) - 1:
        return False

    for sibling_hex in proof.siblings:
        try:
            sibling = bytes.fromhex(sibling_hex)
        except ValueError:
            return False
        if len(sibling) != 32:
            return False
        if index % 2 == 0:
            cursor = node_hash(cursor, sibling)
        else:
            cursor = node_hash(sibling, cursor)
        index //= 2
    expected = bytes.fromhex(expected_root) if isinstance(expected_root, str) else expected_root
    return cursor == expected
