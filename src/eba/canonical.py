"""RFC 8785 JSON Canonicalization Scheme for protocol objects."""

from __future__ import annotations

import json
import math
from typing import Any


def _utf16_sort_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="surrogatepass")


def _format_number(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("JCS does not permit NaN or Infinity")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    text = repr(value).lower()
    if "e" in text:
        mantissa, exponent = text.split("e", 1)
        sign = ""
        if exponent.startswith(("+", "-")):
            sign, exponent = exponent[0], exponent[1:]
        exponent = exponent.lstrip("0") or "0"
        text = f"{mantissa}e{sign}{exponent}"
    return text


def _format_string(value: str) -> str:
    escaped = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return escaped.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def dumps(value: Any) -> str:
    """Serialize a JSON-compatible value using deterministic RFC 8785 rules."""

    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return _format_number(value)
    if isinstance(value, str):
        return _format_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(dumps(item) for item in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JCS object keys must be strings")
        keys = sorted(value, key=_utf16_sort_key)
        return "{" + ",".join(f"{_format_string(key)}:{dumps(value[key])}" for key in keys) + "}"
    raise TypeError(f"unsupported JCS value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return dumps(value).encode("utf-8")


def without_signature(value: dict[str, Any], signature_field: str = "sig") -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != signature_field}
