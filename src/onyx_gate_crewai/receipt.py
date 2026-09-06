"""Signed per-decision receipts — verify one, and REQUIRE one before acting.

The Onyx gateway can sign every decision it returns (``?receipt=true``; the
receipt rides the HTTP response as ``receipt`` and an MCP tool result as
``_meta.receipt``): a small JSON object saying which request (by canonical
hash) was decided, which way, under which policy version, by which engine, and
when — signed with the gateway's Ed25519 *decision key*, whose public half and
key id (``kid``) the gateway discloses on ``GET /ready`` as ``receipt_key``. The
gateway's hash-chained audit trail commits each receipt by hash, so a receipt in
hand can later be bound to its trail record with
``eg_verify --audit-log <trail> --receipt <r> --receipt-public-key <pub>``.

This module is the *effector-side* rule — **no receipt, no action**. A tool
wrapper that holds the gateway's public key refuses to execute a call unless it
holds a receipt that (1) verifies under that key, (2) says ``allow``, and (3) is
for exactly the call about to run: the request hash is recomputed here from the
same body the client sent. Standard library only. The Ed25519 verification is
the RFC 8032 reference algorithm in pure Python (a few milliseconds per receipt;
verification handles no secret, so signing's constant-time concerns do not
apply).

Wire shape (``onyx-receipt-v1``)::

    {"v": "onyx-receipt-v1", "kid": "<16 hex>", "request_sha256": "<64 hex>",
     "decision": "allow", "policy_version": "<64 hex>",
     "engine": "eg_gateway 0.4.0 (abc123)", "ts": "2026-09-05T18:02:11Z",
     "certificate_sha256": "<64 hex>",    # only when a certificate was attached
     "explanation_sha256": "<64 hex>",    # only when the decision carried one
     "sig": "<128 hex>"}

Canonical form (normative in the engine's ``docs/decision-receipts.md`` §3.1):
JSON with keys sorted by code point, no whitespace, the JSON string escapes;
absent optional fields omitted. The signed message is
``b"onyx-receipt-v1" + b"\\x00" + canonical(receipt without "sig")``. ``kid`` is
the first 16 hex characters of SHA-256 over the raw 32-byte public key. The
request hash is SHA-256 of the canonical six-key request object — ``principal``
(``Agent::"<agent>"``), ``action`` (``Action::"<tool>"``), ``resource``,
``resource_attrs`` (``{}`` when absent), ``resource_parents`` (``[]``),
``context`` (``{}``) — with a backslash or double quote inside an id escaped as
the engine's canonical uid rendering does.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

RECEIPT_VERSION = "onyx-receipt-v1"
KID_HEX_LEN = 16

_REQUIRED = ("v", "kid", "request_sha256", "decision", "policy_version", "engine", "ts", "sig")
_OPTIONAL = ("certificate_sha256", "explanation_sha256")


class ReceiptError(Exception):
    """A receipt could not be accepted. Subclasses say why."""


class ReceiptMissing(ReceiptError):
    """No receipt where one is required."""


class ReceiptInvalid(ReceiptError):
    """Malformed, a version this package does not read, signed by another key, or
    a signature that does not verify."""


class ReceiptMismatch(ReceiptError):
    """A genuine receipt that does not say what the effector requires: a
    different decision, a different request, or too old."""


# -- canonical form and hashes ----------------------------------------------


def canonical_json(value: Any) -> str:
    """The engine's canonical JSON: keys sorted by code point (the same order as
    UTF-8 byte order), no whitespace, non-ASCII kept raw. Strings, integers,
    booleans, ``None``, lists, and objects round-trip identically to the
    engine's renderer; floats are not canonical across the two and never occur
    in a receipt or a gate request (the client sends them as strings)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    """SHA-256 (hex) of :func:`canonical_json` — the content hash of any JSON
    document (a certificate, a request, a receipt)."""
    return sha256_hex(canonical_json(value).encode("utf-8"))


def kid_of(public_key_hex: str) -> str:
    """The key id of a public key: the first 16 hex of SHA-256 over its raw bytes."""
    return sha256_hex(_hex_bytes(public_key_hex, 32, "public key"))[:KID_HEX_LEN]


def uid_key(type_path: str, entity_id: str) -> str:
    """The engine's canonical ``Type::"id"`` rendering (``\\`` and ``"`` escaped)."""
    escaped = entity_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'{type_path}::"{escaped}"'


def request_sha256(
    agent: str,
    tool: str,
    resource: Optional[str] = None,
    resource_attrs: Optional[Mapping[str, Any]] = None,
    resource_parents: Optional[list[str]] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> str:
    """The receipt's ``request_sha256`` for a tool call, recomputed from what the
    client sent — the gateway's ``gate_tool_call`` shape. ``resource`` defaults
    to ``Tool::"<tool>"`` exactly as :class:`~.client.OnyxGate` does."""
    if resource is None:
        resource = f'Tool::"{tool}"'
    subject = {
        "principal": uid_key("Agent", agent),
        "action": uid_key("Action", tool),
        "resource": resource,
        "resource_attrs": dict(resource_attrs or {}),
        "resource_parents": list(resource_parents or []),
        "context": dict(context or {}),
    }
    return canonical_sha256(subject)


def request_sha256_of_payload(payload: Mapping[str, Any]) -> str:
    """:func:`request_sha256` over a ``POST /gate/tool-call`` body as sent."""
    return request_sha256(
        agent=str(payload["agent"]),
        tool=str(payload["tool"]),
        resource=payload.get("resource"),
        resource_attrs=payload.get("resource_attrs"),
        resource_parents=payload.get("resource_parents"),
        context=payload.get("context"),
    )


def receipt_message(receipt: Mapping[str, Any]) -> bytes:
    """The signed bytes: the version tag, a NUL, the canonical receipt without ``sig``."""
    body = {k: v for k, v in receipt.items() if k != "sig" and v is not None}
    return RECEIPT_VERSION.encode("ascii") + b"\x00" + canonical_json(body).encode("utf-8")


def receipt_sha256(receipt: Mapping[str, Any]) -> str:
    """The receipt's own content hash (``sig`` included) — what the gateway's trail
    record carries as ``receipt_sha256``; also the file name the enforcing hook
    writes a receipt under."""
    return canonical_sha256({k: v for k, v in receipt.items() if v is not None})


def receipt_id(receipt: Mapping[str, Any]) -> str:
    """``receipt:<kid>:<first 12 hex of receipt_sha256>`` — the short id the hook
    puts in its deny reason."""
    return f"receipt:{receipt.get('kid', '?')}:{receipt_sha256(receipt)[:12]}"


# -- verification ------------------------------------------------------------


def _hex_bytes(text: Any, length: int, what: str) -> bytes:
    if not isinstance(text, str) or len(text) != length * 2:
        raise ReceiptInvalid(f"{what} must be {length * 2} hex characters")
    try:
        return bytes.fromhex(text)
    except ValueError as e:
        raise ReceiptInvalid(f"{what} is not valid hex") from e


def check_shape(receipt: Any) -> dict[str, Any]:
    """Refuse anything that is not exactly an ``onyx-receipt-v1`` object. The
    version is checked first, so a receipt from a newer scheme is refused with
    one legible sentence (never a field-by-field error); under the supported
    version unknown fields are refused — what the signature covers is exactly
    what the receipt says, and a consumer can never be handed an unsigned field
    under a verified receipt."""
    if not isinstance(receipt, Mapping):
        raise ReceiptInvalid("a receipt is a JSON object")
    version = receipt.get("v")
    if version is None:
        raise ReceiptInvalid("no `v` field — not a receipt")
    if version != RECEIPT_VERSION:
        raise ReceiptInvalid(
            f"receipt version `{version}` is not one this package reads (supports "
            f"{RECEIPT_VERSION}) — upgrade the package to verify it"
        )
    unknown = sorted(set(receipt) - set(_REQUIRED) - set(_OPTIONAL))
    if unknown:
        raise ReceiptInvalid(f"unknown receipt field(s): {', '.join(unknown)}")
    for key in _REQUIRED:
        if not isinstance(receipt.get(key), str):
            raise ReceiptInvalid(f"receipt field `{key}` is missing or not a string")
    for key in _OPTIONAL:
        value = receipt.get(key)
        if value is not None and not isinstance(value, str):
            raise ReceiptInvalid(f"receipt field `{key}` is not a string")
    _hex_bytes(receipt["kid"], KID_HEX_LEN // 2, "kid")
    _hex_bytes(receipt["request_sha256"], 32, "request_sha256")
    _hex_bytes(receipt["sig"], 64, "sig")
    return dict(receipt)


def verify_receipt(receipt: Any, public_key_hex: str) -> dict[str, Any]:
    """Check that ``receipt`` is a well-formed ``onyx-receipt-v1`` receipt that
    names ``public_key_hex``'s key (``kid``) and whose signature verifies under
    it. Returns the receipt; raises :class:`ReceiptInvalid` otherwise. A
    receipt is verified under the key it names — a different key is reported
    with both ids, never tried anyway."""
    checked = check_shape(receipt)
    public = _hex_bytes(public_key_hex.strip(), 32, "public key")
    expected_kid = sha256_hex(public)[:KID_HEX_LEN]
    if checked["kid"] != expected_kid:
        raise ReceiptInvalid(
            f"the receipt names kid {checked['kid']}; the supplied public key is kid "
            f"{expected_kid} — verify it under the key it names"
        )
    if not ed25519_verify(public, receipt_message(checked), bytes.fromhex(checked["sig"])):
        raise ReceiptInvalid("the signature does not verify under the given public key")
    return checked


def parse_ts(ts: str) -> float:
    """The receipt's RFC 3339 UTC ``ts`` as Unix seconds."""
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError as e:
        raise ReceiptInvalid(f"receipt `ts` is not RFC 3339 UTC: {ts!r}") from e


def require_receipt(
    receipt: Any,
    public_key_hex: str,
    *,
    decision: str = "allow",
    request_sha256: Optional[str] = None,
    max_age_s: Optional[float] = None,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """The effector-side rule: refuse unless ``receipt`` is a valid receipt under
    ``public_key_hex`` that attests ``decision`` (default ``allow``) — and, when
    given, exactly the request ``request_sha256`` (see :func:`request_sha256`)
    and is no older than ``max_age_s`` seconds (the receipt's ``ts`` is
    informational; ordering comes from the gateway's trail, so treat an age
    bound as hygiene, not as replay protection). Returns the receipt; raises
    :class:`ReceiptMissing`, :class:`ReceiptInvalid`, or
    :class:`ReceiptMismatch`."""
    if receipt is None:
        raise ReceiptMissing("no receipt — the gateway issued none (no receipt key, or "
                             "an unversioned policy state); refusing to act without one")
    checked = verify_receipt(receipt, public_key_hex)
    if checked["decision"] != decision:
        raise ReceiptMismatch(
            f"the receipt attests `{checked['decision']}`, not `{decision}`"
        )
    if request_sha256 is not None and checked["request_sha256"] != request_sha256:
        raise ReceiptMismatch(
            "the receipt is for a different request "
            f"({checked['request_sha256'][:12]}… vs this call {request_sha256[:12]}…)"
        )
    if max_age_s is not None:
        issued = parse_ts(checked["ts"])
        current = time.time() if now is None else now
        if current - issued > max_age_s:
            raise ReceiptMismatch(
                f"the receipt is {current - issued:.0f}s old, older than the {max_age_s:.0f}s bound"
            )
    return checked


def read_public_key(path: str) -> str:
    """The hex public key from an ``eg_verify --keygen`` ``.pub`` file (or the
    ``receipt_key.public_key`` value from ``GET /ready``, saved to a file)."""
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


# -- Ed25519 verification (RFC 8032 §5.1, reference algorithm) ---------------

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> Optional[int]:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _point_add(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _point_decompress(data: bytes) -> Optional[tuple[int, int, int, int]]:
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _recover_x(_G_Y, 0) or 0
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 Ed25519 signature verification (``s·B == R + h·A``). Pure Python."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _point_decompress(public)
    if a is None:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    r = _point_decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(r_bytes + public + message).digest(), "little") % _L
    return _point_equal(_point_mul(s, _G), _point_add(r, _point_mul(h, a)))
