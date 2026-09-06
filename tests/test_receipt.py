"""Signed per-decision receipts: the pure-Python verifier against the RFC 8032
vectors, and against receipts a REAL Onyx gateway signed (tests/fixtures) — so
the canonical hashing and the signature check are pinned to the engine's own,
not to this package's idea of them."""

import json
import pathlib

import pytest

from onyx_gate_crewai import receipt as r

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
PUB = (FIXTURES / "gw.pub").read_text().strip()
ALLOW = json.loads((FIXTURES / "response_allow.json").read_text())["receipt"]
DENY = json.loads((FIXTURES / "response_deny.json").read_text())["receipt"]
REQUEST_ALLOW = json.loads((FIXTURES / "request_allow.json").read_text())
REQUEST_DENY = json.loads((FIXTURES / "request_deny.json").read_text())
TRAIL = [json.loads(line) for line in (FIXTURES / "trail.jsonl").read_text().splitlines()]


# -- Ed25519 (RFC 8032 §7.1 test vectors) --------------------------------


def test_ed25519_rfc8032_vectors():
    pk1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig1 = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert r.ed25519_verify(pk1, b"", sig1)
    pk2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    sig2 = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert r.ed25519_verify(pk2, b"\x72", sig2)
    # A different message, a flipped signature bit, a flipped key bit: all refused.
    assert not r.ed25519_verify(pk2, b"\x73", sig2)
    assert not r.ed25519_verify(pk2, b"\x72", bytes([sig2[0] ^ 1]) + sig2[1:])
    assert not r.ed25519_verify(bytes([pk2[0] ^ 1]) + pk2[1:], b"\x72", sig2)
    assert not r.ed25519_verify(pk2, b"\x72", sig2[:63])
    assert not r.ed25519_verify(b"\xff" * 32, b"\x72", sig2)


# -- the engine's own receipts -------------------------------------------


def test_engine_receipts_verify_and_the_kid_is_the_keys():
    assert r.kid_of(PUB) == ALLOW["kid"] == DENY["kid"]
    assert r.verify_receipt(ALLOW, PUB)["decision"] == "allow"
    assert r.verify_receipt(DENY, PUB)["decision"] == "deny"
    assert ALLOW["engine"].startswith("eg_gateway ")


def test_request_hash_recomputes_from_the_body_as_sent():
    # The cross-pin that matters: this package's canonical request hash equals
    # the engine's over the exact body the gateway decided.
    assert r.request_sha256_of_payload(REQUEST_ALLOW) == ALLOW["request_sha256"]
    assert r.request_sha256_of_payload(REQUEST_DENY) == DENY["request_sha256"]
    # …and the keyword form is the same function.
    assert (
        r.request_sha256(
            agent="ap-clerk",
            tool="pay_invoice",
            resource='Tool::"pay_invoice"',
            resource_attrs={"vendor": "globex", "amount": 4800, "rush": True},
            context={"env": "prod"},
        )
        == ALLOW["request_sha256"]
    )
    # Any change to any field is a different request.
    changed = dict(REQUEST_ALLOW, resource_attrs={"vendor": "globex", "amount": 4801, "rush": True})
    assert r.request_sha256_of_payload(changed) != ALLOW["request_sha256"]


def test_receipt_hash_is_what_the_trail_record_commits():
    assert TRAIL[0]["result"]["receipt_sha256"] == r.receipt_sha256(ALLOW)
    assert TRAIL[1]["result"]["receipt_sha256"] == r.receipt_sha256(DENY)
    assert "sig" not in json.dumps(TRAIL[0]), "the record commits the hash, never the receipt"
    assert r.receipt_id(ALLOW) == f"receipt:{ALLOW['kid']}:{r.receipt_sha256(ALLOW)[:12]}"


def test_uid_key_escapes_like_the_engine():
    assert r.uid_key("Agent", "planner") == 'Agent::"planner"'
    assert r.uid_key("Agent", 'plan"ner') == 'Agent::"plan\\"ner"'
    assert r.uid_key("Agent", "a\\b") == 'Agent::"a\\\\b"'


# -- require_receipt: the effector-side rule ------------------------------


def test_require_accepts_the_allow_for_this_call():
    got = r.require_receipt(ALLOW, PUB, request_sha256=r.request_sha256_of_payload(REQUEST_ALLOW))
    assert got["decision"] == "allow"


def test_require_refuses_a_deny_a_missing_receipt_and_another_request():
    with pytest.raises(r.ReceiptMismatch, match="attests `deny`"):
        r.require_receipt(DENY, PUB)
    with pytest.raises(r.ReceiptMissing):
        r.require_receipt(None, PUB)
    with pytest.raises(r.ReceiptMismatch, match="different request"):
        r.require_receipt(ALLOW, PUB, request_sha256=r.request_sha256_of_payload(REQUEST_DENY))


def test_require_refuses_edits_forgeries_and_the_wrong_key():
    for what, edit in [
        ("decision", {"decision": "deny"}),
        ("policy_version", {"policy_version": "0" * 64}),
        ("request", {"request_sha256": "1" * 64}),
        ("ts", {"ts": "2030-01-01T00:00:00Z"}),
        ("engine", {"engine": "eg_gateway 9.9.9"}),
        ("certificate added", {"certificate_sha256": "2" * 64}),
        ("sig", {"sig": ("1" if ALLOW["sig"][0] == "0" else "0") + ALLOW["sig"][1:]}),
    ]:
        with pytest.raises(r.ReceiptInvalid, match="does not verify"):
            r.verify_receipt(dict(ALLOW, **edit), PUB)
    # A different key: reported as a kid mismatch naming both, never tried anyway.
    other = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    with pytest.raises(r.ReceiptInvalid, match=f"names kid {ALLOW['kid']}"):
        r.verify_receipt(ALLOW, other)
    # A forged kid pointing at the other key fails the signature under it.
    with pytest.raises(r.ReceiptInvalid, match="does not verify"):
        r.verify_receipt(dict(ALLOW, kid=r.kid_of(other)), other)


def test_shape_refusals_are_legible():
    with pytest.raises(r.ReceiptInvalid, match="not one this package reads"):
        r.verify_receipt(dict(ALLOW, v="onyx-receipt-v2", chain_position=7), PUB)
    with pytest.raises(r.ReceiptInvalid, match="unknown receipt field"):
        r.verify_receipt(dict(ALLOW, executed=True), PUB)
    with pytest.raises(r.ReceiptInvalid, match="not a receipt"):
        r.verify_receipt({"kid": "x"}, PUB)
    with pytest.raises(r.ReceiptInvalid, match="JSON object"):
        r.verify_receipt("nope", PUB)
    missing = dict(ALLOW)
    del missing["engine"]
    with pytest.raises(r.ReceiptInvalid, match="missing"):
        r.verify_receipt(missing, PUB)
    with pytest.raises(r.ReceiptInvalid, match="public key"):
        r.verify_receipt(ALLOW, "not-hex")
    # An explicit null for an absent optional field reads as absent (the
    # engine's reader does the same) and still verifies.
    assert r.verify_receipt(dict(ALLOW, certificate_sha256=None), PUB)["kid"] == ALLOW["kid"]


def test_max_age_is_hygiene_against_the_receipts_ts():
    issued = r.parse_ts(ALLOW["ts"])
    r.require_receipt(ALLOW, PUB, max_age_s=60, now=issued + 30)
    with pytest.raises(r.ReceiptMismatch, match="old"):
        r.require_receipt(ALLOW, PUB, max_age_s=60, now=issued + 61)
    with pytest.raises(r.ReceiptInvalid, match="RFC 3339"):
        r.parse_ts("yesterday")


def test_read_public_key_trims(tmp_path):
    p = tmp_path / "gw.pub"
    p.write_text(f"  {PUB}\n")
    assert r.read_public_key(str(p)) == PUB
