import pytest

from onyx_gate_crewai import OnyxGate, ToolGuard
from onyx_gate_crewai.guard import describe_call, scalarize_args
from tests.stub_gateway import StubGateway

DENY = (200, {"decision": "deny", "explanation": "amount 12000 exceeds the autonomous cap"})
ALLOW = (200, {"decision": "allow"})


def make_guard(stub: StubGateway, **kwargs) -> ToolGuard:
    return ToolGuard(gate=OnyxGate(stub.url), agent="ap-clerk", **kwargs)


# -- scalarize -----------------------------------------------------------


def test_scalarize_scalars_pass_through():
    assert scalarize_args({"s": "x", "b": True, "i": 42}) == {"s": "x", "b": True, "i": 42}


def test_scalarize_bool_stays_bool_not_int():
    out = scalarize_args({"b": False})
    assert out["b"] is False


def test_scalarize_float_and_oversized_int_become_strings():
    out = scalarize_args({"f": 1.5, "big": 2**70})
    assert out["f"] == "1.5"
    assert out["big"] == str(2**70)


def test_scalarize_none_omitted_nested_serialized():
    out = scalarize_args({"skip": None, "nested": {"cmd": "rm -rf /"}, "lst": [1, 2]})
    assert "skip" not in out
    assert out["nested"] == '{"cmd":"rm -rf /"}'  # substring policies still see content
    assert out["lst"] == "[1,2]"


def test_describe_call_truncates_only_the_descriptor():
    long = "x" * 500
    desc = describe_call("t", {"a": long})
    assert len(desc) < 200
    assert desc.startswith("t(a=")


# -- enforce mode --------------------------------------------------------


def test_enforce_allow_passes():
    with StubGateway(lambda p: ALLOW) as stub:
        result = make_guard(stub).check("read_ledger", {})
        assert result.allowed
        assert result.blocked_message is None
        assert result.advisory_note is None


def test_enforce_deny_blocks_with_descriptor_and_reason():
    with StubGateway(lambda p: DENY) as stub:
        result = make_guard(stub).check("pay_invoice", {"vendor": "vandelay", "amount": 12000})
        assert not result.allowed
        msg = result.blocked_message
        assert "did NOT execute" in msg
        assert "pay_invoice(vendor='vandelay', amount=12000)" in msg
        assert "exceeds the autonomous cap" in msg


def test_enforce_gateway_down_fails_closed():
    guard = ToolGuard(gate=OnyxGate("http://127.0.0.1:1", timeout=0.5), agent="a")
    result = guard.check("pay_invoice", {"amount": 1})
    assert not result.allowed
    assert "fail-closed" in result.blocked_message
    assert result.error is not None


def test_enforce_gateway_down_on_error_allow_is_annotated():
    guard = ToolGuard(
        gate=OnyxGate("http://127.0.0.1:1", timeout=0.5), agent="a", on_error="allow"
    )
    result = guard.check("read_ledger", {})
    assert result.allowed
    assert "fail-open" in result.advisory_note


def test_unsafe_tool_name_fails_closed_through_the_guard():
    with StubGateway() as stub:
        result = make_guard(stub).check('evil"tool', {})
        assert not result.allowed
        assert stub.requests == []  # never reached the gateway


# -- observe mode --------------------------------------------------------


def test_observe_deny_runs_but_annotates_the_flagged_call():
    with StubGateway(lambda p: DENY) as stub:
        result = make_guard(stub, mode="observe").check("pay_invoice", {"amount": 12000})
        assert result.allowed
        note = result.advisory_note
        assert "would have been DENIED" in note
        assert "pay_invoice(amount=12000)" in note
        assert "exceeds the autonomous cap" in note


def test_observe_allow_has_no_note():
    with StubGateway(lambda p: ALLOW) as stub:
        result = make_guard(stub, mode="observe").check("read_ledger", {})
        assert result.allowed
        assert result.advisory_note is None


def test_observe_gateway_down_runs_with_note():
    guard = ToolGuard(
        gate=OnyxGate("http://127.0.0.1:1", timeout=0.5), agent="a", mode="observe"
    )
    result = guard.check("read_ledger", {})
    assert result.allowed
    assert "could not decide" in result.advisory_note


# -- wiring --------------------------------------------------------------


def test_agent_context_and_attrs_reach_the_gateway():
    with StubGateway() as stub:
        guard = make_guard(stub, context={"env": "prod"})
        guard.check("pay_invoice", {"vendor": "globex", "amount": 4800})
        payload = stub.requests[0]["payload"]
        assert payload["agent"] == "ap-clerk"
        assert payload["tool"] == "pay_invoice"
        assert payload["resource"] == 'Tool::"pay_invoice"'
        assert payload["resource_attrs"] == {"vendor": "globex", "amount": 4800}
        assert payload["context"] == {"env": "prod"}


def test_invalid_mode_and_on_error_are_rejected():
    with pytest.raises(ValueError):
        ToolGuard(gate=OnyxGate("http://127.0.0.1:1"), mode="audit")
    with pytest.raises(ValueError):
        ToolGuard(gate=OnyxGate("http://127.0.0.1:1"), on_error="retry")


# -- receipts: no receipt, no action (opt-in) -----------------------------

import json as _json
import pathlib as _pathlib

_FIXTURES = _pathlib.Path(__file__).parent / "fixtures"
_PUB = (_FIXTURES / "gw.pub").read_text().strip()
_ALLOW_RECEIPTED = _json.loads((_FIXTURES / "response_allow.json").read_text())
_ALLOW_ARGS = {"vendor": "globex", "amount": 4800, "rush": True}


def _receipted(stub: StubGateway, **kwargs) -> ToolGuard:
    return make_guard(
        stub,
        context={"env": "prod"},
        require_receipt=True,
        receipt_public_key=_PUB,
        check_version=False,
        **kwargs,
    )


def test_require_receipt_runs_the_call_the_gateway_receipted():
    with StubGateway(lambda p: (200, _ALLOW_RECEIPTED)) as stub:
        result = _receipted(stub).check("pay_invoice", _ALLOW_ARGS)
    assert result.allowed
    assert result.receipt == _ALLOW_RECEIPTED["receipt"]
    assert stub.requests[0]["path"].endswith("?receipt=true"), "the guard asks for a receipt"


def test_require_receipt_blocks_when_the_allow_came_without_one():
    with StubGateway(lambda p: (200, {"decision": "allow"})) as stub:
        result = _receipted(stub).check("pay_invoice", _ALLOW_ARGS)
    assert not result.allowed
    assert "DENIED (no valid receipt)" in result.blocked_message
    assert "no receipt" in result.blocked_message
    assert result.error and result.error.startswith("receipt:")


def test_require_receipt_blocks_a_receipt_for_another_call():
    # The gateway's receipt is for amount 4800; the tool is about to run 4801.
    with StubGateway(lambda p: (200, _ALLOW_RECEIPTED)) as stub:
        result = _receipted(stub).check("pay_invoice", dict(_ALLOW_ARGS, amount=4801))
    assert not result.allowed
    assert "different request" in result.blocked_message


def test_require_receipt_is_not_subject_to_on_error_allow():
    # A missing receipt is not a transport error — fail-open never applies.
    with StubGateway(lambda p: (200, {"decision": "allow"})) as stub:
        result = _receipted(stub, on_error="allow").check("pay_invoice", _ALLOW_ARGS)
    assert not result.allowed


def test_require_receipt_observe_mode_runs_and_annotates():
    with StubGateway(lambda p: (200, {"decision": "allow"})) as stub:
        result = _receipted(stub, mode="observe").check("pay_invoice", _ALLOW_ARGS)
    assert result.allowed
    assert "without an acceptable signed receipt" in result.advisory_note


def test_receipt_alone_exposes_without_enforcing():
    with StubGateway(lambda p: (200, {"decision": "allow"})) as stub:
        guard = make_guard(stub, receipt=True, check_version=False)
        result = guard.check("pay_invoice", _ALLOW_ARGS)
    assert result.allowed and result.receipt is None
    assert stub.requests[0]["path"].endswith("?receipt=true")


def test_certify_and_receipt_both_ride_the_query():
    with StubGateway(lambda p: (200, {"decision": "allow"})) as stub:
        make_guard(stub, receipt=True, certify=True, check_version=False).check("t", {})
    assert stub.requests[0]["path"] == "/gate/tool-call?certify=true&receipt=true"


def test_require_receipt_needs_the_public_key():
    with pytest.raises(ValueError, match="receipt_public_key"):
        ToolGuard(gate=OnyxGate("http://127.0.0.1:1"), require_receipt=True, check_version=False)

