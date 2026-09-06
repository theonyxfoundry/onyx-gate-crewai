"""Framework-agnostic tool-call guard.

This module holds everything that is *not* CrewAI-specific: how a tool call is
mapped onto a gateway request, the enforce/observe modes, the fail-closed error
handling, and the exact wording the agent sees on a deny. The CrewAI adapter
(:mod:`onyx_gate_crewai.crew`) is a thin wrapper over :class:`ToolGuard`, and an
adapter for any other framework (LangChain, AutoGen, a bare tool loop) would
call the same ``check`` method.

Design notes, all deliberate:

* **Fail-closed by default.** If the gateway is unreachable, times out, or
  errors, an *enforcing* guard denies the call. A guard that fails open is a
  decoration, not a control. ``on_error="allow"`` exists for explicitly
  advisory deployments and says so in the note it attaches.

* **The deny message names the call and carries the reason.** A note that
  doesn't say *which* call was flagged gets misattributed by the agent, and a
  bare verdict without the policy's reason is frequently rationalized away.
  Both message parts are load-bearing.

* **Every argument reaches the policy.** Scalar tool arguments become resource
  attributes verbatim; non-scalar arguments are serialized to compact JSON
  strings rather than dropped, so a ``like`` pattern can still match content
  nested inside them. Dropping an argument silently would let a policy keyed
  on it fail open.

* **No receipt, no action (opt-in).** With ``require_receipt=True`` and the
  gateway's public decision key, an enforcing guard runs a tool only when the
  gateway's allow came with a signed receipt that verifies under that key and
  is for exactly this call (:mod:`.receipt`). A missing or unacceptable receipt
  blocks the call even though the gate said allow — it is not a transport
  error, so ``on_error="allow"`` does not apply: the effector holds proof, or
  it does not act.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from .client import I64_MAX, I64_MIN, GateDecision, OnyxGate, OnyxGateError
from .receipt import ReceiptError, request_sha256_of_payload, require_receipt

MODE_ENFORCE = "enforce"
MODE_OBSERVE = "observe"

# Truncation applies only to the human/agent-facing call descriptor, never to
# the attribute values sent to the gateway (truncating those could hide a
# blocklisted substring from the policy — a fail-open).
_DESCRIPTOR_VALUE_LIMIT = 120


def scalarize_args(args: Mapping[str, Any]) -> dict[str, Any]:
    """Map tool arguments onto the gateway's single-level attribute floor.

    * ``str`` / ``bool`` stay themselves.
    * ``int`` stays an integer when it fits Cedar's signed 64-bit ``Long``;
      outside that range it is sent as its decimal string (documented, and a
      policy comparing ``Long`` bounds will then not match it — the permit-when
      allowlist style keeps that fail-closed).
    * ``float`` is sent as its ``repr`` string — Cedar has no float type, and
      silently rounding to an integer would change what a ``>`` cap means.
    * ``None`` values are omitted (an absent attribute; in the permit-when
      allowlist style an absent required attribute fails closed).
    * anything else (dict, list, objects) is serialized to compact JSON so
      substring (``like``) policies still see the content.
    """
    out: dict[str, Any] = {}
    for key, value in args.items():
        if value is None:
            continue
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, int):
            out[key] = value if I64_MIN <= value <= I64_MAX else str(value)
        elif isinstance(value, float):
            out[key] = repr(value)
        elif isinstance(value, str):
            out[key] = value
        else:
            try:
                out[key] = json.dumps(value, separators=(",", ":"), default=str)
            except (TypeError, ValueError):
                out[key] = str(value)
    return out


def describe_call(tool_name: str, args: Mapping[str, Any]) -> str:
    """A compact, unambiguous descriptor of the flagged call for messages."""
    parts = []
    for key, value in args.items():
        text = repr(value)
        if len(text) > _DESCRIPTOR_VALUE_LIMIT:
            text = text[:_DESCRIPTOR_VALUE_LIMIT] + "…"
        parts.append(f"{key}={text}")
    return f"{tool_name}({', '.join(parts)})"


@dataclass(frozen=True)
class GateResult:
    """The guard's ruling on one tool call.

    ``allowed`` says whether the tool body may run. ``blocked_message`` is the
    string to return to the agent instead of a result when blocked.
    ``advisory_note`` is a note to append to the result when the call ran but
    the gate (or a gate error) has something the agent must see.
    """

    allowed: bool
    blocked_message: Optional[str] = None
    advisory_note: Optional[str] = None
    decision: Optional[GateDecision] = None
    error: Optional[str] = None
    #: The gateway's signed receipt for this decision, when one was issued —
    #: keep it: it binds this call to the gateway's audit trail later.
    receipt: Optional[dict] = None


class ToolGuard:
    """Decides tool calls for one agent identity against one gateway.

    Args:
        gate: the :class:`OnyxGate` client (or ``None`` to build a default
            loopback client).
        agent: the agent identity presented as the Cedar principal
            (``Agent::"<agent>"``). Wrap each crew agent's tools with that
            agent's name so the trail attributes calls correctly.
        mode: ``"enforce"`` blocks denied calls before they execute (default);
            ``"observe"`` never blocks, but appends an advisory note naming the
            flagged call — the gateway still records the real decision in its
            trail either way.
        on_error: what an *enforcing* guard does when the gateway cannot decide
            (unreachable, timeout, malformed request): ``"deny"`` (default,
            fail-closed) or ``"allow"`` (fail-open, honestly annotated).
        context: static per-guard context fields sent with every call
            (e.g. ``{"env": "prod"}``), readable by policies as
            ``context.<name>``.
        certify: request a kernel-re-checkable certificate with each decision
            (best-effort on the gateway side; adds prover latency, off by
            default).
        resource_type: entity type for the synthesized per-call resource uid
            (default ``Tool`` — policies match ``resource == Tool::"name"``
            or, more commonly, key on ``action == Action::"name"``).
        receipt: ask the gateway to sign each decision (``?receipt=true``) and
            expose it as :attr:`GateResult.receipt` — without enforcing it.
        require_receipt: the effector-side rule — an enforcing guard runs a tool
            only when the allow came with a receipt that verifies under
            ``receipt_public_key`` and is for exactly this call; in observe
            mode a missing/unacceptable receipt is an advisory note. Implies
            ``receipt``. Not subject to ``on_error`` (see the module notes).
        receipt_public_key: the gateway's public decision key, hex — the
            ``receipt_key.public_key`` value on its ``GET /ready``, or the
            ``.pub`` of its ``--receipt-key-file`` pair (see
            :func:`~.receipt.read_public_key`). Required with ``require_receipt``.
        receipt_max_age_s: refuse receipts older than this many seconds
            (hygiene, not replay protection — ordering comes from the trail).
    """

    def __init__(
        self,
        gate: Optional[OnyxGate] = None,
        agent: str = "crew",
        mode: str = MODE_ENFORCE,
        on_error: str = "deny",
        context: Optional[dict[str, Any]] = None,
        certify: bool = False,
        resource_type: str = "Tool",
        check_version: bool = True,
        receipt: bool = False,
        require_receipt: bool = False,
        receipt_public_key: Optional[str] = None,
        receipt_max_age_s: Optional[float] = None,
    ) -> None:
        if mode not in (MODE_ENFORCE, MODE_OBSERVE):
            raise ValueError(f"mode must be 'enforce' or 'observe', got {mode!r}")
        if on_error not in ("deny", "allow"):
            raise ValueError(f"on_error must be 'deny' or 'allow', got {on_error!r}")
        if require_receipt and not receipt_public_key:
            raise ValueError("require_receipt=True needs receipt_public_key (the gateway's public decision key)")
        self.receipt = receipt or require_receipt
        self.require_receipt = require_receipt
        self.receipt_public_key = receipt_public_key
        self.receipt_max_age_s = receipt_max_age_s
        self.gate = gate if gate is not None else OnyxGate()
        self.agent = agent
        self.mode = mode
        self.on_error = on_error
        self.context = dict(context) if context else None
        self.certify = certify
        self.resource_type = resource_type
        if check_version:
            # Startup only, and never a refusal: a version skew is a RuntimeWarning
            # (the gateway's product version from GET /ready vs this client's range).
            self.gate.warn_if_unsupported()

    # -- messages --------------------------------------------------------

    def _deny_message(self, descriptor: str, reason: Optional[str]) -> str:
        why = reason or "denied by policy (no further detail available)"
        return (
            "[Onyx Gate] DENIED — this tool call was blocked and did NOT execute.\n"
            f"  call:   {descriptor}\n"
            f"  reason: {why}\n"
            "The gate's decision is final for this exact call. Do not retry it with "
            "the same arguments; adjust the plan — use a permitted route, or report "
            "that this step needs human approval."
        )

    def _error_deny_message(self, descriptor: str, error: str) -> str:
        return (
            "[Onyx Gate] DENIED (fail-closed) — the authorization gateway could not "
            "decide this call, so it was blocked and did NOT execute.\n"
            f"  call:  {descriptor}\n"
            f"  error: {error}\n"
            "This is an infrastructure condition, not a policy verdict. Report it; "
            "do not work around the gate."
        )

    def _receipt_deny_message(self, descriptor: str, error: str) -> str:
        return (
            "[Onyx Gate] DENIED (no valid receipt) — the gateway allowed this call but "
            "did not prove it: this guard requires a signed decision receipt before a "
            "tool runs, and none could be accepted, so the call did NOT execute.\n"
            f"  call:    {descriptor}\n"
            f"  receipt: {error}\n"
            "This is an infrastructure condition (a gateway without a receipt key, a "
            "rotated key, or a receipt for another request), not a policy verdict. "
            "Report it; do not work around the gate."
        )

    def _receipt_note(self, descriptor: str, error: str) -> str:
        return (
            f"[Onyx Gate advisory] The call {descriptor} executed, but the gateway's "
            "allow came without an acceptable signed receipt — in enforcing mode it "
            f"would have been blocked.\n  receipt: {error}"
        )

    def _observe_note(self, descriptor: str, reason: Optional[str]) -> str:
        why = reason or "denied by policy (no further detail available)"
        return (
            f"[Onyx Gate advisory] The call {descriptor} — this specific call, which "
            "did execute above — would have been DENIED by policy in enforcing "
            f"mode.\n  reason: {why}\n"
            "Treat its result accordingly and flag this step for review."
        )

    # -- the decision ----------------------------------------------------

    def check(self, tool_name: str, args: Mapping[str, Any]) -> GateResult:
        """Decide one call. Never raises — errors become fail-closed results."""
        descriptor = describe_call(tool_name, args)
        try:
            decision = self.gate.gate_tool_call(
                agent=self.agent,
                tool=tool_name,
                resource=f'{self.resource_type}::"{tool_name}"',
                resource_attrs=scalarize_args(args),
                context=self.context,
                certify=self.certify,
                receipt=self.receipt,
            )
        except OnyxGateError as e:
            if self.mode == MODE_OBSERVE:
                return GateResult(
                    allowed=True,
                    advisory_note=(
                        f"[Onyx Gate advisory] The gateway could not decide the call "
                        f"{descriptor} (it executed anyway — observe mode): {e}"
                    ),
                    error=str(e),
                )
            if self.on_error == "allow":
                return GateResult(
                    allowed=True,
                    advisory_note=(
                        f"[Onyx Gate advisory] The gateway could not decide the call "
                        f"{descriptor}; it was allowed to run because this guard is "
                        f"configured fail-open (on_error='allow'): {e}"
                    ),
                    error=str(e),
                )
            return GateResult(
                allowed=False,
                blocked_message=self._error_deny_message(descriptor, str(e)),
                error=str(e),
            )

        if decision.allowed:
            if self.require_receipt:
                # The effector-side rule: proof of THIS allow, for THIS call, under
                # the key we trust — or the tool does not run. Never fail-open here.
                try:
                    require_receipt(
                        decision.receipt,
                        self.receipt_public_key or "",
                        decision="allow",
                        request_sha256=request_sha256_of_payload(decision.request),
                        max_age_s=self.receipt_max_age_s,
                    )
                except ReceiptError as e:
                    if self.mode == MODE_OBSERVE:
                        return GateResult(
                            allowed=True,
                            advisory_note=self._receipt_note(descriptor, str(e)),
                            decision=decision,
                            receipt=decision.receipt,
                        )
                    return GateResult(
                        allowed=False,
                        blocked_message=self._receipt_deny_message(descriptor, str(e)),
                        decision=decision,
                        error=f"receipt: {e}",
                        receipt=decision.receipt,
                    )
            return GateResult(allowed=True, decision=decision, receipt=decision.receipt)

        if self.mode == MODE_OBSERVE:
            return GateResult(
                allowed=True,
                advisory_note=self._observe_note(descriptor, decision.explanation),
                decision=decision,
                receipt=decision.receipt,
            )
        return GateResult(
            allowed=False,
            blocked_message=self._deny_message(descriptor, decision.explanation),
            decision=decision,
            receipt=decision.receipt,
        )
