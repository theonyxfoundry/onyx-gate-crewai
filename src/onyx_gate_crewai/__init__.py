"""Onyx Gate for CrewAI — a verifiable authorization gate for crew tool calls.

Core (no dependencies beyond the standard library):

* :class:`OnyxGate` — HTTP client for a running Onyx gateway.
* :class:`ToolGuard` — framework-agnostic per-agent guard (enforce/observe,
  fail-closed error handling, deny messages the agent can act on).
* :mod:`onyx_gate_crewai.receipt` — signed per-decision receipts: verify one
  under the gateway's public key, and :func:`require_receipt` before acting.

CrewAI adapter (requires ``crewai``; imported lazily):

* :func:`guard_tool` / :func:`guard_tools` — wrap tools so every execution is
  decided by the gateway before it runs.
"""

from .client import GateDecision, OnyxGate, OnyxGateError
from .guard import GateResult, ToolGuard
from .receipt import (
    ReceiptError,
    ReceiptInvalid,
    ReceiptMismatch,
    ReceiptMissing,
    read_public_key,
    request_sha256,
    require_receipt,
    verify_receipt,
)

__all__ = [
    "GateDecision",
    "GateResult",
    "OnyxGate",
    "OnyxGateError",
    "ReceiptError",
    "ReceiptInvalid",
    "ReceiptMismatch",
    "ReceiptMissing",
    "ToolGuard",
    "read_public_key",
    "request_sha256",
    "require_receipt",
    "verify_receipt",
    "guard_tool",
    "guard_tools",
    "OnyxGuardedTool",
]

__version__ = "0.3.0"


def __getattr__(name: str):
    # The CrewAI adapter is imported lazily so the core client/guard work in
    # environments without crewai installed (tests, other-framework adapters).
    if name in ("guard_tool", "guard_tools", "OnyxGuardedTool"):
        from . import crew

        return getattr(crew, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
