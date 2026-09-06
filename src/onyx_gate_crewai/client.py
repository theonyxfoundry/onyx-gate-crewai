"""HTTP client for the Onyx gateway's tool-call decision endpoint.

Standard library only (``urllib``) — the client adds no dependencies to the
agent stack it guards.

The wire contract (``POST /gate/tool-call``)::

    {
      "agent": "ap-clerk",                  # -> principal Agent::"ap-clerk"
      "tool": "pay_invoice",                # -> action    Action::"pay_invoice"
      "resource": "Tool::\"pay_invoice\"",  # entity uid string
      "resource_attrs": {"vendor": "globex", "amount": 4800},
      "resource_parents": [],
      "context": {}
    }

Response::

    {"decision": "allow" | "deny",
     "explanation": "...",        # only on deny
     "certificate": {...},        # only with ?certify=true, best-effort
     "policy_version": "...",
     "receipt": {...}}            # only with ?receipt=true, when the gateway holds a
                                  # decision key — a signed per-decision receipt
                                  # (see :mod:`.receipt`)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT = 5.0

# The Onyx gateway versions this client was written against. The gateway reports
# its PRODUCT version as ``server.version`` on ``GET /ready`` (since Onyx 0.2.0).
# The HTTP paths this client speaks are stable, so the check is SOFT: outside the
# range a guard warns once at construction and keeps working — never a refusal.
SUPPORTED_GATEWAY_MIN = (0, 2, 0)
SUPPORTED_GATEWAY_BELOW = (1, 0, 0)


def _parse_version(text: str) -> Optional[tuple[int, int, int]]:
    """``"0.3.0"`` → ``(0, 3, 0)``; pre-release / build suffixes ignored; ``None`` if unparseable."""
    core = text.split("+", 1)[0].split("-", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return (int(parts[0]), int(parts[1]), int(parts[2]))

# Cedar Long is a signed 64-bit integer; anything outside is not representable.
I64_MIN = -(2**63)
I64_MAX = 2**63 - 1


class OnyxGateError(Exception):
    """The gateway could not be reached or refused the request.

    The guard layer treats this as a *deny* by default (fail-closed): an
    unreachable or erroring gate must never silently wave a call through.
    """


@dataclass(frozen=True)
class GateDecision:
    """One authorization decision returned by the gateway."""

    decision: str
    explanation: Optional[str] = None
    certificate: Optional[dict] = None
    policy_version: Optional[str] = None
    #: The signed per-decision receipt, when requested and issued (``?receipt=true``).
    receipt: Optional[dict] = None
    #: The request body exactly as sent — what a receipt's ``request_sha256`` is over.
    request: dict = field(default_factory=dict, repr=False)
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


def _validate_uid_part(label: str, value: str) -> str:
    """Refuse strings that cannot be safely embedded in a Cedar entity uid.

    The ``resource`` field is an entity uid *string* (``Tool::"pay_invoice"``)
    assembled client-side, so a quote or backslash in a tool name could change
    what the server parses. We refuse rather than escape: a tool name that
    needs escaping is not a name this integration produces, and refusal is
    fail-closed (the guard turns the raised error into a deny).
    """
    if not value:
        raise OnyxGateError(f"{label} must be non-empty")
    if '"' in value or "\\" in value or "\n" in value or "\r" in value:
        raise OnyxGateError(f"{label} contains characters not allowed in an entity id: {value!r}")
    return value


class OnyxGate:
    """A client for one running Onyx gateway.

    Args:
        url: base URL of the gateway (default ``http://127.0.0.1:8080``).
        api_key: bearer key for the decision surface. Falls back to the
            ``ONYX_GATE_API_KEY`` environment variable. Unset is fine for a
            loopback gateway, which is the default deployment.
        timeout: per-request timeout in seconds. On timeout the client raises
            :class:`OnyxGateError`, which the guard treats as a deny.
    """

    def __init__(
        self,
        url: str = DEFAULT_URL,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ONYX_GATE_API_KEY")
        self.timeout = timeout

    # -- HTTP plumbing ---------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.url + path,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self.api_key:
            req.add_header("Authorization", f"Bearer {self.api_key}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:500]
            except Exception:
                pass
            raise OnyxGateError(f"gateway returned HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise OnyxGateError(f"gateway unreachable at {self.url}: {e.reason}") from e
        except (TimeoutError, OSError, ValueError) as e:
            raise OnyxGateError(f"gateway request failed: {e}") from e

    # -- API -------------------------------------------------------------

    # -- gateway version (a soft startup check) ----------------------------

    def server_info(self) -> Optional[dict]:
        """The gateway's identity from ``GET /ready`` — ``{"name", "version",
        "commit"}`` — or ``None`` when it is unreachable or predates Onyx 0.2.0
        (which introduced the ``server`` block)."""
        try:
            req = urllib.request.Request(self.url + "/ready")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return None
        server = body.get("server") if isinstance(body, dict) else None
        return server if isinstance(server, dict) else None

    def gateway_version_warning(self) -> Optional[str]:
        """One line when the gateway reports a product version outside
        ``SUPPORTED_GATEWAY_MIN``..``SUPPORTED_GATEWAY_BELOW``; ``None`` when in
        range, unknown, or unreachable. Decisions keep working either way."""
        info = self.server_info()
        if not info:
            return None
        version = str(info.get("version", ""))
        parsed = _parse_version(version)
        if parsed is None or SUPPORTED_GATEWAY_MIN <= parsed < SUPPORTED_GATEWAY_BELOW:
            return None
        lo = ".".join(map(str, SUPPORTED_GATEWAY_MIN))
        hi = ".".join(map(str, SUPPORTED_GATEWAY_BELOW))
        return (
            f"onyx-gate-crewai: the gateway at {self.url} reports Onyx {version} "
            f"({info.get('name', 'eg_gateway')}); this client was written against "
            f">={lo},<{hi}. Decisions still work over the stable HTTP paths, but "
            "upgrade the client or the gateway so the two are tested together."
        )

    def warn_if_unsupported(self) -> Optional[str]:
        """Emit :meth:`gateway_version_warning` as a :class:`RuntimeWarning`; returns it."""
        message = self.gateway_version_warning()
        if message:
            warnings.warn(message, RuntimeWarning, stacklevel=2)
        return message

    def health(self) -> bool:
        """True iff the gateway answers its ``/health`` endpoint."""
        try:
            req = urllib.request.Request(self.url + "/health")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def gate_tool_call(
        self,
        agent: str,
        tool: str,
        resource: Optional[str] = None,
        resource_attrs: Optional[dict[str, Any]] = None,
        resource_parents: Optional[list[str]] = None,
        context: Optional[dict[str, Any]] = None,
        certify: bool = False,
        receipt: bool = False,
    ) -> GateDecision:
        """Decide one tool call. Raises :class:`OnyxGateError` on any failure.

        ``receipt=True`` asks the gateway to sign the decision (``?receipt=true``);
        the receipt comes back as :attr:`GateDecision.receipt` when the gateway
        holds a decision key, else ``None`` — the decision itself is unaffected.
        """
        _validate_uid_part("agent", agent)
        _validate_uid_part("tool", tool)
        if resource is None:
            resource = f'Tool::"{tool}"'
        payload: dict[str, Any] = {
            "agent": agent,
            "tool": tool,
            "resource": resource,
        }
        if resource_attrs:
            payload["resource_attrs"] = resource_attrs
        if resource_parents:
            payload["resource_parents"] = resource_parents
        if context:
            payload["context"] = context
        path = "/gate/tool-call"
        query = [flag for flag, wanted in (("certify=true", certify), ("receipt=true", receipt)) if wanted]
        if query:
            path += "?" + "&".join(query)
        raw = self._post(path, payload)
        decision = raw.get("decision")
        if decision not in ("allow", "deny"):
            raise OnyxGateError(f"gateway returned an unrecognized decision: {raw!r}")
        return GateDecision(
            decision=decision,
            explanation=raw.get("explanation"),
            certificate=raw.get("certificate"),
            policy_version=raw.get("policy_version"),
            receipt=raw.get("receipt") if isinstance(raw.get("receipt"), dict) else None,
            request=payload,
            raw=raw,
        )
