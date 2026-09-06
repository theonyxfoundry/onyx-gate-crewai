# Onyx Gate for CrewAI

**A verifiable authorization gate for CrewAI tool calls.** Wrap a crew's tools
and every execution is decided by policy *before it runs* — outside the model,
in a separate process the agent cannot talk its way past. Denied calls never
execute; the agent receives the reason and re-plans. Every decision lands in a
hash-chained audit trail you can re-check offline, with an optional
machine-checkable proof of each decision attached.

No changes to CrewAI, no changes to your tools: the guard is a wrapper.

```python
from crewai import Agent
from onyx_gate_crewai import OnyxGate, ToolGuard, guard_tools

guard = ToolGuard(OnyxGate("http://127.0.0.1:8080"), agent="ap-clerk")

clerk = Agent(
    role="Accounts-payable clerk",
    goal="Settle the invoices that are due",
    backstory="…",
    tools=guard_tools([read_ledger, pay_invoice], guard=guard),  # ← the whole integration
)
```

## What it looks like

The [finance crew example](examples/finance_crew/) gives an agent a ledger and
a payment tool, under this policy (Cedar, an allowlist — anything unmatched is
denied by default):

```cedar
entity Agent::"ap-clerk" {} ;

// Reading the ledger is harmless — always permitted.
permit(principal, action == Action::"read_ledger", resource);

// Payments are permitted ONLY inside the mandate: an approved vendor AND
// at-or-under the autonomous cap. Anything outside needs a human.
permit(principal, action == Action::"pay_invoice", resource)
  when {
    resource.amount <= 5000 &&
    (resource.vendor == "globex" || resource.vendor == "initech")
  };
```

The agent is told to pay *every* invoice that is due. Two are inside the
mandate; the third is not. Real output (deterministic dry run, real gateway):

```text
[gate    0.5 ms] ALLOW pay_invoice {'vendor': 'initech', 'amount': 1250, 'invoice_id': 'INV-1041'}
Payment sent: $1250 to initech for INV-1041.

[gate    0.5 ms] ALLOW pay_invoice {'vendor': 'globex', 'amount': 4800, 'invoice_id': 'INV-1042'}
Payment sent: $4800 to globex for INV-1042.

[gate    0.5 ms] DENY  pay_invoice {'vendor': 'vandelay', 'amount': 12000, 'invoice_id': 'INV-1043'}
--- the agent sees ----------------------------------------
[Onyx Gate] DENIED — this tool call was blocked and did NOT execute.
  call:   pay_invoice(vendor='vandelay', amount=12000, invoice_id='INV-1043')
  reason: Denied — no permit policy matches (Cedar's default deny).
The gate's decision is final for this exact call. Do not retry it with the
same arguments; adjust the plan — use a permitted route, or report that this
step needs human approval.
-----------------------------------------------------------

Executed payments: initech ($1250), globex ($4800)
```

The $12,000 payment did not execute — not "the model chose not to": the tool
body was never entered. The deny message the agent reads names the exact call
and carries the policy's reason, which is what lets the agent recover sensibly
(report it for human approval) instead of thrashing.

## Why a gate outside the model

Prompted guardrails are advice; a strong model under a persuasive context can
rationalize its way around them. In our measured pilot on a seeded-mistake task
family, agents corrected course after a bare advisory verdict in 8% of flagged
runs, after a verdict *with the policy's reason* in 44% — and a hard block
corrected 100%, with the agents completing their tasks through permitted routes
(one task family, n=20 per arm, driver-model dependent; details at
[onyxfoundry.ai](https://onyxfoundry.ai)). That gradient is this integration's
design: enforce by default, always carry the reason, and keep the decision
outside the agent's process entirely.

## How it works

```
CrewAI agent ──picks tool──▶ OnyxGuardedTool ──POST /gate/tool-call──▶ Onyx gateway
                                   │                                    (policy engine,
                     allow ────────┤◀── {"decision", "explanation"} ──── audit trail)
                     runs the tool │
                     deny: returns the deny message as the observation —
                     the tool body never runs
```

Each call maps onto a Cedar authorization request:

| tool call part | Cedar request part |
| --- | --- |
| the guard's `agent` name | `principal` = `Agent::"ap-clerk"` |
| the tool's name | `action` = `Action::"pay_invoice"` |
| the call itself | `resource` = `Tool::"pay_invoice"` |
| each argument | a resource attribute — `resource.vendor`, `resource.amount`, … |
| guard-level `context={...}` | `context.env`, … |

Argument mapping is designed so **every argument reaches the policy**: strings,
booleans and 64-bit integers pass verbatim; floats and oversized integers are
sent as strings; nested structures are serialized to compact JSON so substring
(`like`) policies still see their content. Nothing is silently dropped or
truncated on the wire — a policy keyed on an argument the gate can't see would
fail open.

### Modes and failure behavior

| situation | `mode="enforce"` (default) | `mode="observe"` |
| --- | --- | --- |
| gate allows | tool runs | tool runs |
| gate denies | **blocked**; agent gets the reason | tool runs; a note naming the flagged call is appended |
| gateway unreachable / errors | **blocked** (fail-closed; `on_error="allow"` opts out, annotated) | tool runs, annotated |

Observe mode is for the pilot phase: nothing is blocked, but the gateway still
records every would-deny in the trail, so you can measure what enforcement
*would* do on real traffic before turning it on.

One guard = one agent identity. Wrap each crew agent's tools with a guard
carrying that agent's name, and the trail attributes every call correctly:

```python
researcher_tools = guard_tools([search, fetch], gate=gate, agent="researcher")
clerk_tools      = guard_tools([read_ledger, pay_invoice], gate=gate, agent="ap-clerk")
```

## The audit trail

Start the gateway with `--log` and every decision — allow and deny, with the
full call arguments — is appended to a hash-chained JSONL trail (each record
links the SHA-256 of the previous one). `eg_verify` re-checks the whole file
offline:

```text
$ eg_verify --audit-log trail.jsonl
  record   5  gate_tool_call   ✓ confirmed (1 step(s))
  record   6  gate_tool_call   ✓ confirmed (1 step(s))
  record   7  gate_tool_call   ✓ confirmed (1 step(s))
  record   8  gate_tool_call   ✓ confirmed (1 step(s))
re-checked 8 record(s): 4 confirmed, 0 failed, 4 without a certificate
chain: 8 linked, 0 unchained, 0 broken
% Onyx audit-log: Confirmed
```

Edit one byte of one record — say, quietly changing the denied `amount` — and
the re-check fails loudly:

```text
chain: recorded link 2ea6e5fe… does not match the expected 3c03da7e… —
       the record before this one was edited, deleted, or reordered
chain: 7 linked, 0 unchained, 1 broken
% Onyx audit-log: Failed
```

## Decision certificates

Pass `certify=True` (per guard or per call) and each decision comes back with a
certificate: a self-contained record of the policy reasoning behind that exact
verdict, which `eg_verify` re-checks **with the engine's small proof kernel
alone** — not by trusting the gateway that issued it. In the run above, the
certified decisions cost ~2–3 ms instead of ~0.5–1 ms (local loopback, single
client, Apple-silicon laptop). That is what "verifiable" means here: the audit
answer is not "the logs say so" but "re-derive it yourself, offline."

## Decision receipts — no receipt, no action

A gateway started with a decision key (`eg_gateway --receipt-key-file`) signs
every decision on request: a small **receipt** saying which request (by
canonical hash) was decided, which way, under which policy version, by which
engine, and when — verifiable by anyone holding the gateway's public key, which
it discloses on `GET /ready` as `receipt_key`. The gateway's hash-chained trail
commits each receipt by hash, so a receipt in hand can later be bound to the
exact record that recorded the decision (`eg_verify --audit-log … --receipt …`).

This package can make that binding a **precondition of execution** — the
effector-side rule:

```python
from onyx_gate_crewai import OnyxGate, ToolGuard, read_public_key

guard = ToolGuard(
    OnyxGate("http://127.0.0.1:8080"),
    agent="ap-clerk",
    require_receipt=True,
    receipt_public_key=read_public_key("gw.pub"),   # the gateway's .pub
)
```

With `require_receipt=True` a tool runs only when the gateway's allow came with
a receipt that (1) verifies under that key, (2) says `allow`, and (3) is for
exactly this call — the request hash is recomputed here from the body the
client sent, so a receipt for a different call, an edited receipt, a receipt
under a rotated key, or no receipt at all blocks the call even though the gate
said allow. That is deliberately *not* subject to `on_error="allow"`: a missing
receipt is not a transport hiccup, it is the absence of proof. `receipt=True`
alone asks for receipts and exposes them (`GateResult.receipt`) without
enforcing; keep them — each one names the trail record it can be checked
against. Verification is standard-library Python (the RFC 8032 algorithm,
about 3 ms per receipt) and is pinned in the tests against receipts a real
gateway signed, byte for byte with the engine's own canonical hashing.

## Try it

```bash
pip install "onyx-gate-crewai[crewai] @ git+https://github.com/theonyxfoundry/onyx-gate-crewai"
```

**Without the engine** — the test suite runs against a scripted stub gateway,
so you can see the integration shape immediately:

```bash
git clone https://github.com/theonyxfoundry/onyx-gate-crewai && cd onyx-gate-crewai
pip install -e '.[dev,crewai]' && pytest
```

**With the engine** (design-partner preview — see below):

```bash
eg_gateway --policies examples/finance_crew/policy.cedar --log trail.jsonl &
python examples/finance_crew/dry_run.py            # deterministic, no LLM key needed
python examples/finance_crew/crew.py               # the live crew (any CrewAI-supported LLM)
eg_verify --audit-log trail.jsonl                  # re-check the trail offline
```

### Policy tips

- Prefer the **allowlist** style shown above (`permit … when { … }`, no
  catch-all permit). A permit whose condition errors — e.g. a required
  argument is missing — simply doesn't match, so the call is denied:
  fail-closed. A blocklist (`permit(principal, action, resource);` plus
  `forbid`s) is easy to start with but a `forbid unless { … }` whose condition
  errors *skips the forbid* — fail-open. Reach for `forbid` when you want a
  rule no permit can override.
- Policies can also key on tool taxonomies (`action in ActionGroup::"…"` via
  the gateway's `--action-groups`), resource hierarchies (`resource_parents`),
  and per-guard `context` fields.

## Scope, honestly

- **This is an authorization boundary, not a sandbox.** The guard governs the
  *agent's tool calls* in-process. It does not contain a malicious tool
  implementation, and code that bypasses the wrapped tools bypasses the guard.
  Pair it with OS-level sandboxing where that threat matters. (The same engine
  also ships an enforcing PreToolUse hook for Claude Code, which blocks at the
  harness rather than in-process.)
- **The gateway decides; it never executes.** Onyx holds no keys and moves no
  funds — it answers allow/deny and proves its answers.
- Certificates are **kernel-re-checkable records of the policy reasoning** —
  re-derivable by an independent checker; they are not digital signatures, and
  the trail's hash chain detects edits, not deletion of the whole file
  (anchor the chain head externally for that).
- Latency figures above are measured on the example, not a benchmark suite.

## Getting the gateway

The wire protocol is fully documented here and stubbed in
[`tests/stub_gateway.py`](tests/stub_gateway.py); this package is Apache-2.0
and yours to use. The gateway binary (`eg_gateway`) and offline checker
(`eg_verify`) are part of the **Onyx engine** — a verification-first policy
engine whose decision calculus is machine-checked in two independent proof
assistants — currently in design-partner preview.

Running agents that touch money, records, or customers, and want the pilot
shape you saw above (observe mode → measured would-denies → enforcement, with
a re-checkable trail)? **contact@onyxfoundry.ai** · [onyxfoundry.ai](https://onyxfoundry.ai)

## Supported gateway versions

This client was written against Onyx gateways **≥ 0.2.0 and < 1.0.0** — the Onyx
*product* version, which the gateway reports as `server.version` on `GET /ready`
(since 0.2.0). The HTTP paths it speaks are stable, so this is a *soft* check:
when a guard is built it reads the gateway's version once and emits a
`RuntimeWarning` outside that range — never a refusal — so the two can be
upgraded together. `ToolGuard(..., check_version=False)` skips the startup
request; a gateway older than 0.2.0 reports no version and is treated as
unknown (silent). `OnyxGate.server_info()` returns the block for your own logs.
Receipts need a gateway with the receipts lane (after Onyx 0.3.1) started with
a decision key — `receipt_key` on `GET /ready` shows whether it is on; a gateway
without one answers `?receipt=true` with a plain decision, which
`require_receipt=True` then refuses.

## License

[Apache-2.0](LICENSE). CrewAI is a trademark of its respective owner; this is
an independent integration, not affiliated with or endorsed by CrewAI.
