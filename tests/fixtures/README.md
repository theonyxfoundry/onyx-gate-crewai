# Real-engine receipt fixtures

Produced 2026-09-06 by a real `eg_gateway` (Onyx 0.3.1 + the receipts lane) started
with `--receipt-key-file` over `policy.cedar`, deciding `request_allow.json` and
`request_deny.json` via `POST /gate/tool-call?receipt=true`; `response_*.json` are
the gateway's responses (each carrying its signed `receipt`), `gw.pub` the
gateway's public decision key (`receipt_key.public_key` on `GET /ready`, kid
f99d4a66d0a5bda8), and `trail.jsonl` the two hash-chained records that commit
the receipts by `result.receipt_sha256`. The tests pin this package's pure-Python
canonical hashing and Ed25519 verification against the engine's signer byte for
byte. The private key was generated for the fixture and discarded.
