# epsilon-atl — Attestation Transparency Log

## What This Is
A Certificate Transparency-style append-only Merkle tree log for per-execution TEE attestation documents. Part of the Epsilon privacy-preserving research platform. Supports an IEEE TDSC 2026 paper.

## Language & Stack
- **Go 1.23+**
- **Merkle tree:** Tessera (transparency-dev/merkle) — tile-based, RFC 9162 compliant
- **Database:** PostgreSQL (entries + tree tiles + STHs)
- **Signing:** Ed25519 for STH signatures
- **Serialization:** CBOR (github.com/fxamacker/cbor/v2) — deterministic/canonical mode ALWAYS
- **HTTP:** stdlib net/http with Go 1.22+ routing
- **No frameworks** — keep dependencies minimal

## Project Structure
```
cmd/atl/main.go          — entry point (cobra CLI)
internal/
  merkle/                — Merkle tree (leaf hash, interior hash, proofs)
  entry/                 — ATL entry types (HA, LA, Config) + CBOR serialization
  store/                 — PostgreSQL backing store (entries, tiles, STHs)
  sth/                   — Signed Tree Head (signing, verification, heartbeat)
  api/                   — HTTP handlers (/v1/entries, /v1/sth, etc.)
  policy/                — Registration policy (attestation validation)
  receipt/               — SCITT-aligned inclusion receipts (COSE_Sign1)
  config/                — Configuration loading
```

## Key Constraints
1. **Deterministic CBOR** — ALL CBOR encoding uses canonical mode (sorted keys, shortest encoding). Identical entries MUST produce identical bytes.
2. **RFC 9162 hashing** — Leaf: `SHA-256(0x00 || entry_bytes)`, Interior: `SHA-256(0x01 || left || right)`
3. **Public GET endpoints** — No auth on any GET endpoint. Public verifiability is core.
4. **POST requires coordinator auth** — Verify coordinator Ed25519 signature on submissions.
5. **1-hour MMD** — Heartbeat STH every hour even if no new entries.
6. **This is NOT a blockchain** — Single operator + external monitors. Append-only log.

## Three Entry Types
- **HA (type=1):** High-Assurance — hardware-signed COSE_Sign1 attestation from Nitro enclave
- **LA (type=2):** Low-Assurance — coordinator-signed failure record
- **Config (type=3):** Key lifecycle events (creation, rotation, revocation)

## API Endpoints
| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/v1/entries` | Coordinator key | Submit entry |
| GET | `/v1/entries/{index}` | None | Get entry by index |
| GET | `/v1/entries/{index}/proof?tree_size=N` | None | Inclusion proof |
| GET | `/v1/sth` | None | Latest Signed Tree Head |
| GET | `/v1/sth/consistency?first=M&second=N` | None | Consistency proof |
| GET | `/v1/metadata` | None | Operator public key, MMD, policy |

## Testing
- Use RFC 9162 test vectors for Merkle tree correctness
- CBOR roundtrip tests for all entry types
- Integration tests: submit -> proof -> verify cycle
- `go test ./...` must pass before any commit

## DO NOT
- Do NOT use timestamps for security-critical freshness — use STH-derived nonces
- Do NOT store raw data in entries — only hashes
- Do NOT require auth on GET endpoints
- Do NOT implement blockchain semantics
- Do NOT add unnecessary dependencies

## Related Repos
- **Coordinator:** `/Users/nizzle1994/Developments/WebStorm/Epsilon/epsilon-cordinator` (Python, note typo in name)
- **Enclave:** `/Users/nizzle1994/Developments/WebStorm/Epsilon/epsilon-enclave` (Python)
- **SDK:** `/Users/nizzle1994/Developments/WebStorm/Epsilon/sdk-epsilon` (Python)
- **Design spec:** `/Users/nizzle1994/Developments/WebStorm/phd_milestone/papers/tdsc2026-atl/atl-design.md`
- **Paper LaTeX:** `/Users/nizzle1994/Developments/WebStorm/phd_milestone/papers/tdsc2026-atl/sections/atl-design.tex`
