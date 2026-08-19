# Phase 10 — Final Integration Hardening

Phase 10 does **not** create authority, persistent artifacts, or
production orchestration. It hardens the Phase 9 integration contract
with additional assertions over existing 8F `gate` / `orchestrate`.

```text
7A–8F existing authorities
        ↓
Phase 9 integration contract
        ↓
Phase 10 hardening (assert / observe / validate / reject / document)
```

There is no `tools/phase10_*.py`. Tests call existing 8F APIs with
synthetic JSON and injected 7B/7C fakes.

Phase 10 does not modify Phases 7A–9.

## Phase 9 findings adjudication

Phase 9 audit: **PASS WITH FINDINGS**. BLOCKERS: none. All findings
RECORD-ONLY. Phase 9 is READY FOR COMMIT and is not retouched here.

| # | Finding | Action in Phase 10 |
|---|---------|--------------------|
| 1 | ARM/Thumb reverse copy weakly asserted | same-address independence tests |
| 2 | 8A matching success untested | 8A overlay A/B/C/D |
| 3 | 8E conflict untested | observe 8F `conflicting-verification` |
| 4 | persistence paths not observed | in-memory / temp / no-import checks (no real writes) |
| 5 | happy path lacked `invoked` / peel-emitted asserts | execution contract |
| 6 | Phase 9 docs omitted 8A overlay | documented here, not in Phase 9 docs |

## Authority table

| Concern | Authority | Phase 10 |
|---------|-----------|----------|
| CandidateKey | `(int address, mode)` | identity assert |
| selection | 7A `selected` | read-only |
| peel-ready | 7A `disposition == peel-ready` | read-only |
| explicit end | 8B human EndMap | read-only |
| encoding_verified | 8E v1 + `deterministic=true` | read-only |
| gate | 8F | observed |
| peel | 7B | fake observer |
| RANGE | 7C | fake observer |

```text
Phase 10 ≠ selection / eligibility / end / encoding / peel / RANGE
```

## CandidateKey

Identity is `(address, mode)` only. Address-only lookup, mode inference,
winner selection, candidate mint, and cross-mode copy are forbidden.
`(0x08001200, arm)` and `(0x08001200, thumb)` are independent.

## ARM / Thumb independence

Same address, opposite verification or opposite EndMap: one side may be
ready; the other must fail. ARM end must not fill Thumb end, and reverse.

## 8A overlay

- **Absent** + authoritative conjunction → ready
- **Present + matching** `eligible-for-peel` → ready
- **Present + mismatch** → `eligibility-mismatch`, no 7B
- **eligible-for-peel alone** (disposition ≠ peel-ready) → no 7B

8A does not manufacture selected, peel-ready, end, or encoding_verified.

## 8E conflict

Same CandidateKey with `encoding_verified=true` and `false` is
fail-closed (`conflicting-verification`). Phase 10 does not arbitrate
(first/last/true/false wins). It only observes existing 8F.

## Conjunction

Ready only when all hold:

- `selection == selected`
- `disposition == peel-ready`
- valid 8B EndMap for that CandidateKey
- valid 8E artifact, matching key, `encoding_verified == true`

Every partial combination is not ready. 8C / 8D / human claim artifacts
are not encoding verification.

## 7B / 7C sequencing

```text
gate = ready
    → 7B invoked
    → fake result peel-emitted
    → 7C invoked
```

Happy-path tests assert `invoked.peel`, `invoked.check`, recorded
CandidateKey, and `peel-emitted`. Fakes are observers only.

Phase 10 does not emit `range_verified`. Existing 7C remains the only
RANGE authority; Phase 10 does not run it.

## Failure propagation

- gate failure → no 7B, no 7C
- 7B failure → no 7C, final failure
- 7C failure → final failure

No retry, fallback, inference, promotion, or success conversion.

## Persistence

No new artifact. Tests use in-memory fixtures. No writes to Evidence,
FrontierStore, labels.toml, or gamedb. 7A / 8B / 8E / 8A JSON are
unmodified by the call.

## Security

Phase 10 tests: no real ROM, LLM, Ghidra, network, git, shell, real
peel, or real RANGE. No subprocess.

## Test coverage

`tests/test_phase10_hardening.py`:

- same-address ARM/Thumb (verified / end axes, both directions)
- 8A absent / matching / mismatch / eligible-for-peel-not-peel-ready
- 8E conflict both record orders
- happy-path execution contract
- gate / 7B / 7C failure propagation
- conjunction matrix of partial conditions
- 8C / 8D / human-claim rejection
- in-memory persistence and import boundary
