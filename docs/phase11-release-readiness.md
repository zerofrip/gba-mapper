# Phase 11 — Final Release-Readiness Validation

Phase 11 is validation-only. It does **not** create, replace, infer,
promote, or rewrite any authority.

```text
7A selected + peel-ready
  + 8B human EndMap
  + 8E encoding_verified == true
        ↓
     8F gate
        ↓
  existing 7B (fake observer)
        ↓
  existing 7C (fake observer)
```

Phase 11 does not modify Phases 7A–10.

## Authority chain

| Concern | Authority | Phase 11 |
|---------|-----------|----------|
| CandidateKey | `(int address, mode)` | identity assert |
| selection | 7A `selected` | read-only |
| peel-ready | 7A `disposition == peel-ready` | read-only |
| explicit end | 8B human EndMap | read-only |
| encoding_verified | 8E v1 + `deterministic=true` | read-only |
| gate | 8F | observed |
| peel | 7B | fake observer |
| RANGE | 7C | fake observer |

```
Phase 11 ≠ selection / eligibility / end / encoding / peel / RANGE
```

## CandidateKey identity

`(int address, mode)` — canonical through 7A → 8B → 8E → 8F → 7B → 7C.
Address-only, mode inference, winner, and cross-mode copy are forbidden.
`(0x08001200, arm)` and `(0x08001200, thumb)` are independent keys.

## Synthetic happy path

All four conditions must hold:

- `selection == selected`
- `disposition == peel-ready`
- valid 8B EndMap for the CandidateKey
- valid 8E artifact: `format/version=1`, `deterministic=true`,
  matching key, `encoding_verified=true`

Only then is `gate: ready` emitted. Every partial combination is not
ready.

## Negative authority matrix

The following alone or in combination cannot produce ready:

- `eligible-for-peel` (overlay only; never substitutes for `peel-ready`)
- 8D claim
- 8C suggestion
- human encoding claim
- `encoding_verified` without the other three conditions
- `peel-ready` without `selected`

## ARM / Thumb isolation

Same address: ARM end does not satisfy Thumb end requirement, and
reverse. Phase 11 tests both axes.

## 8E validation boundary

Phase 11 observes existing 8F `_index_8e` rejection:

- wrong format → `invalid-encoding-verification`
- wrong version → `invalid-encoding-verification`
- `deterministic=false` → `invalid-encoding-verification`

Phase 11 does not re-implement 8E parsing.

## 8F gate boundary

`phase8f_gate.gate` / `phase8f_gate.orchestrate` remain the sole
conjunction authority. Phase 11 does not duplicate gate logic.

## 7B / 7C sequencing

```text
gate = ready → 7B invoked (fake: returns peel-emitted) → 7C invoked
gate failure  → 7B NOT invoked
7B failure    → 7C NOT invoked
7C failure    → final failure
```

Fake runners are observers only; they record address/mode and inject
result strings. They do not implement peel or RANGE semantics.

## Output invariants

8F output must not contain: `winner`, `selection`, `disposition`,
`eligible-for-peel`, `peel-ready`, `end`, `encoding_verified`,
`range_verified`, `Evidence`, `FrontierStore`.

## Input immutability

Input JSON (7A, 8B, 8E, 8A) is byte-equivalent before and after the
call. Phase 11 does not write any authority store.

## Persistence boundary

No writes to Evidence, FrontierStore, labels.toml, or gamedb. No new
authority artifact. Temporary files are not used.

## Security boundary

Phase 11 tests:

- NO real ROM, LLM, Ghidra, network, git, shell
- NO real peel or RANGE
- NO subprocess

Injected fake 7B/7C are the only execution hooks.

## Explicit statements

- Phase 11 creates no authority.
- Phase 11 creates no persistent artifact.
- Phase 11 does not modify Phases 7A–10.
- Real ROM, LLM, Ghidra, peel, and RANGE are NOT run.
