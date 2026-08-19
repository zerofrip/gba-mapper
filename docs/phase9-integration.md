# Phase 9 — Integration / Invariant Validation

Phase 9 does **not** create authority. It validates the existing chain
offline, with synthetic JSON and injected 7B/7C fakes.

```text
7A selected + disposition peel-ready
  + 8B human EndMap
  + 8E encoding_verified == true
        ↓
     8F gate
        ↓
  existing 7B
        ↓
  existing 7C / RANGE
```

## Authority matrix

| Concern | Authority | Phase 9 |
|---------|-----------|---------|
| CandidateKey | `(int address, mode)` | identity check only |
| selection | 7A `selected` | read-only |
| peel-ready | 7A `disposition == peel-ready` | read-only |
| explicit end | 8B human EndMap | read-only |
| encoding_verified | 8E v1 + `deterministic=true` | read-only |
| gate | 8F | exercised, not rewritten |
| peel | existing 7B | fake runner only |
| RANGE | existing 7C | fake runner only |

```text
Phase 9 ≠ selection / eligibility / end / encoding / peel / RANGE
```

8C LLM, 8D claims, human encoding claims, and `eligible-for-peel` are
**not** verification or 7B authority.

## Conjunction

`gate: ready` only when all hold:

- `selection == selected`
- `disposition == peel-ready`
- valid human explicit end for that CandidateKey
- valid 8E artifact with matching `encoding_verified == true`

Alone, none of: selected, peel-ready, end, encoding_verified,
eligible-for-peel, 8D claim, LLM suggestion.

## ARM / Thumb

`(address, arm)` and `(address, thumb)` are independent. Ready, end, and
`encoding_verified` must not copy across modes.

## 8F → 7B → 7C

- 7B only after ready. Production flags: `write_labels=False`,
  `force_boundary=False`.
- 7C only after `peel-emitted`.
- 7B/7C failure propagates. No failure → success. Phase 9 does not
  emit `range_verified` or RANGE.

Default 8F CLI remains gate-only. Phase 9 tests pass injected fakes into
`phase8f_gate.orchestrate`.

## Failure

Fail-closed: missing/invalid end, missing/invalid 8E, not-selected,
not-peel-ready, CandidateKey/mode mismatch, 8F/7B/7C failure.
No inferred fallback authority.

## Security

Phase 9 tests:

- NO real LLM, Ghidra, proprietary ROM, network, git, shell
- NO real peel or RANGE
- 8E real ROM verification is **not** required

## Persistence

7A / 8B / 8E / 8F JSON are read-only in tests. No Evidence,
FrontierStore, labels.toml, or gamedb writes. No new persistent
authority artifact.

## Out of scope

Real ROM verification, real LLM, Ghidra, new decoder, new Evidence,
FrontierStore redesign, new selection/eligibility/end/RANGE algorithms,
7B/7C semantics changes, automatic production pipeline.

## Tests

`tests/test_phase9_integration.py` calls existing 8F APIs only.
There is no `tools/phase9_integration.py`.
