# Phase 7B: Peel execution adapter

Phase 7B invokes the existing `tools/peel.py` CLI for candidates
already selected by Phase 7A, using an **explicit** `[start, end)`.

It does **not** decide whether the end is correct.

```
peel-emitted != RANGE_VERIFIED
peel-failed != unresolved
peel recommendation != peel success
```

## Goal

```
Phase 6A adjudicate
        ↓
Phase 7A select_peel
        ↓
selected candidate
        ↓
Phase 7B adapter (explicit end required)
        ↓
python3 tools/peel.py --start START --end END --mode MODE --no-labels
```

7B is an orchestrator. It does not reimplement peeling, boundary
detection, or verification.

## Relationship to Phase 7A

7A chooses `selection=selected` for `disposition=peel-ready`.
7B executes **only** that list.

Never executed:

- 7A `skipped`
- `unresolved`
- `selection != selected`
- `disposition != peel-ready` (including `conflicted`)

Invalid selected rows become `not-executed` / `invalid-selection`.
The input is not repaired.

## Explicit end

End is an external input, keyed by CandidateKey `(address, mode)`:

```
{
  "0x08000100:arm": { "end": "0x08000180" }
}
```

Address-only keys such as `"0x08000100"` do **not** apply to ARM or
Thumb. The two modes stay independent. No winner.

If no explicit end exists:

```
result = not-executed
reason = missing-explicit-end
```

`peel.py` is not called.

## Why Ghidra size/end is not used

Ghidra remains a STATIC_ANALYSIS_ORACLE. Size, Ghidra end, next
mapped range, next frontier candidate, gap bounds, and
`boundary.recommendedEnd` are **not** automatic end sources in 7B.

Those may feed a future end-resolution phase. 7B must not invent end.

Candidate fields `end` / `size` / `recommendedEnd` are ignored.

## CandidateKey

Every result is `(address, mode)`. Dual-mode rows at one address
execute independently, each only with its own explicit end.

## peel.py adapter

`tools/run_peel.py` runs `peel.py` as a subprocess. It does not import
peel internals, reinterpret exit codes, or modify `peel.py`.

Default argv:

```
--start START --end END --mode MODE --no-labels
```

`--force-boundary` is passed **only** when the human requests it.
It does not establish RANGE verification.

`--write-labels` is an explicit opt-in. Default is `--no-labels`
because peel.py would otherwise append `labels.toml`. No Ghidra names
or adjudication data are written there.

ROM is not required at the adapter layer. Missing ROM/objdump is a
`peel-failed` execution result.

## Failure semantics

| peel.py exit | result |
|---|---|
| 0 | `peel-emitted` |
| non-zero (including 1, 2) | `peel-failed` |

`peel-failed` keeps address, mode, explicit end, and exit code.
It does not delete the candidate, move it to `unresolved`, change
disposition/Evidence, retry another end/mode, or mark verified.

Allowed result values: `peel-emitted`, `peel-failed`, `not-executed`.

Never: `verified`, `range-verified`, `encoding-verified`.

## Evidence

Execution state lives in the 7B wrapper only.

Do not add `peel-attempt`, `peel-emitted`, or `peel-failed` to
Evidence. Discovery provenance is unchanged.

## Verification boundary

Correct chain:

```
selected → peel-emitted → wire → make check
  → record_range_after_check → RANGE_VERIFIED
```

7B stops after `peel-emitted`. No `record_range_*`, no
`promote_encoding_verified`, no status/winner/score.

## CLI

```
python3 tools/run_peel.py INPUT --ends ENDS.json [--output PATH]
        [--peel PATH] [--force-boundary] [--write-labels]
```

No `--output` → stdout. Writes that JSON only.

## Out of scope / STOP

Phase 7C wiring / `make check` / RANGE, ENCODING promotion, LLM,
Ghidra execution, end inference, map.js, gamedb, gba-recomp,
automatic retry, automatic winner.

PHASE 7B STOPS HERE.
