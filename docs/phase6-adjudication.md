# Phase 6: Candidate adjudication

Phase 6A is a **read-only** layer over reconciled frontier JSON. It
attaches a peel recommendation to each `CandidateKey`. It does not
verify, peel, or choose a winner.

```
disposition != status
agreement != verification
peel-ready != RANGE_VERIFIED
deterministic != verification
```

## Goal

From Phase 3–5 frontier-compatible JSON, compute for every
`(address, mode)`:

- `disposition` — one of `peel-ready`, `agreed-seed`, `heuristic`, `conflicted`
- `sources` — unique `evidence_items[].source` in insertion order
- `classes` — `control-flow` / `oracle-seed` / `heuristic` from types

Then sort candidates in peel **recommendation** order. Provenance is
unchanged. This is not RANGE_VERIFIED.

## CandidateKey

```
CandidateKey = (address, mode)
```

Address-only adjudication is forbidden. ARM and Thumb at one address
stay two candidates.

## Read-only adjudication

[tools/adjudicate.py](../tools/adjudicate.py) wraps
`EvidenceMerger` / `FrontierStore`. Insertion is only
`FrontierStore.add_candidate`. `_cands` is not written here.
`to_json()` reads `to_json_list()` and adds computed fields.

## Disposition

Exactly one per candidate, in this order of rules:

1. `conflicted` — same address has both `arm` and `thumb`
2. `peel-ready` — not conflicted, and a `control-flow` class is present
3. `agreed-seed` — not conflicted, no control-flow, two or more sources
4. `heuristic` — everything else

Examples:

- modeflow-only → `peel-ready`
- modeflow + ghidra, same key → `peel-ready`
- ghidra-only → `heuristic`
- gap-only → `heuristic`
- manual-seed-only → `heuristic`
- decomp-reference-only → `heuristic`
- ghidra ARM + modeflow Thumb → both `conflicted`

No winner. No numeric score. No `confidence`. No `status`.

## Classes

Computed from `type`. Types are not rewritten.

| class | types |
|---|---|
| `control-flow` | `bl-target`, `bx-target`, `vector-entry` with known `target_addr` and `target_mode` |
| `oracle-seed` | `ghidra-seed`, `decomp-reference` |
| `heuristic` | `gap`, `manual-seed` |

Unknown types stay on `evidence_items` and are omitted from `classes`.

**gap = heuristic.** It is not verified control-flow.

## sources

Insertion-order unique sources. Not a trust score. `agreement` is
observed when `len(sources) >= 2`; it is **not** a persisted field
and **not** verification.

## agreement != verification

modeflow + Ghidra on one key is agreement. Both can still be wrong.
RANGE_VERIFIED remains peel → `.incbin` → wire → `make check`.

## Conflict semantics

Dual-mode at one address: both candidates `conflicted`, both kept,
existing FrontierStore conflict strings kept. ARM is not preferred.
Thumb is not preferred. Listing order for the same address is `arm`
then `thumb` (display only).

## Ghidra = STATIC_ANALYSIS_ORACLE

```
type = ghidra-seed
source = ghidra
```

Ghidra-only is `heuristic` and `deterministic = false`. Ghidra does
not flip `deterministic`. Combined with modeflow control-flow on the
**same** key, disposition may be `peel-ready` because of the
modeflow item, not because Ghidra verified anything.

## Deterministic vs disposition

`deterministic` is unchanged Phase 3
`FrontierStore.to_json_list()` output. Adjudication does not
recompute it. `peel-ready` is a separate recommendation label.

## Unresolved

`unresolved` (indirect-branch, jump-table, …) is copied through. It
is not a candidate and gets no disposition.

## Serialization

```
{
  "candidates": [ { ...frontier fields..., disposition, sources, classes } ],
  "unresolved": [ ... ]
}
```

Forbidden keys: `status`, `range_verified`, `encoding_verified`,
`winner`, `confidence`, `score`.

Round-trip: re-ingest ignores computed fields; `evidence_items` stay.

## CLI

```
python3 tools/adjudicate.py INPUT [INPUT ...] [--output PATH]
```

No `--output` → stdout. Writes that JSON only. No labels.toml, no
sidecar, no gamedb. No ROM, Ghidra, or LLM.

## Out of scope / STOP

No RANGE_VERIFIED, ENCODING_VERIFIED, labels writer, sidecar writer,
gamedb, gba-recomp, map.js, Ghidra headless, LLM, peel wiring, winner
persistence, numeric scores, new provenance types.

Phase 7+ peel wiring is not this phase.

PHASE 6A STOPS HERE.
