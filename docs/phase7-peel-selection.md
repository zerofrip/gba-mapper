# Phase 7A: Peel selection adapter

Phase 7A reads Phase 6A adjudicated frontier JSON and splits
candidates into `selected` / `skipped`. It does **not** peel, invent
`end`, run `make check`, or record RANGE_VERIFIED.

```
peel recommendation != peel success
peel success != make check success
make check success != RANGE_VERIFIED
```

## Goal

Default policy:

| disposition | selection | skip_reason |
|---|---|---|
| `peel-ready` | selected | — |
| `agreed-seed` | skipped | `no control-flow` |
| `heuristic` | skipped | `heuristic/oracle only` |
| `conflicted` | skipped | `dual-mode conflict` |

Ghidra-only and gap-only are `heuristic` and are **not** auto-selected.

## Boundary with Phase 6A

Phase 6A computes `disposition` / `sources` / `classes`.
Phase 7A only consumes those labels. It does not recompute
adjudication rules except by calling `Adjudicator` for multi-input
union (Phase 5 merge + Phase 6A annotate).

## CandidateKey

`(address, mode)`. Address-only merge is forbidden. Dual-mode
conflicted pairs stay two skipped rows. No winner.

## Conflict policy

Both ARM and Thumb at one address: both skipped, both kept,
`skip_reason = dual-mode conflict`.

## `--limit`

Caps **selected** count only. Extra `peel-ready` rows become skipped
with `skip_reason = selection-cap`.

This is not `frontier.py --max` (harvest cap). `--limit 0` selects
nothing. Negative values are rejected.

## Unresolved

Copied through unchanged. No `selection`. Not a candidate.

## end is not invented

Selected rows keep address, mode, provenance, disposition.
No `end` / `size` / `recommendedEnd`. Phase 7B obtains end later.

## selection != verification

`selection` is not `status`. Output forbids `status`,
`range_verified`, `encoding_verified`, `winner`, `confidence`,
`score`. `deterministic` is copied, not recomputed.
`peel-ready != deterministic`.

## CLI

```
python3 tools/select_peel.py INPUT [INPUT ...] [--limit N] [--output PATH]
```

No `--output` → stdout. Writes that JSON only. No labels.toml, sidecar,
gamedb, `asm/`. No ROM, objdump, peel.py, Ghidra, or LLM.

## Out of scope / STOP

Phase 7B peel execution, 7C `make check` / RANGE, 7D LLM, end
estimation, boundary estimation, Ghidra size→end, labels writer,
map.js, winner resolution, heuristic/agreed-seed auto-peel,
persistent selection queues.

PHASE 7A STOPS HERE.
