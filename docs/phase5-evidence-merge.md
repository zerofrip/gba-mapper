# Phase 5: Evidence merge / reconciliation

Phase 5 unions frontier-compatible provenance on
`CandidateKey = (address, mode)`. It does not verify, accept, rank,
or peel anything.

```
agreement != verification
```

## Purpose

1. Merge multiple frontier JSON inputs on `(address, mode)`.
2. Keep every `Evidence` item across the merge (except exact
   `Evidence.key()` duplicates).
3. Make source agreement / ARM–Thumb conflict observable without
   choosing a winner.

Example, same key:

```
(0x08001200, thumb)
  bl-target / modeflow
  ghidra-seed / ghidra
```

Example, different mode — both keys kept, no winner:

```
(0x08001200, thumb)   modeflow
(0x08001200, arm)     ghidra
```

## CandidateKey

```
CandidateKey = (address, mode)
mode ∈ {"arm", "thumb"}
```

Address-only identity is forbidden. Merge never drops ARM or Thumb.

## Evidence union

Same key: append. Never overwrite. Never keep "the strongest" item.
Never prefer Ghidra or modeflow. Never collapse items into
`confirmed` / a single string.

Deduplicate only when `Evidence.key()` matches exactly.

`evidence_items` is authoritative. The human `evidence` string stays
as Phase 3 compatibility display (`FrontierStore.to_json_list()`).

No new evidence type is added. Active sources stay:

- `modeflow`
- `gap`
- `vector-entry`
- `decomp-reference`
- `manual-seed`
- `ghidra` (`type=ghidra-seed`, `source=ghidra`)

## Evidence.key dedupe

`Evidence.key()` is the full structural tuple from Phase 3, including
optional `insn`. Identical records merge to one; a second source with
a different type, `detail`, or `from_addr` is kept.

## Conflict handling

ARM and Thumb at one address remain two candidates. Existing
FrontierStore conflict strings are reused. Conflict is not rejection.
Phase 5 adds no priority / winner rule.

## ARM/Thumb separation

Ghidra ARM + modeflow Thumb is two candidates. The merger does not
decide which mode is correct.

## Ghidra unverified boundary

Ghidra is a STATIC_ANALYSIS_ORACLE.

```
type = ghidra-seed
source = ghidra
```

Ghidra function size/end/name/confidence are not RANGE_VERIFIED,
ENCODING_VERIFIED, labels identity, or a trust score. Adding
`ghidra-seed` does not flip `deterministic` to true.

## agreement != verification

`EvidenceMerger.sources(address, mode)` returns the observed source
set for a key. That is metadata, not:

- `confidence`
- `score`
- `verified`
- `accepted`
- `trusted`

It is a computed property. It is not a new persistent verification
field on the JSON schema.

## Deterministic semantics

Unchanged from Phase 3 `FrontierStore.to_json_list()`. True iff some
item is `bl-target` / `bx-target` / `vector-entry` with known
`target_addr` and `target_mode`. Ghidra-only and gap-only stay false.

## Unresolved handling

Input `unresolved` (for example `indirect-branch`, `jump-table`) is
copied with `FrontierStore.add_unresolved`. It is never converted
into a candidate. Phase 5 does not invent new static analysis.

## Existing-map handling

Mapped labels.toml ranges are input-only coverage in Phase 3. A dict
without `evidence_items` does not mint a candidate. Phase 5 does not
create an `existing-map` evidence type.

## Sidecar boundary

Merge output is frontier JSON (stdout or `--output`). It does not
write `*.evidence.jsonl`, `labels.toml`, or gamedb.

RANGE_VERIFIED remains: peel → `.incbin` → wire → `make check`.
ENCODING_VERIFIED remains `evidence.promote_encoding_verified` only.
Phase 5 calls neither.

## Serialization

```
{
  "candidates": [...],   # FrontierStore.to_json_list()
  "unresolved": [...]
}
```

Each candidate keeps `evidence` and `evidence_items`. Optional
Evidence fields (`from_addr`, `target_addr`, `source_mode`,
`target_mode`, `insn`) round-trip through `Evidence.from_json`.

Phase 1 sidecar JSONL is not a merge input; `Record.from_json`
without optional fields still loads. Phase 2/3/4 frontier objects
with `evidence_items` are valid merge inputs.

## Source lifecycle

Insertion path is only `FrontierStore.add_candidate(address, mode, evidence)`.
`FrontierStore._cands` is not written by this module.

CLI:

```
python3 tools/evidence_merge.py INPUT [INPUT ...] [--output PATH]
```

No `--output` → stdout.

## Limitations

- Does not run Ghidra, modeflow, or peel.
- Does not rank or accept candidates.
- `sources()` is not written into the JSON schema.
- Human `evidence` strings are not parsed back into items; missing
  `evidence_items` means no candidate.

## Explicitly out of scope

Ghidra headless / Java exporter, LLM, LLM confidence, candidate
ranking or scoring, automatic acceptance or rejection,
RANGE_VERIFIED, ENCODING_VERIFIED, labels.toml writer, gamedb,
gba-recomp, ROM SHA verification, assembler verification, peel
wiring, `workflows/map.js` integration, Phase 6.
