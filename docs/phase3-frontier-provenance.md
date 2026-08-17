# Phase 3: Frontier provenance

Phase 3 makes every frontier candidate attributable. Phase 2
`CandidateKey = (address, mode)` is unchanged. Evidence is not
verification. RANGE_VERIFIED still happens only after `make check`.

## CandidateKey

```
CandidateKey = (address, mode)
mode ∈ {"arm", "thumb"}
```

Address-only identity is forbidden. ARM and Thumb at the same address
are two candidates.

## Invariant

```
NO PROVENANCE = NO FRONTIER CANDIDATE
```

The only insertion path is `FrontierStore.add_candidate(address, mode, evidence)`
in `tools/frontier.py`. Empty evidence is a no-op. There is no
confidence score. The frontier never writes the evidence sidecar.

## FrontierStore

- `add_candidate(address, mode, evidence)` — `Evidence` or `list[Evidence]`
- `add_unresolved(edge_or_evidence)` — not a candidate
- `to_json_list()` — serialization; `evidence_items` is authoritative;
  the string `evidence` is compatibility-only

`build_frontier(rom_bytes, ranges, *, skips, sidecar_records, max_n)`
is the library entry. `main()` loads labels / skips / sidecar and
prints JSON.

## Evidence merge

Same `(address, mode)`: append. Never overwrite. Never collapse into
`"found"`. Deduplicate only when `Evidence.key()` matches exactly.

## Evidence.key deduplication

`Evidence.key()` is the full structural tuple, including optional
`insn`. Identical records merge to one; a second source with a
different type or `from_addr` is kept.

## ARM/Thumb conflict

Both keys stay. Each record lists a conflict string. Conflict is
**not** rejection.

## modeflow integration

`frontier.py` consumes `FlowEdge` from `tools/modeflow.py`. It does
not decode ARM/Thumb itself.

Known BL / known BX / vector-entry with a ROM target become
candidates (`deterministic: true`).

## Unknown BX / indirect branch

`target is None` → `add_unresolved`. Types: `indirect-branch`,
`jump-table`. No guessed function. Unresolved items are in the JSON
`unresolved` array, not `candidates`.

## vector-entry

Non-empty map: inspect `0x08000000` via `modeflow.header_vector_edge`.
The candidate is the branch **target** (stub), ARM. Header/logo
`0x08000004` .. `0x080000C0` is not harvested. Empty map still
returns no candidates (seed_entry remains the cold start).

## gap heuristic

Existing gap walk is unchanged. Insertion goes through
`add_candidate` with:

```
type = gap
source = gap
from_addr = previous mapped end
source_mode = previous mapped mode   # heuristic, not modeflow
target_addr = proposed address
target_mode = inherited mode         # heuristic
detail = "[gap_lo, gap_hi) after mapped [prev_lo, prev_hi)"
```

`deterministic` is false. Gap is never rewritten as `bl-target`.
Large-gap `leading_function` (objdump) is unchanged except it also
calls `add_candidate`.

## manual-seed

Accepted by `add_candidate` and by sidecar ingest. No new CLI. Not
verification.

## decomp-reference

`seed_from_decomp.py` is unchanged. Frontier reads unresolved sidecar
records that are **unmapped** and inserts them via `add_candidate`.
Not verification. Not ENCODING_VERIFIED.

## existing-map

labels.toml ranges are **input** (coverage for harvest and gaps).
They do not mint new frontier candidates.

## JSON serialization

Each candidate:

- `address`, `mode`
- `evidence` — human string (type list)
- `evidence_items` — `Evidence.to_json()` list (authoritative)
- `conflicts`
- `deterministic` — computed: true iff some item is
  `bl-target` / `bx-target` / `vector-entry` with known
  `target_addr` and `target_mode`; gap-only is false

Phase 1 JSONL without optional fields still loads. Optional Phase 3
field on `Evidence`: `insn`.

## Active sources

- `modeflow`
- `gap`
- `vector-entry`
- `decomp-reference` (sidecar ingest)
- `manual-seed` (API / sidecar)

## Inactive sources

- Ghidra
- gba-recomp analyzer
- LLM
- external evidence merger
- encoding roundtrip

## Limitations

- Gap mode is inherited from the previous mapped function.
- Large-gap screening still uses objdump via `leading_function`.
- One-hit literal tracking remains in modeflow (unchanged).
- Frontier does not persist discovery into the sidecar.
- Empty map does not emit vector-entry (seed_entry).
