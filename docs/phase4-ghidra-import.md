# Phase 4: Ghidra JSON/JSONL import

Phase 4 turns Ghidra function lists into frontier **discovery**
candidates. It does not run Ghidra, does not write labels or the
sidecar, and does not verify anything.

## Purpose

Consume a JSON or JSONL dump of Ghidra functions and insert them into
a `FrontierStore` as `ghidra-seed` evidence. The CLI is a thin wrapper
around parse → normalize → ingest.

## Ghidra = STATIC_ANALYSIS_ORACLE

Ghidra is an unverified static-analysis oracle. Its output is
**evidence**, not a decision.

| Ghidra field | What it is not |
|---|---|
| function `size` / `end` | not RANGE_VERIFIED |
| disassembly | not ENCODING_VERIFIED |
| function `name` | not labels.toml identity |
| `confidence` | not a trust score |

`kind`, `details`, and Ghidra `source` are likewise unused for
scoring, deterministic flags, or verification status.

## Input formats

- JSON array of objects
- JSON single object
- JSONL: one JSON object per non-empty line (blank lines ignored)

Broken JSON **syntax** rejects the whole file (no partial success).
Invalid **records** (missing fields, bad mode, bad size) are rejected
per record; valid siblings still ingest.

Each record must have:

```
address
mode ∈ {"arm", "thumb"}
```

Optional provenance-only fields: `name`, `size`, `end`.

## Address normalization

`parse_addr` accepts an `int` or a hex string (`0x08000100`,
`08000100`). Bool, negative, empty, and junk values are rejected.

`normalize_rom_addr`:

```
0 <= addr < 0x02000000          → addr + 0x08000000
0x08000000 <= addr < 0x0A000000 → addr unchanged
otherwise                       → invalid
```

Mode is **not** inferred from alignment. ARM/Thumb is taken from the
input `mode` field as-is.

## ARM/Thumb handling

`CandidateKey = (address, mode)` is unchanged from Phase 2/3. The
same address in ARM and Thumb is two candidates plus the existing
FrontierStore conflict string. Alignment is not used as a mode hint.

## Record validation

- invalid / out-of-window `address` → reject
- `mode` not `arm`/`thumb` → reject
- `end` present → must normalize and be `> address`
- `size` present → must be a positive `int`

Incomplete records never become candidates. They go to `rejected`,
not `unresolved`. `add_unresolved()` is for FlowEdge/Evidence
indirect-branch / jump-table items, not bad Ghidra rows.

## Evidence generation

Every accepted record becomes:

```
Evidence(
    type="ghidra-seed",
    source="ghidra",
    detail="ghidra function: {name}; ghidra_size=...; ghidra_end=...",
    target_addr=address,
    target_mode=mode,
)
```

Missing `name` / `size` / `end` are omitted from `detail`.
`confidence` is ignored and is not stored in `detail`.

Ghidra evidence never produces `range_verified`, `encoding_verified`,
`deterministic=true`, or a labels.toml identity.

## FrontierStore integration

`ingest_ghidra(store, records)` calls only
`store.add_candidate(address, mode, evidence)`. It does not touch
`store._cands`. Insertion rules are Phase 3's: empty evidence is a
no-op (not used here); merge by `Evidence.key()`; ARM/Thumb dual keys.

## Merge / dedupe

Same `(address, mode)`: append. Identical Ghidra evidence (same
`Evidence.key()`) is stored once. An existing `bl-target` plus a
`ghidra-seed` keeps **both** items on that candidate.

## Conflict behavior

ARM and Thumb at the same address remain two candidates. FrontierStore
attaches the existing conflict string; Ghidra import does not add a
new conflict type and does not drop either side.

## Rejected records

`import_ghidra_text` returns the Phase 3 frontier-compatible object
plus `rejected`:

```
{
  "candidates": [...],
  "unresolved": [...],
  "rejected": [{"reason": "...", "raw": {...}}]
}
```

`unresolved` stays the store's FlowEdge/Evidence list (empty for a
pure Ghidra import). Bad Ghidra rows are never stuffed into it.

## deterministic semantics

Unchanged from Phase 3 `FrontierStore.to_json_list()`. A candidate is
`deterministic` only when it already has `bl-target` / `bx-target` /
`vector-entry` with a known target+mode. **Ghidra-only candidates are
`deterministic=false`.** Ghidra fields never flip that flag.

No `status`, `range_verified`, or `encoding_verified` key is added to
the JSON.

## Verification boundary

Ghidra function size/end is not RANGE_VERIFIED.
Ghidra disassembly is not ENCODING_VERIFIED.
Ghidra function name is not labels identity.
Ghidra confidence is not a trust score.

RANGE_VERIFIED remains: peel → `.incbin` → wire → `make check`.
ENCODING_VERIFIED remains the isolated future gate. Phase 4 does not
implement either.

## labels.toml boundary

This importer never reads or writes `labels.toml`. Ghidra names stay
in evidence `detail`.

## Sidecar / gamedb boundary

This importer never writes `*.evidence.jsonl` or gamedb. Discovery
stays on stdout / `--output` JSON.

## CLI

```
python3 tools/import_ghidra.py INPUT [--output PATH]
python3 tools/import_ghidra.py --input INPUT [--output PATH]
```

No `--output` → stdout. `--output` writes that file only. ROM and
SHA-256 checks are not required and are not implemented.

## Limitations

- No Ghidra headless / Java exporter; input files are assumed.
- No SHA-256 image check (ROM is unused).
- Ghidra `size`/`end` are provenance text, not peel bounds.
- No LLM, gba-recomp, or gamedb integration.

## Phase 5 is not included

Phase 5 (LLM / stronger adjudication / peel wiring of Ghidra seeds)
is out of scope. This document stops at JSON/JSONL → `ghidra-seed`
frontier candidates.
