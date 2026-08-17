# Mapping evidence sidecar

Verification state lives in `<rom stem>.evidence.jsonl` beside the
working `gba-labels` v2 file. [labels.toml](labels-toml.md) is unchanged:
addresses and names only, consumed by the recompiler as **hints**.

This sidecar is the authority for status and provenance. It never
contains image bytes. Evidence items are a list, never collapsed into
a confidence score.

## Status

| status | meaning |
|---|---|
| `unresolved` | candidate; not verified |
| `range_verified` | `.incbin` reproduces the ROM range; ARM/Thumb and decode are unproven |
| `encoding_verified` | RANGE plus established mode, complete decode, successful reassembly, byte-identical comparison, boundary checks |
| `rejected` | explicit reject |

`FUNCTION_VERIFIED` is not a status. Do not weaken `encoding_verified`
to mean "looks like a function."

Only `encoding_verified` may enter the canonical verified mapping set
or `gamedb.sqlite`. Phase 1 does not write gamedb.

Promotion to `encoding_verified` is **only** via
`evidence.promote_encoding_verified`. The peel / `.incbin` path never
calls it. Silent upgrades through `upsert` are refused.

## File format

JSONL. First line is a header; every later line is one record. Keyed
by `(address, mode)` like labels.toml. Addresses are hex strings;
loaders also accept integers.

```json
{"format":"gba-mapping-evidence","version":1,"sha256":"<64 hex>"}
{"address":"0x080001c8","mode":"thumb","end":"0x08000220","name":"AgbMain","status":"range_verified","evidence":[{"type":"peel-incbin","source":"peel","detail":"incbin range [0x80001c8, 0x8000220); mode unproven"}],"conflicts":[]}
```

A `sha256` mismatch against the image is an error.

## Evidence types

`bl-target`, `blx-target`, `bx-target`, `gap`, `prologue`, `epilogue`,
`cfg-consistency`, `interior-bl`, `ghidra-seed`, `gba-recomp-seed`,
`decomp-reference`, `runtime-entry`, `manual-seed`, `hook`, `repoint`,
`routine-pointer`, `encoding-roundtrip`, `skip-audit`, `peel-incbin`,
`literal-pool`, `jump-table`, `indirect-branch`, `vector-entry`.

Unknown types are preserved. Optional evidence fields (absent on
Phase 1 records): `target_addr`, `source_mode`, `target_mode`, `insn`.

Do not rename existing type strings. `blx-target` is reserved;
ARMv4T decode does not produce it. See [phase2-arm-thumb.md](phase2-arm-thumb.md).

## Producers in Phase 1

- `tools/peel.py` — writes `.incbin` + labels.toml only. Does **not** record RANGE_VERIFIED.
- `make check` then `tools/evidence.py record-range` (workflow / `seed_entry.py`) — SHA-256 match → `range_verified` + `peel-incbin`
- `tools/seed_from_decomp.py` — ELF FUNC symbols → `unresolved` + `decomp-reference`; **does not write labels.toml**

## Producers in Phase 3

- `tools/frontier.py` — stdout JSON candidates with `evidence_items`;
  does **not** write the sidecar. See [phase3-frontier-provenance.md](phase3-frontier-provenance.md).
  Unresolved sidecar records (`decomp-reference`, `manual-seed`) that
  are unmapped may appear as frontier candidates. That is discovery,
  not RANGE_VERIFIED or ENCODING_VERIFIED.

## Producers in Phase 4

- `tools/import_ghidra.py` — Ghidra JSON/JSONL → `ghidra-seed` /
  `source=ghidra` frontier candidates. STATIC_ANALYSIS_ORACLE only:
  does **not** write labels.toml, the sidecar, or gamedb, and does
  **not** produce RANGE_VERIFIED or ENCODING_VERIFIED. See
  [phase4-ghidra-import.md](phase4-ghidra-import.md).

## Producers in Phase 5

- `tools/evidence_merge.py` — unions frontier-compatible JSON on
  `(address, mode)`. Provenance reconciliation only:
  **agreement != verification**. Does **not** write labels.toml, the
  sidecar, or gamedb, and does **not** produce RANGE_VERIFIED or
  ENCODING_VERIFIED. See [phase5-evidence-merge.md](phase5-evidence-merge.md).

## Producers in Phase 6

- `tools/adjudicate.py` — read-only disposition / sources / classes on
  frontier JSON. **disposition != status**; **peel-ready !=
  RANGE_VERIFIED**. Does **not** write labels.toml, the sidecar, or
  gamedb. See [phase6-adjudication.md](phase6-adjudication.md).

## Producers in Phase 7A

- `tools/select_peel.py` — consumes adjudicated frontier data and
  emits selection metadata only. It does **not** create verification
  evidence, invent `end`, or run peel. See
  [phase7-peel-selection.md](phase7-peel-selection.md).

## Producers in Phase 7B

- `tools/run_peel.py` — invokes existing `tools/peel.py` with an
  explicit `[start, end)` keyed by `(address, mode)`. It does **not**
  invent `end`, mutate Evidence, or record RANGE/ENCODING. See
  [phase7b-peel-execution.md](phase7b-peel-execution.md).


