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
`routine-pointer`, `encoding-roundtrip`, `skip-audit`, `peel-incbin`.

Unknown types are preserved.

## Producers in Phase 1

- `tools/peel.py` — writes `.incbin` + labels.toml only. Does **not** record RANGE_VERIFIED.
- `make check` then `tools/evidence.py record-range` (workflow / `seed_entry.py`) — SHA-256 match → `range_verified` + `peel-incbin`
- `tools/seed_from_decomp.py` — ELF FUNC symbols → `unresolved` + `decomp-reference`; **does not write labels.toml**
