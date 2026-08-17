# Phase 2 design: future gba-recomp analyzer interface

**Design only.** This document does not change gba-recomp. Do not
treat it as an implemented export.

gba-mapper Phase 2 produces per-mode control-flow facts from ROM
bytes. A later analyzer (in gba-recomp or a mapper-side exporter)
should consume the same identity and fields so ARM/Thumb is not
re-guessed from alignment.

## Identity

Every analyzed unit is keyed by:

```
address: u32    // even GBA ROM address; thumb bit already stripped
mode:    "arm" | "thumb"
```

Never address-only. Dual-mode at one address is two units.

## Expected payload

One object per candidate / recovered function:

```json
{
  "address": "0x08001234",
  "mode": "thumb",
  "edges": [
    {
      "src": "0x08001234",
      "src_mode": "thumb",
      "insn": "bl",
      "target": "0x08001300",
      "target_mode": "thumb",
      "evidence_type": "bl-target"
    }
  ],
  "evidence": [
    {
      "type": "bl-target",
      "source": "modeflow",
      "detail": "",
      "from_addr": "0x08001000",
      "target_addr": "0x08001234",
      "source_mode": "thumb",
      "target_mode": "thumb"
    }
  ]
}
```

### `address` / `mode`

Must match `CandidateKey`. Recomp should not coerce mode from `address
& 1` or word alignment when the mapper already supplied `mode`.

### `edges`

The `FlowEdge` list from `tools/modeflow.py`:

| field | meaning |
|---|---|
| `src` | instruction address |
| `src_mode` | ARM or Thumb at `src` |
| `insn` | `b` / `bl` / `bx` / `ldr-pc` / `ldr-literal` / `ldr-jt` / … |
| `target` | statically known destination, or `null` |
| `target_mode` | statically known mode, or `null` |
| `evidence_type` | mapper evidence string |

Unresolved BX: `target` and `target_mode` are `null`,
`evidence_type` is `indirect-branch`. The analyzer must not invent a
callee.

Immediate BLX must not appear for ARMv4T images.

### `evidence`

The sidecar list already stored in `<stem>.evidence.jsonl`. Optional
fields (`target_addr`, `source_mode`, `target_mode`) may be absent on
Phase 1 records.

Conflicts stay on the record; the analyzer should not silently pick
ARM or Thumb.

## What this is not

- Not a gamedb schema change
- Not RANGE_VERIFIED / ENCODING_VERIFIED promotion
- Not a request to implement CFG export in gba-recomp in Phase 2
- Not labels.toml v2 (still addresses and names only)

When export is implemented (later phase), mapper → recomp should pass
`{address, mode, edges, evidence}` and leave verification with
`make check` / encoding roundtrip as they stand.
