# Phase 7C: Wire, make check, RANGE

Phase 7C connects a Phase 7B `peel-emitted` artifact to the existing
verification boundary. It does not peel, invent `end`, or promote
ENCODING.

```
peel-emitted != RANGE_VERIFIED
wire success != RANGE_VERIFIED
make check exit 0 is the RANGE prerequisite
```

## Goal

```
Phase 7A select_peel
        ↓
Phase 7B run_peel (explicit end)
        ↓
asm/disasm_0xADDR.s
        ↓
Phase 7C run_check
        ↓
tools/wire.py --start START --end END
        ↓
linker.ld contains peeled object
        ↓
make check   (returncode == 0)
        ↓
record_range_after_check(True, ...)
```

7C is an orchestrator. It does not reimplement peel or wire.

## Relationship to 7A / 7B

7A selects `peel-ready`. 7B peels with an explicit `[start, end)`.
7C runs **only** 7B `results` rows with:

- `result == peel-emitted`
- `selection == selected` (if present)
- `disposition == peel-ready` (if present)

Never executed: 7B `skipped`, `unresolved`, `peel-failed`,
`conflicted`, non-selected rows.

## Explicit end only

End comes from `--ends`, keyed by CandidateKey `(address, mode)`:

```
{ "0x08000100:arm": { "end": "0x08000180" } }
```

Address-only keys are rejected. No Ghidra size/end, `recommendedEnd`,
next candidate, gap, alignment, or boundary inference. Artifact
metadata must match the explicit end; mismatch does not correct end.

## wire.py reuse

```
python3 tools/wire.py --tree TREE --start START --end END
```

No `--mode` (wire.py has none). Exit 0 continues. Exit 3 or any
non-zero is `wire-failed`; RANGE is not recorded. `wire.py` is not
modified.

After exit 0, `linker.ld` must contain `build/asm/disasm_0xADDR.o`.
If it does not, `not-recorded` / `not-wired`. make check is not a
substitute for this check.

## make check

`make -C TREE check`. Green is **returncode == 0** only. Stdout
`OK` is ignored. Non-zero is `check-failed`;
`record_range_after_check` is not called.

## RANGE connection

The only 7C → RANGE path is:

```
record_range_after_check(True, path, rom_sha, address, mode, end,
                         name=None, source="make-check")
```

`record_range_verified` is not called from 7C.
`promote_encoding_verified` is not called.

`range-recorded` is an execution result. Sidecar `range_verified` is
authoritative.

## CandidateKey / conflict

Every lookup is `(address, mode)`. Dual-mode rows stay independent.
No winner. ARM success does not verify Thumb at the same address.

## Failure

No RANGE write on: missing/malformed end, invalid selection, missing
artifact, metadata mismatch, wire failure, missing linker object,
check failure.

Failures do not delete candidates, move them to `unresolved`, mutate
frontier Evidence, retry, or create a winner.

## labels / Evidence / ENCODING

7B default `--no-labels` is unchanged. 7C does not write labels.toml
and does not import `labels_toml`. No new Evidence types. No
`peel-attempt` / `wire-success` items. ENCODING is out of scope.

## CLI

```
python3 tools/run_check.py INPUT --ends ENDS.json [--output PATH]
        [--tree PATH] [--wire PATH] [--rom NAME]
```

No `--output` → stdout.

## Out of scope / STOP

Phase 7D LLM, Ghidra execution, end inference, map.js, gamedb,
gba-recomp, encoding promotion, labels writer.

PHASE 7C STOPS HERE.
