# Phase 2: ARM/Thumb state and conservative boundaries

Phase 2 corrects mode propagation and stops treating control-flow
edges as function ends. It does not change labels.toml v2, gamedb,
gba-recomp, the LLM workflow, or RANGE_VERIFIED timing.

## CandidateKey

```
CandidateKey = (address, mode)
mode ∈ {"arm", "thumb"}
```

Address-only identity is forbidden. The same ROM address may hold an
ARM candidate and a Thumb candidate at once. Never collapse them.

Implemented in `tools/modeflow.py` (`Candidate`, `candidates_from_edges`,
`merge_candidates`) and consumed by `tools/frontier.py`.

## ARMv4T restriction

The target ISA is GBA **ARMv4T**. Immediate BLX (`cond=1111`, `101x`)
is ARMv5. Phase 2:

- does not decode those bytes as BLX
- does not emit `blx-target` from ROM bytes
- does not invent an immediate BLX mode transition

`blx-target` remains a reserved evidence type for later sources. Mode
changes in this phase come only from `BX Rn`, known function pointers
(bit 0), and known entry references (vector-entry).

## ARM/Thumb propagation

`tools/modeflow.py` decodes **bytes**. No objdump, no ARM toolchain.
Synthetic fixtures are enough.

| Instruction | Source mode | Target mode |
|---|---|---|
| BL | ARM | ARM |
| BL | Thumb | Thumb |
| B (cond or uncond) | current | current |
| BX Rn (resolved pointer) | current | bit 0 of pointer |
| BX Rn (unknown register) | current | unknown |

Do not infer mode from address alignment.

## B semantics

B is intra-function (or same-mode) control flow.

- evidence type: `cfg-consistency` (header ARM B at `0x08000000` is
  `vector-entry` instead)
- does **not** mint a function candidate
- does **not** terminate a function in `detect_boundary` /
  `detect_boundary_arm`

Unconditional `b` / `b.n` / `b.w` were removed from Thumb automatic
epilogue classification.

## BL semantics

BL is a same-mode call.

- evidence type: `bl-target`
- mints a candidate at `(target, source_mode)` when the target is in
  ROM and not cartridge-header data (`0x08000004` .. `0x080000C0`)

## BX semantics

`BX Rn` only. Target and target mode are filled in only when Rn’s
value is a **statically known** GBA function pointer (one-hit
PC-relative literal load into that register, then BX).

```
bit 0 == 0 → ARM,  address = ptr & ~1
bit 0 == 1 → Thumb, address = ptr & ~1
```

Evidence type: `bx-target`. That mints a candidate.

## Unknown indirect branches

If Rn is unknown:

```
FlowEdge(target=None, target_mode=None, evidence_type="indirect-branch")
```

No function candidate is created. Phase 2 does not run speculative
dataflow.

## ARM boundary rules

`boundary.detect_boundary_arm` / `detect_boundary_arm_bytes` (bytes,
no objdump). Matches are **evidence**, not proof.

Prologue evidence: `STMDB` / `STMFD sp!, {…}`.

Epilogue evidence:

- `LDMIA` / `LDMFD … pc`
- `BX LR`
- `MOV PC, LR`

Unconditional B is not an epilogue. `peel.py` uses this path when
`mode == arm`. `seed_entry.py` uses it instead of “first B ends the
ARM function”.

## Thumb boundary rules

Existing Thumb walk is preserved, with these changes:

- epilogue: `pop {…, pc}` and `bx lr` only
- `bx rN` (`rN != lr`) is not an epilogue
- unconditional B is not an epilogue
- interior-bl still revises the recommended end
- literal-pool words after an epilogue stay attached to the function
  above and emit `literal-pool` evidence

## Literal pools

Known pool words are not decoded as instructions (`modeflow` skips
addresses recorded from `LDR Rd, [pc, #imm]`). Pool evidence is
emitted. Pools do not create functions.

No speculative pool recovery.

## Jump tables

Only an obvious static form is recognized:

ARM `LDR pc, [pc, Rm, LSL #2]` → evidence `jump-table`, `target=None`.

Entries are not enumerated and are not minted as functions. Ambiguous
tables stay unresolved (`indirect-branch` or no edge).

## Vector entry

The word at `0x08000000` is ARM. An ARM B there is `vector-entry`.
The candidate is the **branch target** (boot stub), not a function
covering the Nintendo logo / header (`0x08000004` .. `0x080000C0`).
Targets that land in that header window are dropped.

## Evidence and conflicts

`Evidence` gained optional fields only: `target_addr`, `source_mode`,
`target_mode`. Phase 1 JSONL still loads.

New types (additive): `literal-pool`, `jump-table`, `indirect-branch`,
`vector-entry`.

Existing names are unchanged, including reserved `blx-target`.

Same `(address, mode)`: merge evidence lists; do not overwrite
provenance.

Mode conflict at one address: keep both candidates and record a
conflict string. Do not pick a winner.

`gap` remains gap evidence in the frontier. It is never rewritten as a
BL target.

## Known limitations

- Literal tracking is one-hit PC-relative LDR, not a dataflow solver.
  Any intervening non-LDR/BX instruction clears the map.
- ARM functions that tail-branch with B and never hit LDM/BX LR/MOV PC,LR
  have a weak recommended end (walk limit), not a false B-epilogue.
- Jump tables are evidence-only.
- Thumb `detect_boundary` on a real ROM still uses objdump to obtain
  insns; tests use `detect_boundary_from_insns` on synthetic dicts.
- Gap candidates still inherit the previous mapped function’s mode
  (existing gap heuristic, not a call-regex copy).
- `ENCODING_VERIFIED`, Ghidra, LLM, and gba-recomp export are out of
  scope.
