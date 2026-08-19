# Phase 8B: Human explicit-end approval

Phase 8B writes a **standalone 7B `--ends` candidate file** from an
explicit human end. It is not verification and does not invoke 7B.

```
suggested_end != human-approved end
human-approved end != verified end
```

The only end authority is the human-authored `end` field.

## Human gate

Human input (`format = gba-mapper-explicit-end`, `version = 1`)
contains `ends[]` with `address`, `mode`, and `end`.

`suggested_end` is **never** automatically promoted. A 7D-C
`suggested_end` or advisory `end` alias is **not** authority. 8B
does not copy them into `--ends`.

8A `eligible-for-peel` does **not** generate an end. 8B may accept
an explicit human end without 8A. Optional 8A mismatch is a warning
only.

## Output

Primary output is a **pure 7B EndMap** (no wrapper):

```
{
  "0x08001200:thumb": { "end": "0x08001240" }
}
```

This is a **candidate `--ends` file**. 8B does not invoke `run_peel`.
8B does **not** verify the end. `human-approved end != verified end`.
RANGE remains 7C only.

8B does not modify 7A `selection` / `disposition`. No Evidence,
labels, gamedb, ROM read, LLM, or Ghidra.

## Scope

Optional 7A JSON restricts keys to skipped `agreed-seed` /
`heuristic` / `conflicted`. `selected`, `peel-ready`, and
`unresolved` are not targets (`unknown-candidate`). No mint.
CandidateKey is `(address, mode)`. Filter then first-wins.
ARM/Thumb independent. No winner.

Validation is syntactic only: hex parse, `end > start`, ROM window
constants (no ROM file). Not instruction alignment or peel success.

## CLI

```
python3 tools/ends_approve.py --ends-input PATH
    [INPUT]
    [--eligibility-approval PATH]
    [--eligibility PATH]
    [--output PATH]
    [--audit PATH]
```

`--output` omitted → stdout (EndMap). `--audit` writes
`gba-mapper-explicit-end-run` v1 with `deterministic: false`.
Does not import 7D/8A/7B tools.

## Out of scope / STOP

8C real LLM, 8D encoding, 8E real validation, **8F 7B gate**
(separate approval), automatic promotion, RANGE, ENCODING.

PHASE 8B STOPS HERE.
