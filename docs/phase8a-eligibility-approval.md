# Phase 8A: Human eligibility approval

Phase 8A records an explicit human decision that a skipped
CandidateKey is `eligible-for-peel`. It is a **standalone overlay
artifact**, not selection, not 7B input, and not verification.

```
eligible-for-peel != selected
eligible-for-peel != peel-ready
eligible-for-peel != RANGE_VERIFIED
eligible-for-review != eligible-for-peel
```

8A does **not** invoke 7B. 8B–8F are out of scope.

## Human gate

Approval comes **only** from a human-authored file. 8A does not infer
approval from LLM suggestion, 7D-C eligibility, `suggested_end`,
source, deterministic, conflict, or confidence.

A human may approve a key even when 7D-C says `not-eligible`. That
mismatch is recorded (`eligibility-mismatch`) and **not** auto-resolved.

7D-C `eligible-for-review` does **not** become `eligible-for-peel`.

## Scope

Reads 7A `skipped` with disposition `agreed-seed`, `heuristic`, or
`conflicted`. Ignores `selected`, `peel-ready`, `unresolved`.
No candidate mint. CandidateKey is `(address, mode)`. Filter then
first-wins. ARM/Thumb independent. No winner.

## Output

`format = gba-mapper-eligibility-approval`, `version = 1`.

Each approval: `address`, `mode`, `eligibility=eligible-for-peel`,
`deterministic=false`. `run.deterministic` is false.

Forbidden: `select-for-peel`, `verified`, `range_verified`,
`encoding_verified`, `winner`, `confidence`, `score`, `status`,
`selection`, `end`, `suggested_end`.

Standalone JSON only. No Evidence, labels, gamedb, `--ends`, peel,
wire, make check, RANGE.

## CLI

```
python3 tools/eligibility_approve.py INPUT
    [--approval APPROVAL.json]
    [--eligibility ELIG.json]
    [--output PATH]
```

`--approval` is the human file (`approvals` list). Without it,
`approvals` is empty. `--eligibility` is optional 7D-C JSON for
mismatch warnings only.

Does not import `review_select.py`, `llm_suggest.py`, or
`eligibility.py`. Does not call 7B/7C.

## Out of scope / STOP

8B explicit `--ends`, 8C real LLM, 8D encoding, 8E real validation,
8F 7B gate, automatic promotion, RANGE, ENCODING.

PHASE 8A STOPS HERE.
