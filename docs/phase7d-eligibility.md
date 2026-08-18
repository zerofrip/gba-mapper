# Phase 7D-C: Eligibility / suggested-end overlay

Phase 7D-C emits a **standalone advisory artifact** for 7A skipped
candidates. It is not verification, selection, or a 7B input.

```
eligibility != selection
eligibility != verification
suggested_end != verified end
suggested_end != 7B --ends
LLM suggestion != human review
human review != automatic
```

7D-C does **not** itself perform the human gate.

## Human-gated path

```
7D-B suggestion
  ↓
7D-C eligibility overlay
  ↓
human inspection
  ↓
7D-A review (human-written)
  +
explicit --ends (human-written)
  ↓
existing 7B run_peel
  ↓
existing 7C run_check
  ↓
RANGE API
```

There is **no automatic 7B**, **no automatic RANGE**, **no automatic
`--ends`**, and **no automatic 7D-A review**.

`eligible-for-review` plus `suggested_end` means a human *may* use
this information when writing the separate 7D-A review and `--ends`
file. It does **not** mean 7B-ready.

## Scope

Reads `skipped` rows with disposition `agreed-seed`, `heuristic`, or
`conflicted`. Does **not** process `selected`, `peel-ready` (even if
present in skipped), or `unresolved`.

CandidateKey is `(address, mode)`. ARM/Thumb stay independent.
No winner. Filter target rows **before** first-wins.

Disposition and selection are copied/ignored, never rewritten.
No `review_decision`. No candidate mint.

## 7D-B mapping (advisory only)

| 7D-B action | 7D-C eligibility |
|---|---|
| `possible-control-flow` | `eligible-for-review` |
| `arm-plausible` | `eligible-for-review` (ARM key only) |
| `thumb-plausible` | `eligible-for-review` (Thumb key only) |
| `possible-data` | `not-eligible` |
| `possible-invalid` | `not-eligible` |
| `insufficient-evidence` | `needs-human-review` |
| `review` | `needs-human-review` |

Missing / stale / malformed / unknown / forbidden suggestion →
`needs-human-review` plus `errors[]`. No retry. No extra mappings.

Suggestion `input_hash` is recomputed from the current 7A request
(same 7-field canonical JSON as 7D-B). Stale hashes are ignored.

## Suggested end

v1 source is `--suggested-ends` only, keyed by `(address, mode)`
(`0xADDR:mode`). Address-only keys are invalid.

`--suggested-ends` accepts `suggested_end` as the advisory input
field. For compatibility it may also accept `end` as an **advisory
alias**. The alias is normalized only to `suggested_end` in the
overlay. It is not a verified end, not human approval, and not a
change to selection or disposition.

```
suggested_end          = advisory suggestion / input only
7B --ends              = explicit operational end for run_peel
verified RANGE         = make check + wired artifact, then
                         record_range_after_check()
```

These three are not the same. Advisory `end` != 7B `--ends`.

Reading the alias never emits a 7B `--ends` file, never invokes 7B,
never calls peel / wire / make check, never records RANGE or
ENCODING, and never mutates Evidence. Explicit human `--ends` remains
a separate later step.

An advisory `end` field in a 7D-C suggestion input is not a
7B `--ends` file and must not be reused as one automatically.

`start < suggested_end` is required. This is **not** a verified end
and is **not** passed to `record_range_after_check`, peel, wire, or
7B `--ends`.

No inference from size, `recommendedEnd`, Ghidra, gap, next range,
boundary, ROM, or objdump.

`end_source` is suggestion provenance only:

```
boundary-recommendation != verified
ghidra != verified
llm != verified
manual != verified
human != verified
```

Allowed sources: `llm`, `human`, `boundary-recommendation`, `ghidra`,
`manual`.

## Output

`format = gba-mapper-eligibility`, `version = 1`.

Allowed `eligibility`: `eligible-for-review`, `not-eligible`,
`needs-human-review`.

Forbidden: `select-for-peel`, `human-approved`, `eligible-for-peel`,
`selected`, `verified`, `winner`, `status`, `range_verified`,
`encoding_verified`, `confidence`, `score`, `review_decision`.

Every entry has `"deterministic": false`.
`FrontierStore._is_deterministic` is not modified.

Rationale is untrusted text. It is not copied to `Evidence.detail`.

Standalone JSON only. No Evidence, sidecar, labels.toml, gamedb,
frontier mutation.

## CLI

```
python3 tools/eligibility.py INPUT
    [--suggestions SUGGESTIONS.json]
    [--suggested-ends ENDS.json]
    [--output PATH]
```

Does not import `review_select.py`. Does not call peel/wire/make
check. Does not invoke an LLM.

## Out of scope / STOP

Phase 8, real LLM, automatic suggestion→review, automatic
eligibility→7B, automatic end adoption, ENCODING, map.js.

PHASE 7D-C STOPS HERE.
