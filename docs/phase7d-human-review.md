# Phase 7D-A: Human review overlay

Phase 7D-A records which `CandidateKey` a human wanted to select
for peel. It is an **audit overlay**, not eligibility, verification,
provenance, or an end.

```
review decision != Phase 7A selection
review decision != verification
review decision != end
review decision != provenance
```

## Purpose

Sit beside the 7A → 7B → 7C pipeline. Do not feed skipped candidates
into 7B. 7B remains `peel-ready` + `selected` + explicit end only.

## CandidateKey

`(address, mode)`. Address-only review keys are rejected. ARM and
Thumb at one address stay two rows. No winner.

## Review file

```
{
  "format": "gba-mapper-review",
  "version": 1,
  "decisions": [
    {
      "address": "0x08001200",
      "mode": "thumb",
      "decision": "select-for-peel",
      "note": "optional"
    }
  ]
}
```

Allowed `decision` values: `select-for-peel`, `keep-skipped`,
`defer`, `reject-as-data`.

Forbidden on a decision: `status`, `range_verified`,
`encoding_verified`, `winner`, `confidence`, `score`, `end`.

7D-A is **end-blind**. No size, Ghidra end, `recommendedEnd`, gap, or
boundary inference.

## Overlay

`skipped` + `select-for-peel` stays `skipped`. `selection` and
`disposition` are unchanged. `deterministic` is copied, not
recomputed. `select-for-peel` is not `peel-ready`.

Optional output fields on skipped rows only:
`review_decision`, `review_note`, `reviewer`.

The 7A `selected` set is unchanged. `unresolved` is unchanged and is
not a candidate. `select-for-peel` on unresolved is invalid (ignored).

## Conflict

Both `(addr, arm)` and `(addr, thumb)` may be reviewed independently,
including both `select-for-peel`. That does not create a winner or
change `conflicted`.

## Invalid review

Malformed hex, invalid mode, unknown decision, address-only,
verification keys, `end`, unknown CandidateKey, and duplicates after
the first valid entry are ignored. First-wins. No candidate mint,
delete, or Evidence change.

## Evidence / verification / LLM

No new Evidence type. No `manual-review` / `llm-analysis`.
`evidence_items` are copied. No peel, wire, make check, RANGE,
ENCODING, labels.toml, sidecar, or gamedb. LLM is not called.

Ghidra stays `ghidra-seed` / heuristic.

## CLI

```
python3 tools/review_select.py INPUT [--review REVIEW.json] [--output PATH]
```

No `--review` → deterministic queue (`queue` plus unchanged 7A
wrapper). Queue order: skipped by address then mode (arm, thumb),
then unresolved in input order. Same input → same output.

## Out of scope / STOP

Phase 7D-B LLM suggestion, 7D-C eligibility overlay / end suggestion,
7B/7C changes, unresolved → candidate.

PHASE 7D-A STOPS HERE.
