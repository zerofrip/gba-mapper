# Phase 7D-B: LLM suggestion layer

Phase 7D-B emits a **standalone suggestion artifact** for 7A skipped
candidates. It is a fake-provider oracle only.

```
LLM suggestion != verification
LLM != Evidence
LLM != candidate generation
LLM != selection
LLM != winner
LLM != end
LLM != RANGE
LLM != ENCODING
```

## Scope

Reads `skipped` rows with disposition `agreed-seed`, `heuristic`, or
`conflicted`. Does **not** send `peel-ready` (even if present in
skipped). **unresolved is out of scope.**

Does not feed 7B. Does not auto-convert to 7D-A `select-for-peel`.

## Human gate (mandatory)

LLM suggestions are advisory only.
A suggestion MUST NOT be automatically converted into a 7D-A review
decision, 7A selection, an explicit `--ends` entry, or a 7B
invocation.
A human MUST independently create the 7D-A review decision and
explicit end input before a skipped candidate can enter the existing
7B/7C verification path.

## Fake provider only

`--provider fake` is the only implementation. No network LLM.
Real providers need separate approval.

## Request

Canonical payload (no `Evidence.detail`, no ROM bytes, no selection,
no end):

```
address, mode, disposition, sources, classes, evidence_types, deterministic
```

`input_hash` = SHA-256 of `canonical_json` (`sort_keys`, compact
separators). Per-suggestion hash is that request. `run.input_hash`
hashes `{"requests": [...]}`. No timestamp.

## Output

`format = gba-mapper-llm-suggestion`, `version = 1`.

Allowed `action`: `review`, `possible-control-flow`, `possible-data`,
`possible-invalid`, `insufficient-evidence`, `arm-plausible`,
`thumb-plausible`.

Rejected: `select-for-peel`, verification fields, `winner`,
`confidence`, `score`, `end`, `status`, `selection`, `disposition`.

Each suggestion has `"deterministic": false`. Input candidate
`deterministic` is not modified (7D-B does not rewrite 7A JSON).

## CandidateKey / conflict

`(address, mode)`. Duplicates: first-wins. ARM/Thumb independent.
`arm-plausible` is not a winner.

## Failure

Provider exception / timeout / empty / invalid → `errors[]`, no
suggestion for that key. No retry. Other keys continue. No Evidence /
RANGE / labels / sidecar / gamedb writes.

## CLI

```
python3 tools/llm_suggest.py INPUT [--output PATH] [--provider fake]
```

Stdout default. `--output` writes that JSON only.

## Out of scope / STOP

Phase 7D-C, real provider, ROM bytes, detail opt-in, map.js,
suggestion→review converter, peel/wire/make check.

PHASE 7D-B STOPS HERE.
