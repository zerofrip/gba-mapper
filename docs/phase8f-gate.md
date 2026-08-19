# Phase 8F — Explicit Gate / Orchestration

Phase 8F is a **fail-closed gate**. It does not create authority.

```text
7A selected + disposition peel-ready
  + 8B human EndMap
  + 8E encoding_verified == true
        ↓
     8F gate
        ↓
     existing 7B
        ↓
     existing 7C / RANGE
```

## Authority

| Item | Source |
|------|--------|
| CandidateKey | `(address, mode)` |
| selection | 7A `selection == selected` |
| peel-ready | 7A `disposition == peel-ready` |
| explicit end | 8B EndMap `ends[addr:mode].end` only |
| encoding_verified | 8E `gba-mapper-encoding-verification` v1 only |

8F consumes these. It does not generate them.

```text
eligible-for-peel != peel-ready
8A overlay != 7B unlock
8C LLM != gate
8D claim != encoding_verified
encoding_verified != selected / peel-ready / end / RANGE
```

## Gate conditions

All must hold for `gate: ready`:

1. CandidateKey exists
2. 7A `selection == selected`
3. 7A `disposition == peel-ready`
4. 8B EndMap has matching `(address, mode)` with a valid `end`
5. 8E artifact: `format == gba-mapper-encoding-verification`, `version == 1`, `run.deterministic == true`
6. matching 8E result has `encoding_verified == true`

Any gap is fail-closed. **No 7B / 7C / RANGE.**

8A is optional. Absence does not fail. Presence with mismatch → `eligibility-mismatch`. `eligible-for-peel` alone does not unlock 7B.

## Output

```json
{
  "format": "gba-mapper-phase8f-result",
  "version": 1,
  "run": { "deterministic": true },
  "results": [
    { "address": "0x08001200", "mode": "thumb", "gate": "ready" }
  ],
  "errors": [],
  "invoked": { "peel": false, "check": false }
}
```

`gate: ready` means the four prerequisites hold. It does **not** mean 7B or RANGE succeeded.

Forbidden in output: winner, selection, disposition, eligible-for-peel, peel-ready, end, suggested_end, encoding_verified, range_verified, Evidence, rationale, score.

## Invocation

Default CLI is **gate only**.

```bash
python3 tools/phase8f_gate.py INPUT --ends ENDS.json --encoding ENC.json \
    [--eligibility-approval 8A.json] [--output PATH]
```

Opt-in orchestration:

- `--execute-7b` — existing `run_peel.py` / `PeelRunner` with `write_labels=False` and without `--force-boundary`. Filtered in-memory 7A contains only ready CandidateKeys. Input files are not rewritten.
- `--execute-7c` — existing `run_check.py` only after `peel-emitted`. 8F does not compute RANGE.

7B/7C failure propagates (`7b-failed`, `7c-failed`). No success conversion.

## Security

8F does not:

- read ROM
- run LLM / Ghidra / network / git / shell
- modify Evidence / FrontierStore / labels.toml / gamedb
- mint candidates or winners
- rewrite selection / disposition
- generate ends or encoding_verified

`run.deterministic = true` is gate determinism. `FrontierStore._is_deterministic` is unchanged.

## Failure codes

| Condition | Code |
|-----------|------|
| not selected | `not-selected` |
| disposition != peel-ready | `not-peel-ready` |
| EndMap missing key | `missing-explicit-end` |
| malformed end | `invalid-explicit-end` |
| 8E artifact missing | `missing-encoding-verification` |
| 8E schema/deterministic invalid | `invalid-encoding-verification` |
| not verified for key | `encoding-not-verified` |
| conflicting 8E results | `conflicting-verification` |
| 8A present + mismatch | `eligibility-mismatch` |
| address-only | `address-only` |
| invalid mode/key | `invalid-key` |
| 7B failed | `7b-failed` |
| 7C before peel-emitted | `7c-gate-failed` |
| 7C failed | `7c-failed` |

## 7B / 7C remain existing authorities

8F does not modify `run_peel.py` or `run_check.py`. RANGE remains the existing 7C path.
