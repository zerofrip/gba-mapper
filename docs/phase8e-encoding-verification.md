# Phase 8E — Encoding Verification (ROM)

Phase 8E performs **deterministic ROM-based encoding verification** and is the
**first authority** that may emit `encoding_verified: true`.

## Authority

```text
8D encoding-claim      = advisory
8C LLM suggestion      = advisory
Ghidra claim            = advisory
human claim             = advisory
CandidateKey.mode       = candidate identifier
8E ROM verification     = authoritative encoding verification
```

Fixed distinctions:

```text
LLM claim            != encoding_verified
Ghidra claim           != encoding_verified
human claim            != encoding_verified
8D claim               != encoding_verified
candidate.mode         != encoding_verified
```

`encoding_verified: true` is emitted **only** when ROM bytes at a CandidateKey
are deterministically decodable in that key's mode.

## What encoding_verified means

`encoding_verified: true` means:

> At the CandidateKey address, in the CandidateKey mode, ROM bytes form a
> decodable instruction encoding under ARMv4T rules.

It does **not** mean:

```text
encoding_verified != semantic_verified
encoding_verified != end_verified
encoding_verified != peel_verified
encoding_verified != control-flow correctness
encoding_verified != function boundary correctness
```

## CandidateKey

```text
CandidateKey = (address, mode)
mode ∈ {arm, thumb}
```

Population matches Phase 8D:

- all `selected` rows with valid `(address, mode)`
- `skipped` rows with disposition in `{agreed-seed, heuristic, conflicted}`

ARM and Thumb are verified independently. Results are never copied across modes.

## ROM handling

```text
ROM_BASE = 0x08000000
ROM_WINDOW_END = 0x0A000000
offset = address - ROM_BASE
```

Valid address requires:

- `ROM_BASE <= address < ROM_WINDOW_END`
- `offset < ROM file size`

ROM is read **locally** and **read-only**. ROM bytes are never written to output,
errors, Evidence, or network.

## Decoder

`tools/encoding_decoder.py` validates **encoding only** — not control flow.

- Thumb: 16-bit halfword rules; 32-bit Thumb pairs; rejects ARMv5 BLX prefix
- ARM: 32-bit word; word-aligned; rejects ARMv5 immediate BLX

Does not import `modeflow` or use control-flow walkers as verification authority.

## Determinism

```text
run.deterministic = true
```

Same ROM bytes + same CandidateKey + same decoder version → same result.

`FrontierStore._is_deterministic` is not modified.

## Output artifact

```json
{
  "format": "gba-mapper-encoding-verification",
  "version": 1,
  "run": { "deterministic": true, "decoder_version": "8e-v1" },
  "results": [
    { "address": "0x08000200", "mode": "thumb", "encoding_verified": true }
  ],
  "errors": []
}
```

Forbidden in output: selection, disposition, winner, end, suggested_end,
eligible-for-peel, peel-ready, selected, rationale, Evidence, range fields.

## Failure codes

| Condition | Code |
|-----------|------|
| ROM missing/unreadable | `rom-unavailable` |
| address outside window/file | `invalid-address` |
| truncated bytes | `truncated-instruction` |
| invalid encoding | `invalid-encoding` |
| invalid mode | `invalid-mode` |

Fail-closed. No automatic retry.

## 8D / 8C integration

Optional 8D or 8C JSON may be supplied in future extensions as **context only**.
Verification outcome depends on ROM + CandidateKey, not advisory claims.

```text
8D claim + invalid ROM  → no encoding_verified
no 8D claim + valid ROM → encoding_verified possible
```

## Forbidden integrations

8E does **not**:

- run LLM or import `llm_suggest` / `llm_providers`
- execute Ghidra
- access network
- use subprocess (production code)
- run 7B / 7C / RANGE / peel / wire / make check
- modify selection / disposition
- mint candidates or winners
- generate ends
- create or modify Evidence / FrontierStore / labels.toml / gamedb

## 8F

Connection to 7B/7C/RANGE gates requires **separate Phase 8F approval**.

## Usage

```bash
python3 tools/encoding_verify.py INPUT --rom ROM.gba [--output PATH]
```

## Testing

Unit tests use **synthetic local ROM fixtures** only. No proprietary ROMs.
No real LLM, Ghidra, peel, or RANGE in tests.
