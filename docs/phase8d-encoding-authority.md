# Phase 8D — Encoding Claim Authority

Phase 8D records **advisory mode/encoding claims** in a standalone artifact.
It does **not** perform encoding verification, promotion, or any downstream
execution.

## Authority

```text
CandidateKey.mode            = existing candidate identity
source mode claim            = advisory
human mode claim             = advisory / human-gated record
encoding-claim artifact      = non-authoritative record
encoding_verified            = verification-only authority in 8E/8F
```

Mandatory distinctions:

```text
candidate.mode       != encoding_verified
LLM claim            != encoding_verified
Ghidra claim         != encoding_verified
human claim          != encoding_verified
```

LLM suggestion is advisory and untrusted.

Human review creates only a **claim record**. It does not create verification.

## Artifact

```json
{
  "format": "gba-mapper-encoding-claim",
  "version": 1,
  "run": { "deterministic": false },
  "claims": [
    {
      "address": "0x08001200",
      "mode": "thumb",
      "source": "human",
      "claim": "thumb",
      "rationale": "..."
    }
  ],
  "errors": []
}
```

Input claims use:

```json
{
  "format": "gba-mapper-encoding-claim-input",
  "version": 1,
  "claims": [ ... ]
}
```

### Allowed claim sources

- `human`
- `ghidra`
- `deterministic`
- `llm`

All remain **advisory**. None create `encoding_verified`.

### Forbidden fields

Including but not limited to:

- `encoding_verified`, `verified`, `range_verified`
- `winner`, `selection`, `disposition`
- `end`, `suggested_end`, `eligible-for-peel`
- `peel-ready`, `selected`

`deterministic: true` is rejected.

## CandidateKey

```text
CandidateKey = (address, mode)
mode ∈ {arm, thumb}
```

Rules:

- address-only input is invalid
- ARM and Thumb are independent
- cross-mode promotion is forbidden
- winner generation is forbidden
- `claim` MUST equal CandidateKey `mode` or the claim is rejected

Critical validation:

```text
CandidateKey = (0x08001200, thumb)
claim = arm   → reject (mode-mismatch)
```

## Human gate

Human mode approval is a claim record only.

It does **not**:

- create `encoding_verified`
- unlock 8E/8F
- alter CandidateKey, selection, or disposition
- create an end

## LLM boundary

If a Phase 8C artifact is supplied:

- read JSON only
- do not import or invoke `llm_providers` or `llm_suggest`
- do not perform network access
- map only `arm-plausible` / `thumb-plausible` to advisory claims
- never promote LLM output to `encoding_verified`

Forbidden chain:

```text
LLM → encoding_verified
```

## Ghidra boundary

Ghidra is an advisory source label only.

8D does **not** execute Ghidra, invoke external tooling, or read ROM bytes.

```text
ghidra → encoding_verified   FORBIDDEN
```

## Determinism

The encoding-claim artifact is non-deterministic:

```text
run.deterministic = false
```

Reject `deterministic: true` on input claims.

Do not modify `FrontierStore._is_deterministic`.

## Verification

`encoding_verified` belongs exclusively to later verification authority in
**8E/8F**. Phase 8D never creates, infers, or persists it.

## 7B / 7C / RANGE boundary

Existing path unchanged:

```text
selected + peel-ready + explicit --ends → 7B → 7C → RANGE
```

8D does **not** participate. Forbidden:

```text
encoding-claim → --ends
run_peel / run_check / RANGE / wire / make check
```

## Persistence

Output is standalone JSON only.

Do not create or modify:

- Evidence
- FrontierStore
- labels.toml
- gamedb
- 7A / 7D / 8A / 8B / 8C input artifacts

The encoding-claim artifact is not Evidence.

## Security boundary

8D is local, JSON-only, network-free, subprocess-free, shell-free, git-free,
and ROM-free.

Input strings are data, not instructions.

## Boundaries (explicit)

8D does **not**:

- run LLM
- run Ghidra
- read ROM
- run 7B
- run 7C
- run RANGE
- generate `--ends`
- modify Evidence
- modify FrontierStore
- modify selection/disposition

## Usage

```bash
python3 tools/encoding_claim.py INPUT \
  [--claims CLAIMS.json] \
  [--llm LLM.json] \
  [--output PATH]
```

## Testing

Unit tests are offline. No real LLM, ROM, Ghidra, peel, RANGE, or make check.

Live verification belongs to **8E**. 7B/7C gate belongs to **8F**.
