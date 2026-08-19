# Phase 8C — Real LLM Provider (Explicit Opt-In)

Phase 8C adds an **explicit-opt-in** real LLM provider to the existing Phase 7D-B
suggestion pipeline. The default remains the network-free `FakeProvider`.

## Core rule

    Real LLM suggestion
        != selection
        != eligibility approval
        != explicit end
        != verification
        != encoding_verified
        != Evidence
        != candidate mint
        != winner

LLM suggestion is **advisory and untrusted**.

Suggested output does **not** become an explicit end.

Real LLM output is **not** verification.

## Providers

| CLI `--provider` | Network | Default |
|------------------|---------|---------|
| `fake`           | never   | yes     |
| `openai`         | HTTPS only when explicitly selected | no |

Unknown provider names fail closed with a CLI error.

Missing credentials for a real provider fail closed. There is **no** silent fallback
to `fake`, and environment variables do **not** implicitly select a provider.

## Authentication

- Provider: `openai`
- Environment variable: `OPENAI_API_KEY`
- Credentials are read from the environment only
- Secrets are never written to stdout, stderr, JSON artifacts, errors, rationale,
  or exceptions

## Network boundary

Real network access is allowed **only** when `--provider openai` is explicitly passed.

Implementation uses stdlib HTTPS (`urllib`) — no shell, subprocess, git, tool calling,
ROM access, filesystem traversal beyond local JSON I/O, or Ghidra invocation.

## Request schema (unchanged)

`build_request()` produces the canonical request:

- `address`
- `mode`
- `disposition`
- `sources`
- `classes`
- `evidence_types`
- `deterministic`

### Explicitly excluded from LLM requests

- ROM bytes / ROM path
- filesystem paths
- `Evidence.detail` / raw evidence payload
- `labels.toml`, gamedb
- selection / review_decision
- end / suggested_end / size / recommendedEnd
- verification results
- RANGE information
- encoding verification
- winner information

Sensitive fields are **never placed** in the request. Prompt instruction text and
canonical JSON data are kept logically separate; input strings are data, not instructions.

## Output schema (unchanged v1)

- `format = "gba-mapper-llm-suggestion"`
- `version = 1`

Required per-suggestion metadata:

- `provider`, `model`, `prompt_version`, `input_hash`
- `deterministic = false` (always; real providers cannot claim deterministic truth)
- `rationale`
- allowed `action` values only

Optional additive metadata (run and/or suggestion level):

- `output_hash`, `request_id`, `temperature`, `seed`, `provider_version`

### Forbidden output fields

Including but not limited to:

- `verified`, `winner`, `selection`, disposition rewrite
- `eligible-for-peel`, `human-approved`, `encoding_verified`
- RANGE fields, authoritative end, `select-for-peel`
- **`end`** — a real LLM must not produce an explicit peel end

## Hash semantics

`input_hash = SHA-256(canonical_json(request))` — unchanged.

Provider configuration (provider name, temperature, seed) does **not** alter `input_hash`.

Optional `output_hash` hashes the validated suggestion body; timestamps do not affect it.

`FrontierStore._is_deterministic` is unchanged. Human approval and real LLM output are
not deterministic evidence.

## Failure semantics

Fail closed. No automatic retry. No fallback from a failed real provider to `fake`.

| Condition | Result |
|-----------|--------|
| timeout | `timeout` |
| HTTP 4xx/5xx | `provider-exception` |
| network exception | `provider-exception` |
| authentication failure | `provider-exception` |
| rate limit | `provider-exception` |
| empty response | `invalid-suggestion` |
| malformed JSON | `invalid-suggestion` |
| schema-invalid response | `invalid-suggestion` |

A failed CandidateKey may lose its suggestion; others continue per 7D-B semantics.

Failures do not delete candidates, rewrite disposition/selection, create winners,
eligibility, explicit ends, invoke peel/RANGE, or invoke verification.

## Testing

Unit tests use recorded cassette/fixture responses injected via `fetch`.

The normal test suite is network-free. No test requires API credentials, Internet, or
real provider availability.

Live LLM execution is a **separate opt-in job** and is not part of CI or this phase.

## Non-goals / isolation

Phase 8C does **not**:

- connect automatically to 7D-A, 8A, or 8B
- invoke 7B peel, 7C/RANGE, or encoding verification
- create Evidence or FrontierStore state
- write `labels.toml`, gamedb entries, or sidecars
- modify selection or disposition

Output remains a standalone JSON suggestion artifact.
