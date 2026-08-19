#!/usr/bin/env python3
"""Phase 8D encoding-claim writer. Advisory only. Not verification.

Reads Phase 7A candidates and explicit claim inputs. Emits a standalone
encoding-claim artifact. Does not create encoding_verified, alter
selection/disposition, mint candidates, or invoke 7B/7C/RANGE.

    candidate.mode != encoding_verified
    human claim != encoding_verified
    LLM claim != encoding_verified
    Ghidra claim != encoding_verified

Usage:
  python3 tools/encoding_claim.py INPUT
      [--claims CLAIMS.json]
      [--llm LLM.json]
      [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_TARGET_DISP = frozenset({"agreed-seed", "heuristic", "conflicted"})
_MODES = frozenset({"arm", "thumb"})
_SOURCES = frozenset({"human", "ghidra", "deterministic", "llm"})
_LLM_MODE_ACTIONS = {
    "arm-plausible": "arm",
    "thumb-plausible": "thumb",
}
_FORBIDDEN = frozenset({
    "encoding_verified", "verified", "range_verified",
    "winner", "selection", "disposition",
    "end", "suggested_end", "eligible-for-peel",
    "peel-ready", "selected",
})


def _parse_addr(value) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid address")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("invalid address")
        return value
    s = str(value).strip()
    if not s or s.startswith("-"):
        raise ValueError("invalid address")
    return int(s, 0)


def _key(row: dict) -> tuple[int, str] | None:
    try:
        addr = _parse_addr(row.get("address"))
    except (ValueError, TypeError):
        return None
    mode = str(row.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return None
    return (addr, mode)


def _candidate_keys(phase7a: dict) -> dict[tuple[int, str], dict]:
    seen: set[tuple[int, str]] = set()
    out: dict[tuple[int, str], dict] = {}
    for row in phase7a.get("selected") or []:
        if not isinstance(row, dict):
            continue
        key = _key(row)
        if key is None or key in seen:
            continue
        seen.add(key)
        out[key] = row
    for row in phase7a.get("skipped") or []:
        if not isinstance(row, dict):
            continue
        key = _key(row)
        if key is None or key in seen:
            continue
        if row.get("disposition") not in _TARGET_DISP:
            continue
        seen.add(key)
        out[key] = row
    return out


def _reject_deterministic(item: dict, errors: list[dict]) -> bool:
    if item.get("deterministic") is True:
        errors.append({
            "address": str(item.get("address")),
            "mode": str(item.get("mode") or ""),
            "error": "deterministic-rejected",
        })
        return True
    return False


def _forbidden_fields(item: dict) -> list[str]:
    return [k for k in _FORBIDDEN if k in item]


def _normalize_claim(item: dict, *, default_source: str | None = None) -> dict | None:
    source = str(item.get("source") or default_source or "").strip().lower()
    claim = str(item.get("claim") or "").strip().lower()
    if not source or not claim:
        return None
    out = {
        "address": item.get("address"),
        "mode": str(item.get("mode") or "").strip().lower(),
        "source": source,
        "claim": claim,
    }
    if "rationale" in item:
        out["rationale"] = str(item["rationale"])
    return out


def _load_claim_entries(raw, errors: list[dict]) -> list[dict]:
    if raw is None:
        return []
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-claims"})
        return []
    if raw.get("format") != "gba-mapper-encoding-claim-input" or raw.get("version") != 1:
        errors.append({"error": "malformed-claims"})
        return []
    items = raw.get("claims")
    if items is None:
        items = raw.get("entries")
    if not isinstance(items, list):
        errors.append({"error": "malformed-claims"})
        return []
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            errors.append({"error": "malformed-claim-entry"})
            continue
        out.append(item)
    return out


def _load_llm_entries(raw, errors: list[dict]) -> list[dict]:
    if raw is None:
        return []
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-llm"})
        return []
    if raw.get("format") != "gba-mapper-llm-suggestion" or raw.get("version") != 1:
        errors.append({"error": "malformed-llm"})
        return []
    items = raw.get("suggestions")
    if not isinstance(items, list):
        errors.append({"error": "malformed-llm"})
        return []
    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        action = item.get("action")
        claim = _LLM_MODE_ACTIONS.get(action)
        if claim is None:
            continue
        entry = {
            "address": item.get("address"),
            "mode": item.get("mode"),
            "source": "llm",
            "claim": claim,
        }
        if "rationale" in item:
            entry["rationale"] = item.get("rationale")
        out.append(entry)
    return out


def _process_claim(item: dict, candidates: dict[tuple[int, str], dict], errors: list[dict]) -> dict | None:
    forbidden = _forbidden_fields(item)
    if forbidden:
        errors.append({
            "address": str(item.get("address")),
            "mode": str(item.get("mode") or ""),
            "error": "forbidden-field",
        })
        return None
    if _reject_deterministic(item, errors):
        return None
    norm = _normalize_claim(item)
    if norm is None:
        errors.append({
            "address": str(item.get("address")),
            "mode": str(item.get("mode") or ""),
            "error": "invalid-claim-entry",
        })
        return None
    key = _key(norm)
    if key is None:
        err = "address-only" if norm.get("address") and not norm.get("mode") else "invalid-claim-key"
        errors.append({
            "address": str(norm.get("address")),
            "mode": str(norm.get("mode") or ""),
            "error": err,
        })
        return None
    if norm["source"] not in _SOURCES:
        errors.append({
            "address": str(norm.get("address")),
            "mode": key[1],
            "error": "invalid-source",
        })
        return None
    if norm["claim"] not in _MODES:
        errors.append({
            "address": str(norm.get("address")),
            "mode": key[1],
            "error": "invalid-claim",
        })
        return None
    if norm["claim"] != key[1]:
        errors.append({
            "address": str(norm.get("address")),
            "mode": key[1],
            "error": "mode-mismatch",
        })
        return None
    if key not in candidates:
        errors.append({
            "address": str(norm.get("address")),
            "mode": key[1],
            "error": "unknown-candidate",
        })
        return None
    row = candidates[key]
    out = {
        "address": str(row.get("address")),
        "mode": key[1],
        "source": norm["source"],
        "claim": norm["claim"],
    }
    if "rationale" in norm:
        out["rationale"] = norm["rationale"]
    return out


def build_claims(phase7a: dict, claims_input=None, llm_input=None) -> dict:
    errors: list[dict] = []
    candidates = _candidate_keys(phase7a)
    claim_items = _load_claim_entries(claims_input, errors)
    llm_items = _load_llm_entries(llm_input, errors)
    claims: list[dict] = []
    seen: set[tuple[int, str, str]] = set()
    for item in claim_items + llm_items:
        processed = _process_claim(item, candidates, errors)
        if processed is None:
            continue
        dedupe = (_parse_addr(processed["address"]), processed["mode"], processed["source"])
        if dedupe in seen:
            continue
        seen.add(dedupe)
        claims.append(processed)
    return {
        "format": "gba-mapper-encoding-claim",
        "version": 1,
        "run": {"deterministic": False},
        "claims": claims,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--claims", type=Path, help="encoding-claim input JSON")
    p.add_argument("--llm", type=Path, help="Phase 8C LLM suggestion JSON (read only)")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    phase7a = json.loads(a.input.read_text())
    claims_input = json.loads(a.claims.read_text()) if a.claims else None
    llm_input = json.loads(a.llm.read_text()) if a.llm else None
    result = build_claims(phase7a, claims_input, llm_input)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
