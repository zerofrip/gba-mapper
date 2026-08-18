#!/usr/bin/env python3
"""Phase 7D-C eligibility / suggested_end overlay. Advisory only.

Reads Phase 7A skipped rows (agreed-seed / heuristic / conflicted) and
emits a standalone eligibility artifact. Does not mint candidates,
rewrite disposition/selection, create a 7D-A review, invent --ends,
or invoke 7B/7C.

    eligibility != selection
    eligibility != verification
    suggested_end != verified end
    suggested_end != 7B --ends

Usage:
  python3 tools/eligibility.py INPUT
      [--suggestions SUGGESTIONS.json]
      [--suggested-ends ENDS.json]
      [--output PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_TARGET_DISP = frozenset({"agreed-seed", "heuristic", "conflicted"})
_MODES = frozenset({"arm", "thumb"})
_ELIG = frozenset({
    "eligible-for-review",
    "not-eligible",
    "needs-human-review",
})
_END_SOURCES = frozenset({
    "llm", "human", "boundary-recommendation", "ghidra", "manual",
})
_SUGGEST_ACTIONS = frozenset({
    "review",
    "possible-control-flow",
    "possible-data",
    "possible-invalid",
    "insufficient-evidence",
    "arm-plausible",
    "thumb-plausible",
})
_FORBIDDEN_OUT = frozenset({
    "selection", "review_decision", "status", "verified",
    "range_verified", "encoding_verified", "winner", "confidence", "score",
})
_FORBIDDEN_SUGGEST = frozenset({
    "verified", "range_verified", "encoding_verified",
    "winner", "confidence", "score", "end", "status",
    "select-for-peel", "selection", "disposition",
})
_ACTION_MAP = {
    "possible-control-flow": "eligible-for-review",
    "possible-data": "not-eligible",
    "possible-invalid": "not-eligible",
    "insufficient-evidence": "needs-human-review",
    "review": "needs-human-review",
}


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def input_hash(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


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


def build_request(row: dict) -> dict:
    types: list[str] = []
    for item in row.get("evidence_items") or []:
        if isinstance(item, dict) and item.get("type"):
            types.append(str(item["type"]))
    return {
        "address": str(row.get("address")),
        "mode": str(row.get("mode") or "").strip().lower(),
        "disposition": row.get("disposition"),
        "sources": list(row.get("sources") or []),
        "classes": list(row.get("classes") or []),
        "evidence_types": types,
        "deterministic": row.get("deterministic"),
    }


def _fmt_addr(value) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return f"{int(value):#x}"


def _load_json(path: Path | None):
    if path is None:
        return None
    return json.loads(path.read_text())


def _parse_suggested_ends(raw, errors: list[dict]) -> dict[tuple[int, str], dict]:
    out: dict[tuple[int, str], dict] = {}
    if raw is None:
        return out
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-suggested-ends"})
        return out
    items = raw.get("entries") if "entries" in raw else None
    if isinstance(items, list):
        pairs = []
        for item in items:
            if not isinstance(item, dict):
                errors.append({"error": "malformed-suggested-end"})
                continue
            pairs.append((item, item))
    else:
        pairs = []
        for key, spec in raw.items():
            if key in {"format", "version"}:
                continue
            pairs.append((str(key), spec))
    seen: set[tuple[int, str]] = set()
    for ident, spec in pairs:
        parsed = _one_suggested_end(ident, spec, errors)
        if parsed is None:
            continue
        key, payload = parsed
        if key in seen:
            continue
        seen.add(key)
        out[key] = payload
    return out


def _one_suggested_end(ident, spec, errors: list[dict]) -> tuple[tuple[int, str], dict] | None:
    addr_s = None
    mode = None
    if isinstance(ident, dict):
        addr_s = ident.get("address")
        mode = str(ident.get("mode") or "").strip().lower()
        if isinstance(spec, dict):
            end_raw = spec.get("suggested_end", spec.get("end", ident.get("suggested_end")))
            source = spec.get("end_source", spec.get("source", ident.get("end_source", "human")))
        else:
            end_raw = ident.get("suggested_end", ident.get("end"))
            source = ident.get("end_source", "human")
    else:
        key = str(ident)
        if ":" not in key:
            errors.append({"error": "address-only-end-mapping", "key": key})
            return None
        addr_s, mode = key.rsplit(":", 1)
        mode = mode.strip().lower()
        if isinstance(spec, dict):
            end_raw = spec.get("suggested_end", spec.get("end"))
            source = spec.get("end_source", spec.get("source", "human"))
        else:
            end_raw = spec
            source = "human"
    if mode not in _MODES:
        errors.append({"error": "invalid-mode", "address": str(addr_s), "mode": str(mode)})
        return None
    try:
        start_or_addr = _parse_addr(addr_s)
    except (ValueError, TypeError):
        errors.append({"error": "invalid-address", "address": str(addr_s)})
        return None
    source = str(source or "human")
    if source not in _END_SOURCES:
        errors.append({
            "address": _fmt_addr(addr_s), "mode": mode,
            "error": "invalid-end-source",
        })
        return None
    try:
        end = _parse_addr(end_raw)
    except (ValueError, TypeError):
        errors.append({
            "address": _fmt_addr(addr_s), "mode": mode,
            "error": "invalid-suggested-end",
        })
        return None
    if end <= start_or_addr:
        errors.append({
            "address": _fmt_addr(addr_s), "mode": mode,
            "error": "invalid-suggested-end",
        })
        return None
    return (start_or_addr, mode), {
        "suggested_end": _fmt_addr(end_raw),
        "end_source": source,
    }


def _index_suggestions(raw, errors: list[dict]) -> dict[tuple[int, str], dict]:
    out: dict[tuple[int, str], dict] = {}
    if raw is None:
        return out
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-suggestions"})
        return out
    if raw.get("format") != "gba-mapper-llm-suggestion" or raw.get("version") != 1:
        errors.append({"error": "malformed-suggestions"})
        return out
    seen: set[tuple[int, str]] = set()
    for item in raw.get("suggestions") or []:
        if not isinstance(item, dict):
            errors.append({"error": "malformed-suggestion"})
            continue
        forbidden = [k for k in _FORBIDDEN_SUGGEST if k in item]
        if forbidden:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "forbidden-suggestion-field",
            })
            continue
        key = _key(item)
        if key is None:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "invalid-suggestion-key",
            })
            continue
        action = item.get("action")
        if action not in _SUGGEST_ACTIONS:
            errors.append({
                "address": str(item.get("address")),
                "mode": key[1],
                "error": "unknown-action",
            })
            continue
        for field in ("provider", "model", "prompt_version", "input_hash"):
            if not item.get(field):
                errors.append({
                    "address": str(item.get("address")),
                    "mode": key[1],
                    "error": "missing-suggestion-metadata",
                })
                break
        else:
            if key in seen:
                continue
            seen.add(key)
            out[key] = item
    return out


def _map_action(action: str, mode: str) -> str | None:
    if action == "arm-plausible":
        return "eligible-for-review" if mode == "arm" else None
    if action == "thumb-plausible":
        return "eligible-for-review" if mode == "thumb" else None
    return _ACTION_MAP.get(action)


def overlay(phase7a: dict, suggestions=None, suggested_ends=None) -> dict:
    errors: list[dict] = []
    sug_index = _index_suggestions(suggestions, errors)
    end_index = _parse_suggested_ends(suggested_ends, errors)
    entries: list[dict] = []
    seen: set[tuple[int, str]] = set()
    requests: list[dict] = []
    for row in phase7a.get("skipped") or []:
        if not isinstance(row, dict):
            continue
        key = _key(row)
        if key is None:
            continue
        if row.get("disposition") not in _TARGET_DISP:
            continue
        if key in seen:
            continue
        seen.add(key)
        req = build_request(row)
        requests.append(req)
        addr_s = str(row.get("address"))
        mode = key[1]
        eligibility = "needs-human-review"
        rationale = ""
        suggestion_meta = None
        sug = sug_index.get(key)
        if sug is not None:
            expected = input_hash(req)
            got = str(sug.get("input_hash") or "")
            if got != expected:
                errors.append({
                    "address": addr_s, "mode": mode, "error": "stale-input-hash",
                })
            else:
                mapped = _map_action(str(sug.get("action")), mode)
                if mapped is None:
                    errors.append({
                        "address": addr_s, "mode": mode, "error": "action-mode-mismatch",
                    })
                else:
                    eligibility = mapped
                    rationale = str(sug["rationale"]) if "rationale" in sug else ""
                    suggestion_meta = {
                        "action": sug.get("action"),
                        "provider": sug.get("provider"),
                        "model": sug.get("model"),
                        "prompt_version": sug.get("prompt_version"),
                        "input_hash": sug.get("input_hash"),
                    }
        entry = {
            "address": addr_s,
            "mode": mode,
            "disposition": row.get("disposition"),
            "eligibility": eligibility,
            "rationale": rationale,
            "deterministic": False,
        }
        end_payload = end_index.get(key)
        if end_payload:
            entry["suggested_end"] = end_payload["suggested_end"]
            entry["end_source"] = end_payload["end_source"]
        if suggestion_meta:
            entry["suggestion"] = suggestion_meta
        for k in _FORBIDDEN_OUT:
            entry.pop(k, None)
        if entry["eligibility"] not in _ELIG:
            entry["eligibility"] = "needs-human-review"
        entries.append(entry)
    run = {"phase7a_hash": input_hash({"requests": requests})}
    if suggestions is not None:
        run["suggestion_hash"] = input_hash(suggestions)
    if suggested_ends is not None:
        run["suggested_ends_hash"] = input_hash(suggested_ends)
    return {
        "format": "gba-mapper-eligibility",
        "version": 1,
        "run": run,
        "entries": entries,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--suggestions", type=Path, help="Phase 7D-B suggestion JSON")
    p.add_argument("--suggested-ends", type=Path, help="advisory (address, mode) end map")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    phase7a = json.loads(a.input.read_text())
    suggestions = _load_json(a.suggestions)
    suggested_ends = _load_json(a.suggested_ends)
    result = overlay(phase7a, suggestions, suggested_ends)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
