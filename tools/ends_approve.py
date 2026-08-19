#!/usr/bin/env python3
"""Phase 8B human explicit-end writer. Not verification, not 7B.

Reads a human-authored explicit-end file and emits a pure 7B EndMap
JSON. Does not invoke peel/wire/RANGE, invent end from suggested_end,
or rewrite 7A selection/disposition.

    suggested_end != human-approved end
    human-approved end != verified end

Usage:
  python3 tools/ends_approve.py --ends-input PATH
      [INPUT]
      [--eligibility-approval PATH]
      [--eligibility PATH]
      [--output PATH]
      [--audit PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROM_BASE = 0x08000000
ROM_WINDOW_END = 0x0A000000
_TARGET_DISP = frozenset({"agreed-seed", "heuristic", "conflicted"})
_MODES = frozenset({"arm", "thumb"})
_FORBIDDEN_HUMAN = frozenset({
    "suggested_end", "decisions", "approvals", "recommendedEnd", "size",
    "confidence", "score", "verified", "range_verified", "encoding_verified",
    "winner", "selection", "disposition", "eligible-for-peel",
    "status",
})
_FORBIDDEN_ENTRY = frozenset({
    "suggested_end", "recommendedEnd", "size", "confidence", "score",
    "verified", "range_verified", "encoding_verified", "winner",
    "selection", "disposition", "eligible-for-peel", "status",
})
_FORBIDDEN_OUT = frozenset({
    "verified", "range_verified", "encoding_verified", "winner",
    "selection", "disposition", "eligible-for-peel", "suggested_end",
    "confidence", "score", "status", "deterministic",
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


def _in_rom_start(addr: int) -> bool:
    return ROM_BASE <= addr < ROM_WINDOW_END


def _in_rom_end(addr: int) -> bool:
    return ROM_BASE < addr <= ROM_WINDOW_END


def _fmt_addr(value) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return f"{int(value):#x}"


def _key(row: dict) -> tuple[int, str] | None:
    try:
        addr = _parse_addr(row.get("address"))
    except (ValueError, TypeError):
        return None
    mode = str(row.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return None
    return (addr, mode)


def _target_keys(phase7a: dict | None) -> dict[tuple[int, str], dict] | None:
    if phase7a is None:
        return None
    seen: set[tuple[int, str]] = set()
    out: dict[tuple[int, str], dict] = {}
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
        out[key] = row
    return out


def _index_8a(raw, errors: list[dict]) -> dict[tuple[int, str], str] | None:
    out: dict[tuple[int, str], str] = {}
    if raw is None:
        return None
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-eligibility-approval"})
        return out
    if raw.get("format") != "gba-mapper-eligibility-approval" or raw.get("version") != 1:
        errors.append({"error": "malformed-eligibility-approval"})
        return out
    seen: set[tuple[int, str]] = set()
    for item in raw.get("approvals") or []:
        if not isinstance(item, dict):
            continue
        key = _key(item)
        if key is None:
            continue
        if key in seen:
            continue
        seen.add(key)
        elig = item.get("eligibility")
        if isinstance(elig, str):
            out[key] = elig
    return out


def _load_human(raw, errors: list[dict]) -> dict[tuple[int, str], dict]:
    out: dict[tuple[int, str], dict] = {}
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-ends-input"})
        return out
    for k in ("suggested_end", "decisions", "approvals"):
        if k in raw:
            errors.append({"error": "forbidden-field", "field": k})
            return out
    if raw.get("format") != "gba-mapper-explicit-end" or raw.get("version") != 1:
        errors.append({"error": "malformed-ends-input"})
        return out
    items = raw.get("ends")
    if not isinstance(items, list):
        errors.append({"error": "malformed-ends-input"})
        return out
    seen: set[tuple[int, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            errors.append({"error": "malformed-end-entry"})
            continue
        forbidden = [k for k in _FORBIDDEN_ENTRY if k in item]
        if forbidden:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "forbidden-field",
            })
            continue
        if "end" not in item:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "needs-human-end",
            })
            continue
        key = _key(item)
        if key is None:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "invalid-end-key",
            })
            continue
        if key in seen:
            continue
        seen.add(key)
        out[key] = item
    return out


def _validate_end(start: int, raw_end) -> tuple[str | None, str | None]:
    try:
        end = _parse_addr(raw_end)
    except (ValueError, TypeError):
        return "invalid-end", None
    if end <= start:
        return "end-le-start", None
    if not _in_rom_start(start) or not _in_rom_end(end):
        return "out-of-rom-window", None
    return None, _fmt_addr(raw_end)


def approve(
    human,
    phase7a=None,
    eligibility_approval=None,
    eligibility=None,
) -> tuple[dict, dict]:
    errors: list[dict] = []
    if eligibility is not None:
        if not isinstance(eligibility, dict) or eligibility.get("format") != "gba-mapper-eligibility":
            errors.append({"error": "malformed-eligibility"})
        else:
            for item in eligibility.get("entries") or []:
                if isinstance(item, dict) and (
                    "suggested_end" in item or "end" in item
                ):
                    # context only: never copied into primary output
                    pass
    targets = _target_keys(phase7a)
    eight_a = _index_8a(eligibility_approval, errors)
    human_map = _load_human(human, errors)
    ends: dict[str, dict] = {}
    for key, item in human_map.items():
        addr, mode = key
        if targets is not None and key not in targets:
            errors.append({
                "address": str(item.get("address")),
                "mode": mode,
                "error": "unknown-candidate",
            })
            continue
        why, end_s = _validate_end(addr, item.get("end"))
        if why:
            errors.append({
                "address": str(item.get("address")),
                "mode": mode,
                "error": why,
            })
            continue
        prior = eight_a.get(key) if eight_a is not None else None
        if eight_a is not None and prior != "eligible-for-peel":
            errors.append({
                "address": str(item.get("address")),
                "mode": mode,
                "error": "eligibility-mismatch",
            })
        map_key = f"{_fmt_addr(item.get('address'))}:{mode}"
        payload = {"end": end_s}
        for k in _FORBIDDEN_OUT:
            payload.pop(k, None)
        ends[map_key] = payload
    audit = {
        "format": "gba-mapper-explicit-end-run",
        "version": 1,
        "run": {"deterministic": False},
        "errors": errors,
    }
    return ends, audit


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", nargs="?", type=Path, help="optional Phase 7A JSON")
    p.add_argument("--ends-input", type=Path, required=True,
                   help="human gba-mapper-explicit-end JSON")
    p.add_argument("--eligibility-approval", type=Path,
                   help="optional Phase 8A approval JSON")
    p.add_argument("--eligibility", type=Path, help="optional Phase 7D-C JSON")
    p.add_argument("--output", type=Path, help="write EndMap JSON (default: stdout)")
    p.add_argument("--audit", type=Path, help="write audit JSON")
    a = p.parse_args(argv)
    human = json.loads(a.ends_input.read_text())
    phase7a = json.loads(a.input.read_text()) if a.input else None
    eight_a = json.loads(a.eligibility_approval.read_text()) if a.eligibility_approval else None
    elig = json.loads(a.eligibility.read_text()) if a.eligibility else None
    ends, audit = approve(human, phase7a, eight_a, elig)
    blob = json.dumps(ends, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    if a.audit is not None:
        a.audit.write_text(json.dumps(audit, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
