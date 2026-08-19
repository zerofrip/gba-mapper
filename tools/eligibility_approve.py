#!/usr/bin/env python3
"""Phase 8A human eligibility approval. Overlay only. Not 7B.

Reads Phase 7A skipped candidates and an explicit human approval
file. Emits a standalone approval artifact. Does not rewrite 7A
selection/disposition, mint candidates, invent --ends, or invoke 7B.

    eligible-for-peel != selected
    eligible-for-peel != peel-ready
    eligible-for-peel != RANGE_VERIFIED

Usage:
  python3 tools/eligibility_approve.py INPUT
      [--approval APPROVAL.json]
      [--eligibility ELIG.json]
      [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_TARGET_DISP = frozenset({"agreed-seed", "heuristic", "conflicted"})
_MODES = frozenset({"arm", "thumb"})
_APPROVE = "eligible-for-peel"
_FORBIDDEN = frozenset({
    "status", "range_verified", "encoding_verified",
    "winner", "confidence", "score", "verified", "end",
    "selection", "disposition", "select-for-peel", "suggested_end",
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


def _target_keys(phase7a: dict) -> dict[tuple[int, str], dict]:
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


def _index_7dc(raw, errors: list[dict]) -> dict[tuple[int, str], str]:
    out: dict[tuple[int, str], str] = {}
    if raw is None:
        return out
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-eligibility"})
        return out
    if raw.get("format") != "gba-mapper-eligibility" or raw.get("version") != 1:
        errors.append({"error": "malformed-eligibility"})
        return out
    seen: set[tuple[int, str]] = set()
    for item in raw.get("entries") or []:
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
    if raw is None:
        return out
    if not isinstance(raw, dict):
        errors.append({"error": "malformed-approval"})
        return out
    if raw.get("format") != "gba-mapper-eligibility-approval" or raw.get("version") != 1:
        errors.append({"error": "malformed-approval"})
        return out
    items = raw.get("approvals")
    if items is None:
        items = raw.get("decisions")
    if not isinstance(items, list):
        errors.append({"error": "malformed-approval"})
        return out
    seen: set[tuple[int, str]] = set()
    for item in items:
        if not isinstance(item, dict):
            errors.append({"error": "malformed-approval-entry"})
            continue
        forbidden = [k for k in _FORBIDDEN if k in item]
        if forbidden:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "forbidden-field",
            })
            continue
        key = _key(item)
        if key is None:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode")),
                "error": "invalid-approval-key",
            })
            continue
        elig = item.get("eligibility")
        if elig != _APPROVE:
            errors.append({
                "address": str(item.get("address")),
                "mode": key[1],
                "error": "invalid-eligibility",
            })
            continue
        if key in seen:
            continue
        seen.add(key)
        out[key] = item
    return out


def approve(phase7a: dict, approval=None, eligibility=None) -> dict:
    errors: list[dict] = []
    targets = _target_keys(phase7a)
    human = _load_human(approval, errors)
    elig_index = _index_7dc(eligibility, errors)
    approvals: list[dict] = []
    for key, item in human.items():
        row = targets.get(key)
        if row is None:
            errors.append({
                "address": str(item.get("address")),
                "mode": key[1],
                "error": "unknown-candidate",
            })
            continue
        prior = elig_index.get(key)
        if prior is not None and prior != "eligible-for-review":
            errors.append({
                "address": str(row.get("address")),
                "mode": key[1],
                "error": "eligibility-mismatch",
                "seven_dc": prior,
            })
        approvals.append({
            "address": str(row.get("address")),
            "mode": key[1],
            "eligibility": _APPROVE,
            "deterministic": False,
        })
    return {
        "format": "gba-mapper-eligibility-approval",
        "version": 1,
        "run": {"deterministic": False},
        "approvals": approvals,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--approval", type=Path, help="human eligibility-approval JSON")
    p.add_argument("--eligibility", type=Path, help="optional Phase 7D-C JSON")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    phase7a = json.loads(a.input.read_text())
    approval = json.loads(a.approval.read_text()) if a.approval else None
    eligibility = json.loads(a.eligibility.read_text()) if a.eligibility else None
    result = approve(phase7a, approval, eligibility)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
