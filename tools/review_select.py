#!/usr/bin/env python3
"""Human-review overlay for Phase 7A JSON. Not selection, not verification.

Records which CandidateKey a reviewer wanted to select for peel.
Does not change 7A selected/skipped, disposition, Evidence, or end.

    review decision != Phase 7A selection
    review decision != verification
    review decision != end

Usage:
  python3 tools/review_select.py INPUT [--review REVIEW.json] [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ALLOWED = frozenset({
    "select-for-peel", "keep-skipped", "defer", "reject-as-data",
})
_FORBIDDEN = (
    "status", "range_verified", "encoding_verified",
    "winner", "confidence", "score", "verified", "end",
)
_MODE_ORDER = {"arm": 0, "thumb": 1}
_MODES = frozenset({"arm", "thumb"})


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


def _copy_row(row: dict) -> dict:
    out = dict(row)
    for k in _FORBIDDEN:
        out.pop(k, None)
    return out


def _copy_unresolved(row: dict) -> dict:
    out = dict(row)
    out.pop("selection", None)
    out.pop("skip_reason", None)
    out.pop("review_decision", None)
    for k in _FORBIDDEN:
        out.pop(k, None)
    return out


def _key_from_row(row: dict) -> tuple[int, str] | None:
    try:
        addr = _parse_addr(row.get("address"))
    except (ValueError, TypeError):
        return None
    mode = str(row.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return None
    return (addr, mode)


def load_review(raw) -> dict[tuple[int, str], dict]:
    """Return first-wins map of valid decisions. Invalid entries dropped."""
    if not isinstance(raw, dict):
        return {}
    if raw.get("format") != "gba-mapper-review" or raw.get("version") != 1:
        return {}
    decisions = raw.get("decisions")
    if not isinstance(decisions, list):
        return {}
    out: dict[tuple[int, str], dict] = {}
    for item in decisions:
        parsed = _validate_decision(item)
        if parsed is None:
            continue
        key = parsed["key"]
        if key in out:
            continue
        out[key] = parsed
    return out


def _validate_decision(item) -> dict | None:
    if not isinstance(item, dict):
        return None
    for k in _FORBIDDEN:
        if k in item:
            return None
    if "end" in item:
        return None
    decision = item.get("decision")
    if decision not in _ALLOWED:
        return None
    mode = str(item.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return None
    try:
        addr = _parse_addr(item.get("address"))
    except (ValueError, TypeError):
        return None
    parsed = {"key": (addr, mode), "decision": decision}
    note = item.get("note")
    if note is not None:
        parsed["note"] = str(note)
    reviewer = item.get("reviewer")
    if reviewer is not None:
        parsed["reviewer"] = str(reviewer)
    return parsed


def _skipped_index(skipped: list[dict]) -> set[tuple[int, str]]:
    keys: set[tuple[int, str]] = set()
    for row in skipped:
        k = _key_from_row(row)
        if k is not None:
            keys.add(k)
    return keys


def apply_overlay(phase7a: dict, review_map: dict[tuple[int, str], dict]) -> dict:
    selected = [_copy_row(r) for r in (phase7a.get("selected") or [])]
    skipped_in = list(phase7a.get("skipped") or [])
    unresolved = [_copy_unresolved(r) for r in (phase7a.get("unresolved") or [])]
    present = _skipped_index(skipped_in)
    skipped = []
    for row in skipped_in:
        copied = _copy_row(row)
        key = _key_from_row(row)
        if key is not None and key in review_map and key in present:
            dec = review_map[key]
            if dec["decision"] == "select-for-peel" or dec["decision"] in _ALLOWED:
                copied["review_decision"] = dec["decision"]
                if "note" in dec:
                    copied["review_note"] = dec["note"]
                if "reviewer" in dec:
                    copied["reviewer"] = dec["reviewer"]
        skipped.append(copied)
    return {
        "selected": selected,
        "skipped": skipped,
        "unresolved": unresolved,
        "queue": _queue(skipped_in, phase7a.get("unresolved") or []),
    }


def _queue(skipped: list[dict], unresolved: list[dict]) -> list[dict]:
    rows = []
    sortable = []
    for row in skipped:
        key = _key_from_row(row)
        if key is None:
            continue
        sortable.append((key[0], _MODE_ORDER.get(key[1], 99), row))
    sortable.sort(key=lambda t: (t[0], t[1]))
    for _, _, row in sortable:
        item = {
            "kind": "skipped",
            "address": row.get("address"),
            "mode": row.get("mode"),
        }
        if "disposition" in row:
            item["disposition"] = row["disposition"]
        if "skip_reason" in row:
            item["skip_reason"] = row["skip_reason"]
        rows.append(item)
    for u in unresolved:
        item = {"kind": "unresolved"}
        for k, v in u.items():
            if k in ("selection", "skip_reason", "review_decision"):
                continue
            if k in _FORBIDDEN:
                continue
            item[k] = v
        rows.append(item)
    return rows


def review_select(phase7a: dict, review_raw=None) -> dict:
    review_map = load_review(review_raw) if review_raw is not None else {}
    return apply_overlay(phase7a, review_map)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--review", type=Path, help="optional gba-mapper-review JSON")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    phase7a = json.loads(a.input.read_text())
    review_raw = json.loads(a.review.read_text()) if a.review is not None else None
    result = review_select(phase7a, review_raw)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
