#!/usr/bin/env python3
"""Select peel-ready candidates. Not peel, not verification.

Reads Phase 6A adjudicated frontier JSON and splits candidates into
selected / skipped. Does not invent end, run peel.py, or promote RANGE.

    peel recommendation != peel success
    peel-ready != RANGE_VERIFIED

Usage:
  python3 tools/select_peel.py INPUT [INPUT ...] [--limit N] [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adjudicate

_SKIP_REASON = {
    "agreed-seed": "no control-flow",
    "heuristic": "heuristic/oracle only",
    "conflicted": "dual-mode conflict",
}
_FORBIDDEN = (
    "status", "range_verified", "encoding_verified",
    "winner", "confidence", "score",
)
_END_KEYS = ("end", "size", "recommendedEnd")


def _copy_candidate(row: dict) -> dict:
    out = dict(row)
    for k in _FORBIDDEN:
        out.pop(k, None)
    for k in _END_KEYS:
        if k not in row:
            out.pop(k, None)
    return out


def _split(adj_json: dict, limit: int | None) -> dict:
    selected: list[dict] = []
    skipped: list[dict] = []
    n_sel = 0
    for row in adj_json.get("candidates") or []:
        disp = row.get("disposition")
        copied = _copy_candidate(row)
        if disp == "peel-ready":
            if limit is None or n_sel < limit:
                copied["selection"] = "selected"
                selected.append(copied)
                n_sel += 1
            else:
                copied["selection"] = "skipped"
                copied["skip_reason"] = "selection-cap"
                skipped.append(copied)
            continue
        copied["selection"] = "skipped"
        copied["skip_reason"] = _SKIP_REASON.get(disp, "heuristic/oracle only")
        skipped.append(copied)
    unresolved = list(adj_json.get("unresolved") or [])
    return {
        "selected": selected,
        "skipped": skipped,
        "unresolved": unresolved,
    }


class PeelSelector:
    """Deterministic peel-ready selection. Does not execute peel."""

    def __init__(self, limit: int | None = None) -> None:
        if limit is not None and limit < 0:
            raise ValueError("limit must be >= 0")
        self.limit = limit
        self.adj = adjudicate.Adjudicator()

    def ingest(self, frontier_obj) -> None:
        self.adj.ingest(frontier_obj)

    def add(self, address: int, mode: str, evidence_in) -> None:
        self.adj.add(address, mode, evidence_in)

    def select(self, frontier_obj=None) -> dict:
        if frontier_obj is not None:
            self.ingest(frontier_obj)
        return _split(self.adj.to_json(), self.limit)


def select_files(paths: list[Path], limit: int | None = None) -> dict:
    sel = PeelSelector(limit=limit)
    for path in paths:
        sel.ingest(json.loads(path.read_text()))
    return sel.select()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("inputs", nargs="+", type=Path, help="adjudicated/frontier JSON")
    p.add_argument("--limit", type=int, default=None,
                   help="cap selected count only (not frontier --max)")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    if a.limit is not None and a.limit < 0:
        p.error("--limit must be >= 0")
    result = select_files(a.inputs, limit=a.limit)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
