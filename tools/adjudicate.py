#!/usr/bin/env python3
"""Read-only candidate adjudication. Not verification.

Computes disposition / sources / classes from existing provenance.
Does not peel, promote RANGE/ENCODING, or choose a winner.

    CandidateKey = (address, mode)
    disposition != status
    agreement != verification
    peel-ready != RANGE_VERIFIED

Ghidra remains ghidra-seed / source=ghidra (STATIC_ANALYSIS_ORACLE).
This tool does not write labels.toml, the evidence sidecar, or gamedb.

Usage:
  python3 tools/adjudicate.py INPUT [INPUT ...] [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence_merge

_CONTROL_FLOW = frozenset({"bl-target", "bx-target", "vector-entry"})
_ORACLE_SEED = frozenset({"ghidra-seed", "decomp-reference"})
_HEURISTIC = frozenset({"gap", "manual-seed"})

_DISP_ORDER = {
    "peel-ready": 0,
    "agreed-seed": 1,
    "heuristic": 2,
    "conflicted": 3,
}
_MODE_ORDER = {"arm": 0, "thumb": 1}


def _item_class(item: dict) -> str | None:
    typ = item.get("type")
    if typ in _CONTROL_FLOW:
        if item.get("target_addr") is not None and item.get("target_mode") is not None:
            return "control-flow"
        return None
    if typ in _ORACLE_SEED:
        return "oracle-seed"
    if typ in _HEURISTIC:
        return "heuristic"
    return None


def _sources(items: list[dict]) -> list[str]:
    seen: list[str] = []
    have: set[str] = set()
    for item in items:
        src = item.get("source")
        if src and src not in have:
            have.add(src)
            seen.append(src)
    return seen


def _classes(items: list[dict]) -> list[str]:
    seen: list[str] = []
    have: set[str] = set()
    for item in items:
        cls = _item_class(item)
        if cls and cls not in have:
            have.add(cls)
            seen.append(cls)
    return seen


def _disposition(classes: list[str], sources: list[str], conflicted: bool) -> str:
    if conflicted:
        return "conflicted"
    if "control-flow" in classes:
        return "peel-ready"
    if len(sources) >= 2:
        return "agreed-seed"
    return "heuristic"


def _annotate(rows: list[dict]) -> list[dict]:
    by_addr: dict[int, set[str]] = {}
    parsed: list[tuple[int, str, dict]] = []
    for row in rows:
        addr = int(row["address"], 16)
        mode = row["mode"]
        by_addr.setdefault(addr, set()).add(mode)
        parsed.append((addr, mode, row))
    dual = {addr for addr, modes in by_addr.items() if modes == {"arm", "thumb"}}
    out = []
    for addr, mode, row in parsed:
        items = list(row.get("evidence_items") or [])
        sources = _sources(items)
        classes = _classes(items)
        disp = _disposition(classes, sources, addr in dual)
        annotated = dict(row)
        annotated["disposition"] = disp
        annotated["sources"] = sources
        annotated["classes"] = classes
        out.append(annotated)
    out.sort(
        key=lambda r: (
            _DISP_ORDER[r["disposition"]],
            int(r["address"], 16),
            _MODE_ORDER.get(r["mode"], 99),
        )
    )
    return out


class Adjudicator:
    """Disposition over a FrontierStore. No winner, no verification."""

    def __init__(self) -> None:
        self.merger = evidence_merge.EvidenceMerger()

    def ingest(self, frontier_obj) -> None:
        self.merger.merge_frontier(frontier_obj)

    def add(self, address: int, mode: str, evidence_in) -> None:
        self.merger.add(address, mode, evidence_in)

    def to_json(self) -> dict:
        base = self.merger.to_json()
        return {
            "candidates": _annotate(base["candidates"]),
            "unresolved": base["unresolved"],
        }


def adjudicate_files(paths: list[Path]) -> dict:
    adj = Adjudicator()
    for path in paths:
        adj.ingest(json.loads(path.read_text()))
    return adj.to_json()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("inputs", nargs="+", type=Path, help="frontier JSON path(s)")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    result = adjudicate_files(a.inputs)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
