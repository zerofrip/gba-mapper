#!/usr/bin/env python3
"""Reconcile frontier-compatible JSON by CandidateKey.

Phase 5 merges provenance. It does not verify, accept, or rank
candidates. agreement != verification.

    CandidateKey = (address, mode)

Insertion uses only FrontierStore.add_candidate. Ghidra remains
ghidra-seed / source=ghidra (STATIC_ANALYSIS_ORACLE). This tool
does not write labels.toml, the evidence sidecar, or gamedb.

Usage:
  python3 tools/evidence_merge.py INPUT [INPUT ...] [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence
import frontier


def _parse_addr(value) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid address")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("invalid address")
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("invalid address")
    s = s.lower().replace("_", "")
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def _evidence_list(raw) -> list[evidence.Evidence]:
    if not raw:
        return []
    if isinstance(raw, evidence.Evidence):
        return [raw]
    out: list[evidence.Evidence] = []
    for item in raw:
        if item is None:
            continue
        if isinstance(item, evidence.Evidence):
            out.append(item)
        elif isinstance(item, dict):
            out.append(evidence.Evidence.from_json(item))
    return out


class EvidenceMerger:
    """Union provenance onto FrontierStore. No winner, no verification."""

    def __init__(self) -> None:
        self.store = frontier.FrontierStore()

    def add(self, address: int, mode: str, evidence_in) -> None:
        self.store.add_candidate(address, mode, evidence_in)

    def merge_candidate(self, candidate) -> None:
        if not isinstance(candidate, dict):
            return
        items = _evidence_list(candidate.get("evidence_items"))
        if not items:
            return
        if "address" not in candidate or "mode" not in candidate:
            return
        mode = str(candidate["mode"]).strip().lower()
        if mode not in ("arm", "thumb"):
            return
        try:
            address = _parse_addr(candidate["address"])
        except (ValueError, TypeError):
            return
        self.store.add_candidate(address, mode, items)

    def merge_frontier(self, frontier_in) -> None:
        if isinstance(frontier_in, dict):
            for cand in frontier_in.get("candidates") or []:
                self.merge_candidate(cand)
            for item in frontier_in.get("unresolved") or []:
                self._add_unresolved(item)
            return
        if isinstance(frontier_in, list):
            for cand in frontier_in:
                self.merge_candidate(cand)

    def _add_unresolved(self, raw) -> None:
        if isinstance(raw, evidence.Evidence):
            self.store.add_unresolved(raw)
            return
        if isinstance(raw, dict):
            self.store.add_unresolved(evidence.Evidence.from_json(raw))

    def sources(self, address: int, mode: str) -> list[str]:
        """Observed source set for a key. Not a trust score."""
        seen: list[str] = []
        have: set[str] = set()
        for row in self.store.to_json_list():
            if int(row["address"], 16) != address or row["mode"] != mode:
                continue
            for item in row.get("evidence_items") or []:
                src = item.get("source")
                if src and src not in have:
                    have.add(src)
                    seen.append(src)
        return seen

    def to_json(self) -> dict:
        return {
            "candidates": self.store.to_json_list(),
            "unresolved": [e.to_json() for e in self.store.unresolved],
        }


def merge_files(paths: list[Path]) -> dict:
    merger = EvidenceMerger()
    for path in paths:
        merger.merge_frontier(json.loads(path.read_text()))
    return merger.to_json()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("inputs", nargs="+", type=Path, help="frontier JSON path(s)")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    result = merge_files(a.inputs)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
