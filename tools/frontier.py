#!/usr/bin/env python3
"""Compute the peel frontier deterministically.

This is the static-heuristics rung of the evidence ladder, as a script
— the workflow's survey agent runs it once instead of harvesting call
targets and probing gaps by hand (which costs two orders of magnitude
more in model tokens than it does here in CPU).

Method:
  1. Load the map (<rom stem>.labels.toml): coverage = union of
     [address, end) (entries without `end` cover conservatively to the
     next entry's address).
  2. Byte-decode each mapped range in its recorded ARM/Thumb mode
     (tools/modeflow.py). Harvest statically known BL/BX/vector-entry
     targets that land in unmapped space. Candidate identity is
     (address, mode). Every candidate goes through FrontierStore.add_candidate
     with structured evidence. Gap evidence is never labeled as a BL target.
  3. Gaps between consecutive mapped ranges inside the code span:
     candidate at the gap start (word-aligned), evidence "gap",
     screened by the boundary detector's pool/padding heuristics —
     gaps that are all literal-pool words or padding are dropped.
  4. Rank: call-like targets first (by call count), then gaps by size
     ascending (small gaps between functions are most likely code).

Invariant: NO PROVENANCE = NO FRONTIER CANDIDATE.

Output: JSON {codeSpan, mapped, coverageBytes, candidates: [{address,
mode, evidence, evidence_items, ...}], unresolved: [...]}, capped at
--max (default 24).

Usage:
  python3 tools/frontier.py --rom baserom.gba [--labels map.toml] [--max 24]
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import boundary
import evidence
import labels_toml
import modeflow
from labels_toml import ROM_BASE

_ENTRY_TYPES = frozenset({"bl-target", "bx-target", "vector-entry"})
_UNRESOLVED_TYPES = frozenset({"indirect-branch", "jump-table"})


def leading_function(rom: Path, start: int, gap_hi: int, mode: str, objdump: str):
    """If a real function begins at `start`, return its exclusive end;
    else None. Used to rescue a function sitting at the head of a large
    data gap (jump-table targets the static call graph never reaches).
    Only thumb is probed (the boundary detector is thumb-only); a clean
    entry has no prologue warning and an end strictly inside the gap."""
    if mode != "thumb":
        return None
    try:
        rep = boundary.detect_boundary(rom, start, None, objdump)
    except Exception:
        return None
    end = rep["recommendedEnd"]
    prologue_warn = any("doesn't look like a function entry" in w for w in rep["warnings"])
    if prologue_warn or not (start < end <= gap_hi):
        return None
    return end


def pool_or_padding(rom_bytes: bytes, start: int, end: int) -> bool:
    """True if [start, end) is plausibly all literal pool / padding."""
    off, size = start - ROM_BASE, end - start
    chunk = rom_bytes[off : off + size]
    if all(b == 0x00 for b in chunk) or all(b == 0xFF for b in chunk):
        return True
    if size % 4 == 0 and start % 4 == 0:
        words = [int.from_bytes(chunk[i : i + 4], "little") for i in range(0, size, 4)]
        if all(
            (w >> 24) in (0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08) or w == 0
            for w in words
        ):
            return True
    return False


def _as_evidence_list(value) -> list[evidence.Evidence]:
    if value is None:
        return []
    if isinstance(value, evidence.Evidence):
        return [value]
    return [e for e in value if e is not None]


def evidence_from_modeflow_dict(raw: dict) -> evidence.Evidence:
    return evidence.Evidence(
        type=str(raw.get("type") or ""),
        source=str(raw.get("source") or "modeflow"),
        detail=str(raw.get("detail") or raw.get("insn") or ""),
        from_addr=raw.get("from_addr"),
        target_addr=raw.get("target_addr"),
        source_mode=raw.get("source_mode"),
        target_mode=raw.get("target_mode"),
        insn=raw.get("insn"),
    )


def evidence_from_edge(edge: modeflow.FlowEdge) -> evidence.Evidence:
    return evidence.Evidence(
        type=edge.evidence_type,
        source="modeflow",
        detail=edge.insn,
        from_addr=edge.src,
        target_addr=edge.target,
        source_mode=edge.src_mode,
        target_mode=edge.target_mode,
        insn=edge.insn,
    )


def _is_deterministic(items: list[evidence.Evidence]) -> bool:
    return any(
        e.type in _ENTRY_TYPES
        and e.target_addr is not None
        and e.target_mode is not None
        for e in items
    )


@dataclass
class FrontierCandidate:
    address: int
    mode: str
    evidence: list[evidence.Evidence] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def key(self) -> tuple[int, str]:
        return (self.address, self.mode)


class FrontierStore:
    """Provenance-mandatory frontier. CandidateKey = (address, mode)."""

    def __init__(self) -> None:
        self._cands: dict[tuple[int, str], FrontierCandidate] = {}
        self.unresolved: list[evidence.Evidence] = []

    def add_candidate(self, address: int, mode: str, evidence_in) -> None:
        items = _as_evidence_list(evidence_in)
        if not items:
            return
        if mode not in ("arm", "thumb"):
            raise ValueError(f"invalid mode {mode!r}")
        key = (address, mode)
        if key not in self._cands:
            self._cands[key] = FrontierCandidate(address, mode)
        dst = self._cands[key]
        seen = {e.key() for e in dst.evidence}
        for ev in items:
            k = ev.key()
            if k not in seen:
                dst.evidence.append(ev)
                seen.add(k)
        self._refresh_conflicts()

    def add_unresolved(self, edge_or_evidence) -> None:
        if isinstance(edge_or_evidence, evidence.Evidence):
            ev = edge_or_evidence
        elif isinstance(edge_or_evidence, modeflow.FlowEdge):
            ev = evidence_from_edge(edge_or_evidence)
        else:
            raise TypeError(f"unsupported unresolved item {type(edge_or_evidence)!r}")
        k = ev.key()
        if any(u.key() == k for u in self.unresolved):
            return
        self.unresolved.append(ev)

    def has(self, address: int, mode: str) -> bool:
        return (address, mode) in self._cands

    def _refresh_conflicts(self) -> None:
        by_addr: dict[int, list[FrontierCandidate]] = {}
        for c in self._cands.values():
            by_addr.setdefault(c.address, []).append(c)
        for addr, group in by_addr.items():
            modes = {c.mode for c in group}
            if modes == {"arm", "thumb"}:
                msg = f"mode conflict at {addr:#010x}: arm and thumb evidence"
                for c in group:
                    if msg not in c.conflicts:
                        c.conflicts.append(msg)

    def to_json_list(self) -> list[dict]:
        call_like: list[FrontierCandidate] = []
        rest: list[FrontierCandidate] = []
        for c in self._cands.values():
            n = sum(1 for e in c.evidence if e.type in _ENTRY_TYPES)
            if n:
                call_like.append(c)
            else:
                rest.append(c)
        call_like.sort(
            key=lambda c: -sum(1 for e in c.evidence if e.type in _ENTRY_TYPES)
        )
        rest.sort(key=lambda c: c.address)
        ordered = call_like + rest
        out = []
        for c in ordered:
            types: list[str] = []
            seen: set[str] = set()
            for e in c.evidence:
                if e.type not in seen:
                    types.append(e.type)
                    seen.add(e.type)
            first = c.evidence[0]
            from_addr = first.from_addr
            out.append({
                "address": f"0x{c.address:08x}",
                "mode": c.mode,
                "evidence": ", ".join(types),
                "evidence_items": [e.to_json() for e in c.evidence],
                "conflicts": list(c.conflicts),
                "deterministic": _is_deterministic(c.evidence),
                "evidence_type": types[0] if types else None,
                "source_mode": first.source_mode,
                "target_mode": c.mode,
                "source": f"0x{from_addr:08x}" if from_addr is not None else None,
                "from_addr": f"0x{from_addr:08x}" if from_addr is not None else None,
            })
        return out


def _gap_evidence(
    *,
    start: int,
    mode: str,
    gap_lo: int,
    gap_hi: int,
    prev_start: int,
    prev_end: int,
    prev_mode: str,
    extra: str = "",
) -> evidence.Evidence:
    detail = (
        f"gap [{gap_lo:#x}, {gap_hi:#x}) after mapped "
        f"[{prev_start:#x}, {prev_end:#x})"
    )
    if extra:
        detail = f"{detail}; {extra}"
    return evidence.Evidence(
        type="gap",
        source="gap",
        detail=detail,
        from_addr=prev_end,
        target_addr=start,
        source_mode=prev_mode,
        target_mode=mode,
    )


def ingest_modeflow(
    store: FrontierStore,
    edges: list[modeflow.FlowEdge],
    rom_size: int,
    *,
    in_map,
    rom_end: int,
) -> None:
    minted = modeflow.candidates_from_edges(edges, rom_size)
    for (addr, tmode), cand in minted.items():
        if not (ROM_BASE <= addr < rom_end) or in_map(addr):
            continue
        items = [evidence_from_modeflow_dict(d) for d in cand.evidence]
        store.add_candidate(addr, tmode, items)
    for edge in edges:
        if edge.evidence_type in _UNRESOLVED_TYPES or (
            edge.target is None and edge.evidence_type == "indirect-branch"
        ):
            store.add_unresolved(edge)


def ingest_vector(store: FrontierStore, rom_bytes: bytes, *, in_map) -> None:
    ve = modeflow.header_vector_edge(rom_bytes, ROM_BASE)
    if ve is None or ve.target is None or ve.target_mode is None:
        return
    if in_map(ve.target):
        return
    minted = modeflow.candidates_from_edges([ve], len(rom_bytes))
    for (addr, tmode), cand in minted.items():
        if in_map(addr):
            continue
        store.add_candidate(
            addr, tmode, [evidence_from_modeflow_dict(d) for d in cand.evidence],
        )


def ingest_sidecar(
    store: FrontierStore,
    sidecar_records: dict[tuple[int, str], evidence.Record] | None,
    *,
    in_map,
    skips: set[int],
) -> None:
    if not sidecar_records:
        return
    for rec in sidecar_records.values():
        if rec.status != evidence.UNRESOLVED:
            continue
        if in_map(rec.address) or rec.address in skips:
            continue
        if not rec.evidence:
            continue
        store.add_candidate(rec.address, rec.mode, rec.evidence)


def build_frontier(
    rom_bytes: bytes,
    ranges: list[tuple[int, int, str]],
    *,
    skips: set[int] | None = None,
    sidecar_records: dict[tuple[int, str], evidence.Record] | None = None,
    max_n: int = 24,
    rom_path: Path | None = None,
    objdump: str = "arm-none-eabi-objdump",
) -> dict:
    """Build a provenance-complete frontier from synthetic or real bytes."""
    skips = skips or set()
    store = FrontierStore()
    rom_end = ROM_BASE + len(rom_bytes)
    if not ranges:
        return {
            "codeSpan": None,
            "coverageBytes": 0,
            "candidates": [],
            "unresolved": [],
        }

    span_lo, span_hi = ranges[0][0], max(e for _, e, _ in ranges)
    merged: list[list[int]] = []
    for s, e, _ in ranges:
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    coverage = sum(e - s for s, e in merged)

    def in_map(addr: int) -> bool:
        return any(lo <= addr < hi for lo, hi in merged)

    for s, e, mode in ranges:
        chunk = rom_bytes[s - ROM_BASE : e - ROM_BASE]
        if not chunk:
            continue
        edges = modeflow.decode(chunk, s, mode)
        ingest_modeflow(store, edges, len(rom_bytes), in_map=in_map, rom_end=rom_end)

    ingest_vector(store, rom_bytes, in_map=in_map)
    ingest_sidecar(store, sidecar_records, in_map=in_map, skips=skips)

    def advance_past_known_data(start: int, gap_hi: int) -> int:
        if start < ROM_BASE + 0xC0 and start >= ROM_BASE + 0x4:
            start = ROM_BASE + 0xC0
        while start < gap_hi and (
            start in skips
            or pool_or_padding(rom_bytes, start, min(start + 4, gap_hi))
        ):
            start += 4
        return start

    for (s1, e1), (s2, _) in zip(merged, merged[1:]):
        gap_lo, gap_hi = e1, s2
        size = gap_hi - gap_lo
        if size < 4:
            continue
        start = advance_past_known_data((gap_lo + 3) & ~3, gap_hi)
        prev = next(
            ((s, e, m) for s, e, m in reversed(ranges) if e <= gap_lo),
            None,
        )
        prev_start, prev_end, prev_mode = prev if prev else (gap_lo, gap_lo, "thumb")
        if start >= gap_hi or in_map(start) or start in skips:
            continue
        if store.has(start, prev_mode):
            continue
        if size <= 0x4000:
            if pool_or_padding(rom_bytes, gap_lo, gap_hi):
                continue
            store.add_candidate(
                start, prev_mode,
                _gap_evidence(
                    start=start, mode=prev_mode,
                    gap_lo=gap_lo, gap_hi=gap_hi,
                    prev_start=prev_start, prev_end=prev_end, prev_mode=prev_mode,
                ),
            )
            continue
        if rom_path is None:
            continue
        cur = start
        found = 0
        while cur < gap_hi and found < max_n:
            if store.has(cur, prev_mode) or in_map(cur) or cur in skips:
                break
            probe = leading_function(rom_path, cur, gap_hi, prev_mode, objdump)
            if probe is None:
                break
            store.add_candidate(
                cur, prev_mode,
                _gap_evidence(
                    start=cur, mode=prev_mode,
                    gap_lo=gap_lo, gap_hi=gap_hi,
                    prev_start=prev_start, prev_end=prev_end, prev_mode=prev_mode,
                    extra=f"leading-function {cur:#x}..{probe:#x}",
                ),
            )
            found += 1
            nxt = probe
            while nxt < gap_hi and pool_or_padding(rom_bytes, nxt, min(nxt + 4, gap_hi)):
                nxt += 4
            cur = nxt

    candidates = [
        c for c in store.to_json_list()
        if int(c["address"], 16) not in skips
    ]
    return {
        "codeSpan": f"0x{span_lo:08x}..0x{span_hi:08x}",
        "coverageBytes": coverage,
        "candidates": candidates[:max_n],
        "unresolved": [e.to_json() for e in store.unresolved],
    }


def _load_skips(lpath: Path) -> set[int]:
    skips: set[int] = set()
    skips_file = Path(str(lpath).replace(".labels.toml", ".skips.txt"))
    if not skips_file.exists():
        return skips
    for line in skips_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            addr = next((t for t in line.split() if t.startswith("0x")), None)
            if addr:
                try:
                    skips.add(int(addr, 16))
                except ValueError:
                    pass
    return skips


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--rom", required=True, type=Path)
    p.add_argument("--labels", type=Path)
    p.add_argument("--max", type=int, default=24)
    p.add_argument("--objdump", default="arm-none-eabi-objdump")
    a = p.parse_args()

    lpath = a.labels or labels_toml.state_path(a.rom)
    skips = _load_skips(lpath)
    if not lpath.exists():
        print(json.dumps({"codeSpan": None, "mapped": 0, "coverageBytes": 0,
                          "candidates": [], "note": f"{lpath} missing — empty map; "
                          "seed with the header entry point"}))
        return 0
    _, fns = labels_toml.load(lpath)
    if not fns:
        print(json.dumps({"codeSpan": None, "mapped": 0, "coverageBytes": 0,
                          "candidates": []}))
        return 0

    rom_bytes = a.rom.read_bytes()
    rom_end = ROM_BASE + len(rom_bytes)
    entries = sorted(fns.values(), key=lambda f: f.address)
    ranges: list[tuple[int, int, str]] = []
    for i, f in enumerate(entries):
        end = f.end
        if end is None:
            end = entries[i + 1].address if i + 1 < len(entries) else f.address + 4
        ranges.append((f.address, min(end, rom_end), f.mode))

    sidecar_records = None
    side = evidence.sidecar_path(lpath)
    if side.exists():
        try:
            _, sidecar_records = evidence.load(side, labels_toml.rom_sha256(a.rom))
        except Exception:
            sidecar_records = None

    result = build_frontier(
        rom_bytes, ranges,
        skips=skips,
        sidecar_records=sidecar_records,
        max_n=a.max,
        rom_path=a.rom,
        objdump=a.objdump,
    )
    result["mapped"] = len(fns)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
