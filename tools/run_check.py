#!/usr/bin/env python3
"""Wire a peel-emitted range, run make check, record RANGE if green.

Phase 7C adapter. Reuses tools/wire.py and record_range_after_check.
Does not invent end, mutate Evidence, or promote ENCODING.

    peel-emitted != RANGE_VERIFIED
    wire success != RANGE_VERIFIED
    make check exit 0 is the RANGE prerequisite

Usage:
  python3 tools/run_check.py INPUT --ends ENDS.json [--output PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence
import run_peel

_FORBIDDEN = (
    "status", "range_verified", "encoding_verified",
    "winner", "confidence", "score", "verified",
)
_DEFAULT_WIRE = Path(__file__).resolve().parent / "wire.py"
_RANGE_RE = re.compile(
    r"@ Range:\s+\[(0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)"
    r"\s+\(\d+ bytes,\s*(arm|thumb) mode\)"
)


def _strip_forbidden(obj: dict) -> dict:
    out = dict(obj)
    for k in _FORBIDDEN:
        out.pop(k, None)
    return out


def _fmt_start(addr: int) -> str:
    return f"{addr:#010x}"


def artifact_path(tree: Path, start: int) -> Path:
    return tree / "asm" / f"disasm_{_fmt_start(start)}.s"


def peeled_obj(start: int) -> str:
    return f"build/asm/disasm_{_fmt_start(start)}.o"


def _exe_prefix(path: Path) -> list[str]:
    path = path.resolve()
    if path.suffix == ".py":
        return [sys.executable, str(path)]
    return [str(path)]


def _eligible(row: dict) -> str | None:
    if row.get("result") != "peel-emitted":
        return "invalid-selection"
    if row.get("selection") not in (None, "selected"):
        return "invalid-selection"
    if row.get("disposition") not in (None, "peel-ready"):
        return "invalid-selection"
    mode = str(row.get("mode") or "").strip().lower()
    if mode not in run_peel._MODES:
        return "invalid-selection"
    try:
        start = run_peel._parse_addr(row.get("address"))
    except (ValueError, TypeError):
        return "invalid-range"
    if not run_peel._in_rom_start(start):
        return "invalid-range"
    return None


def parse_artifact_meta(text: str) -> tuple[int, int, str] | None:
    m = _RANGE_RE.search(text)
    if not m:
        return None
    start = int(m.group(1), 16)
    end = int(m.group(2), 16)
    mode = m.group(3).lower()
    return start, end, mode


def linker_has_object(linker_text: str, start: int) -> bool:
    return peeled_obj(start) in linker_text


def _rom_sha(rom: Path) -> str:
    return hashlib.sha256(rom.read_bytes()).hexdigest()


def _find_rom(tree: Path, explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        p = p if p.is_absolute() else tree / p
        return p if p.is_file() else None
    cand = tree / "baserom.gba"
    return cand if cand.is_file() else None


class CheckRunner:
    """wire.py + make check + record_range_after_check. No end inference."""

    def __init__(
        self,
        tree: Path,
        *,
        wire: Path | None = None,
        rom: str | None = None,
        make_check=None,
        record=None,
        rom_sha: str | None = None,
        sidecar: Path | None = None,
    ) -> None:
        self.tree = Path(tree)
        self.wire = Path(wire) if wire is not None else _DEFAULT_WIRE
        self.rom = rom
        self._make_check = make_check
        self._record = record
        self._rom_sha = rom_sha
        self._sidecar = sidecar
        self.commands: list[list[str]] = []

    def run(self, peel_obj: dict, ends_obj: dict | None) -> dict:
        ends = run_peel.EndMap(ends_obj)
        results: list[dict] = []
        skipped: list[dict] = []
        for row in peel_obj.get("results") or []:
            item = self._run_one(row, ends)
            if item["result"] in ("range-recorded", "wire-failed", "check-failed"):
                results.append(item)
            else:
                skipped.append(item)
        unresolved = list(peel_obj.get("unresolved") or [])
        return {
            "results": results,
            "skipped": skipped,
            "unresolved": unresolved,
        }

    def _run_one(self, row: dict, ends: run_peel.EndMap) -> dict:
        addr_s = row.get("address")
        mode_s = str(row.get("mode") or "").strip().lower()
        base = _strip_forbidden({
            "address": addr_s,
            "mode": row.get("mode"),
            "result": "not-recorded",
        })
        why = _eligible(row)
        if why:
            base["reason"] = why
            return base
        start = run_peel._parse_addr(addr_s)
        status, spec = ends.lookup(start, mode_s)
        if status != "ok":
            base["reason"] = status
            return base
        reason, end, end_s = run_peel._validate_end(start, run_peel._end_value(spec))
        if reason:
            base["reason"] = reason
            return base
        assert end is not None and end_s is not None
        base["end"] = end_s
        art = artifact_path(self.tree, start)
        if not art.is_file():
            base["reason"] = "missing-artifact"
            return base
        meta = parse_artifact_meta(art.read_text())
        if meta is None:
            base["reason"] = "metadata-mismatch"
            return base
        m_start, m_end, m_mode = meta
        if m_start != start or m_end != end or m_mode != mode_s:
            base["reason"] = "metadata-mismatch"
            return base
        argv = _exe_prefix(self.wire) + [
            "--tree", str(self.tree),
            "--start", run_peel._fmt_addr(addr_s),
            "--end", end_s,
        ]
        if self.rom:
            argv.extend(["--rom", self.rom])
        self.commands.append(list(argv))
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, check=False)
            wire_exit = proc.returncode
        except OSError:
            wire_exit = -1
        if wire_exit != 0:
            return _strip_forbidden({
                "address": addr_s,
                "mode": row.get("mode"),
                "end": end_s,
                "result": "wire-failed",
                "wire_exit": wire_exit,
            })
        linker = self.tree / "linker.ld"
        text = linker.read_text() if linker.is_file() else ""
        if not linker_has_object(text, start):
            base["reason"] = "not-wired"
            base["wire_exit"] = 0
            return base
        check_exit = self._run_make_check()
        if check_exit != 0:
            return _strip_forbidden({
                "address": addr_s,
                "mode": row.get("mode"),
                "end": end_s,
                "result": "check-failed",
                "wire_exit": 0,
                "check_exit": check_exit,
            })
        rec = self._record_range(start, mode_s, end)
        if rec is None:
            base["reason"] = "not-recorded"
            base["wire_exit"] = 0
            base["check_exit"] = 0
            return base
        return _strip_forbidden({
            "address": addr_s,
            "mode": row.get("mode"),
            "end": end_s,
            "result": "range-recorded",
            "wire_exit": 0,
            "check_exit": 0,
        })

    def _run_make_check(self) -> int:
        if self._make_check is not None:
            return int(self._make_check())
        proc = subprocess.run(
            ["make", "-C", str(self.tree), "check"],
            capture_output=True, text=True, check=False,
        )
        return proc.returncode

    def _record_range(self, start: int, mode: str, end: int):
        if self._record is not None:
            return self._record(True, start, mode, end)
        rom = _find_rom(self.tree, self.rom)
        if rom is None:
            return None
        sha = self._rom_sha or _rom_sha(rom)
        side = self._sidecar or evidence.sidecar_path_for_rom(rom)
        return evidence.record_range_after_check(
            True, side, sha, start, mode, end, None, source="make-check",
        )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7B peel-execution JSON")
    p.add_argument("--ends", type=Path, required=True,
                   help="explicit ends keyed by address:mode")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    p.add_argument("--tree", type=Path, default=Path("."),
                   help="mapping tree (default: cwd)")
    p.add_argument("--wire", type=Path, default=_DEFAULT_WIRE,
                   help="wire.py path (default: tools/wire.py)")
    p.add_argument("--rom", help="ROM path relative to tree (optional)")
    a = p.parse_args(argv)
    peel_obj = json.loads(a.input.read_text())
    ends = json.loads(a.ends.read_text())
    runner = CheckRunner(a.tree, wire=a.wire, rom=a.rom)
    result = runner.run(peel_obj, ends)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
