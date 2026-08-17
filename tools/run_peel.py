#!/usr/bin/env python3
"""Invoke existing peel.py with an explicit [start, end). Not verification.

Phase 7B adapter: selected peel-ready candidates plus an explicit end
keyed by (address, mode). Does not invent end, mutate Evidence, or
record RANGE/ENCODING.

    peel-emitted != RANGE_VERIFIED
    peel-failed != unresolved

Usage:
  python3 tools/run_peel.py INPUT --ends ENDS.json [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROM_BASE = 0x08000000
ROM_WINDOW_END = 0x0A000000
_MODES = frozenset({"arm", "thumb"})
_FORBIDDEN = (
    "status", "range_verified", "encoding_verified",
    "winner", "confidence", "score",
)
_DEFAULT_PEEL = Path(__file__).resolve().parent / "peel.py"


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


def _peel_prefix(peel: Path) -> list[str]:
    peel = peel.resolve()
    if peel.suffix == ".py":
        return [sys.executable, str(peel)]
    return [str(peel)]


def _end_key(addr: int, mode: str) -> tuple[int, str]:
    return (addr, mode)


class EndMap:
    """Explicit ends keyed by CandidateKey = (address, mode)."""

    def __init__(self, raw: dict | None) -> None:
        self._by_key: dict[tuple[int, str], object] = {}
        self._ambiguous: set[tuple[int, str]] = set()
        self._address_only: set[int] = set()
        if not raw:
            return
        for key, spec in raw.items():
            self._ingest(str(key), spec)

    def _ingest(self, key: str, spec: object) -> None:
        if ":" not in key:
            try:
                self._address_only.add(_parse_addr(key))
            except ValueError:
                pass
            return
        addr_s, mode = key.rsplit(":", 1)
        mode = mode.strip().lower()
        if mode not in _MODES:
            return
        try:
            addr = _parse_addr(addr_s)
        except ValueError:
            return
        ck = _end_key(addr, mode)
        if ck in self._by_key and self._by_key[ck] != spec:
            self._ambiguous.add(ck)
        self._by_key[ck] = spec

    def lookup(self, addr: int, mode: str) -> tuple[str, object | None]:
        ck = _end_key(addr, mode)
        if ck in self._ambiguous:
            return "ambiguous-end-mapping", None
        if ck not in self._by_key:
            if addr in self._address_only:
                return "address-only-end-mapping", None
            return "missing-explicit-end", None
        return "ok", self._by_key[ck]


def _end_value(spec: object) -> object:
    if isinstance(spec, dict):
        if "end" not in spec:
            return None
        return spec["end"]
    return spec


def _validate_end(start: int, raw_end: object) -> tuple[str | None, int | None, str | None]:
    if raw_end is None:
        return "malformed-end", None, None
    try:
        end = _parse_addr(raw_end)
    except (ValueError, TypeError):
        return "malformed-end", None, None
    if end <= start or not _in_rom_end(end):
        return "malformed-end", None, None
    return None, end, _fmt_addr(raw_end)


def _executable(row: dict) -> str | None:
    if row.get("selection") != "selected":
        return "invalid-selection"
    if row.get("disposition") != "peel-ready":
        return "invalid-selection"
    mode = str(row.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return "invalid-selection"
    try:
        start = _parse_addr(row.get("address"))
    except (ValueError, TypeError):
        return "invalid-range"
    if not _in_rom_start(start):
        return "invalid-range"
    return None


def _strip_forbidden(obj: dict) -> dict:
    out = dict(obj)
    for k in _FORBIDDEN:
        out.pop(k, None)
    return out


class PeelRunner:
    """Subprocess adapter around peel.py. Does not infer end."""

    def __init__(
        self,
        peel: Path | None = None,
        *,
        force_boundary: bool = False,
        write_labels: bool = False,
    ) -> None:
        self.peel = Path(peel) if peel is not None else _DEFAULT_PEEL
        self.force_boundary = force_boundary
        self.write_labels = write_labels
        self.commands: list[list[str]] = []

    def run(self, selection_obj: dict, ends_obj: dict | None) -> dict:
        ends = EndMap(ends_obj)
        results: list[dict] = []
        skipped: list[dict] = []
        for row in selection_obj.get("selected") or []:
            item = self._run_one(row, ends)
            if item["result"] == "not-executed":
                skipped.append(item)
            else:
                results.append(item)
        unresolved = list(selection_obj.get("unresolved") or [])
        return {
            "results": results,
            "skipped": skipped,
            "unresolved": unresolved,
        }

    def _run_one(self, row: dict, ends: EndMap) -> dict:
        addr_s = row.get("address")
        mode_s = str(row.get("mode") or "").strip().lower()
        base = _strip_forbidden({
            "address": addr_s,
            "mode": row.get("mode"),
            "result": "not-executed",
        })
        why = _executable(row)
        if why:
            base["reason"] = why
            return base
        start = _parse_addr(addr_s)
        mode = mode_s
        status, spec = ends.lookup(start, mode)
        if status != "ok":
            base["reason"] = status
            return base
        reason, end, end_s = _validate_end(start, _end_value(spec))
        if reason:
            base["reason"] = reason
            return base
        assert end is not None and end_s is not None
        argv = self._argv(addr_s, end_s, mode)
        self.commands.append(list(argv))
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        except OSError as exc:
            return _strip_forbidden({
                "address": addr_s,
                "mode": row.get("mode"),
                "end": end_s,
                "result": "peel-failed",
                "exit_code": -1,
                "stderr": str(exc),
            })
        out = _strip_forbidden({
            "address": addr_s,
            "mode": row.get("mode"),
            "end": end_s,
            "exit_code": proc.returncode,
        })
        if proc.returncode == 0:
            out["result"] = "peel-emitted"
        else:
            out["result"] = "peel-failed"
            out["stdout"] = proc.stdout
            out["stderr"] = proc.stderr
        return out

    def _argv(self, start_s: object, end_s: str, mode: str) -> list[str]:
        argv = _peel_prefix(self.peel) + [
            "--start", _fmt_addr(start_s),
            "--end", end_s,
            "--mode", mode,
        ]
        if not self.write_labels:
            argv.append("--no-labels")
        if self.force_boundary:
            argv.append("--force-boundary")
        return argv


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--ends", type=Path, required=True,
                   help="explicit ends keyed by address:mode")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    p.add_argument("--peel", type=Path, default=_DEFAULT_PEEL,
                   help="peel.py path (default: tools/peel.py)")
    p.add_argument("--force-boundary", action="store_true",
                   help="pass through to peel.py; not RANGE verification")
    p.add_argument("--write-labels", action="store_true",
                   help="opt-in: allow peel.py to write labels.toml")
    a = p.parse_args(argv)
    selection = json.loads(a.input.read_text())
    ends = json.loads(a.ends.read_text())
    runner = PeelRunner(
        a.peel,
        force_boundary=a.force_boundary,
        write_labels=a.write_labels,
    )
    result = runner.run(selection, ends)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
