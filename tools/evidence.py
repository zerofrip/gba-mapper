#!/usr/bin/env python3
"""Mapping evidence sidecar: verification status and provenance.

labels.toml (gba-labels v2) stays the recompiler interchange — addresses
and names only. This sidecar is the authority for verification state.
It never contains image bytes.

Status:
  unresolved         candidate; not verified
  range_verified     .incbin reproduces the ROM range; mode/decode unproven
  encoding_verified  RANGE + mode + full decode + reassembly identity
  rejected           explicit reject

Only encoding_verified may enter the canonical verified set / gamedb.
FUNCTION_VERIFIED is not a status. Promote encoding_verified only via promote_encoding_verified(); peel.py
never writes RANGE_VERIFIED. Callers record it only after `make check`
SHA-256 matches the original ROM.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Iterable, Iterator

FORMAT = "gba-mapping-evidence"
VERSION = 1

UNRESOLVED = "unresolved"
RANGE_VERIFIED = "range_verified"
ENCODING_VERIFIED = "encoding_verified"
REJECTED = "rejected"

STATUSES = (UNRESOLVED, RANGE_VERIFIED, ENCODING_VERIFIED, REJECTED)

# Rank for monotonic upgrades. rejected is not on this ladder.
_RANK = {
    UNRESOLVED: 0,
    RANGE_VERIFIED: 1,
    ENCODING_VERIFIED: 2,
}

EVIDENCE_TYPES = (
    "bl-target",
    "blx-target",
    "bx-target",
    "gap",
    "prologue",
    "epilogue",
    "cfg-consistency",
    "interior-bl",
    "ghidra-seed",
    "gba-recomp-seed",
    "decomp-reference",
    "runtime-entry",
    "manual-seed",
    "hook",
    "repoint",
    "routine-pointer",
    "encoding-roundtrip",
    "skip-audit",
    "peel-incbin",
)


class PromotionError(ValueError):
    """ENCODING_VERIFIED promotion was refused."""


@dataclass(frozen=True)
class Evidence:
    type: str
    source: str
    detail: str
    from_addr: int | None = None

    def key(self) -> tuple:
        return (self.type, self.source, self.detail, self.from_addr)

    def to_json(self) -> dict:
        d: dict = {"type": self.type, "source": self.source, "detail": self.detail}
        if self.from_addr is not None:
            d["from_addr"] = _hex(self.from_addr)
        return d

    @classmethod
    def from_json(cls, raw: dict) -> Evidence:
        return cls(
            type=str(raw.get("type") or ""),
            source=str(raw.get("source") or ""),
            detail=str(raw.get("detail") or ""),
            from_addr=_parse_addr(raw["from_addr"]) if "from_addr" in raw and raw["from_addr"] is not None else None,
        )


@dataclass
class Record:
    address: int
    mode: str
    status: str
    end: int | None = None
    name: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple[int, str]:
        return (self.address, self.mode)

    def to_json(self) -> dict:
        d = {
            "address": _hex(self.address),
            "mode": self.mode,
            "status": self.status,
            "evidence": [e.to_json() for e in self.evidence],
            "conflicts": list(self.conflicts),
        }
        if self.end is not None:
            d["end"] = _hex(self.end)
        if self.name:
            d["name"] = self.name
        for k, v in self.extra.items():
            if k not in d:
                d[k] = v
        return d

    @classmethod
    def from_json(cls, raw: dict) -> Record:
        known = {"address", "mode", "status", "end", "name", "evidence", "conflicts"}
        extra = {k: v for k, v in raw.items() if k not in known}
        mode = {"a": "arm", "t": "thumb"}.get(raw.get("mode"), raw.get("mode"))
        status = raw.get("status") or UNRESOLVED
        ev = [Evidence.from_json(e) for e in raw.get("evidence") or [] if isinstance(e, dict)]
        conflicts = [str(c) for c in (raw.get("conflicts") or [])]
        end = raw.get("end")
        return cls(
            address=_parse_addr(raw["address"]),
            mode=mode if mode in ("arm", "thumb") else str(mode or ""),
            status=status if status in STATUSES else UNRESOLVED,
            end=_parse_addr(end) if end is not None else None,
            name=raw.get("name"),
            evidence=ev,
            conflicts=conflicts,
            extra=extra,
        )


def sidecar_path(labels_path: Path) -> Path:
    """`<stem>.labels.toml` → `<stem>.evidence.jsonl`."""
    name = labels_path.name
    suffix = ".labels.toml"
    if name.endswith(suffix):
        return labels_path.with_name(name[: -len(suffix)] + ".evidence.jsonl")
    return labels_path.with_suffix(".evidence.jsonl")


def sidecar_path_for_rom(rom_path: Path) -> Path:
    import labels_toml
    return sidecar_path(labels_toml.state_path(rom_path))


def load(path: Path, expected_sha: str | None = None) -> tuple[str, dict[tuple[int, str], Record]]:
    """Return (sha256, records keyed by (address, mode))."""
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    if not lines:
        raise ValueError(f"{path}: empty evidence sidecar")
    header = json.loads(lines[0])
    if header.get("format") != FORMAT or header.get("version") != VERSION:
        raise ValueError(f"{path}: not a {FORMAT} v{VERSION} file")
    sha = header.get("sha256")
    if not isinstance(sha, str) or len(sha) != 64:
        raise ValueError(f"{path}: missing/malformed sha256")
    sha = sha.lower()
    if expected_sha is not None and sha != expected_sha.lower():
        raise ValueError(f"{path} is for image {sha[:8]}…, not {expected_sha[:8]}…")
    records: dict[tuple[int, str], Record] = {}
    for ln in lines[1:]:
        rec = Record.from_json(json.loads(ln))
        if rec.mode not in ("arm", "thumb"):
            continue
        records[rec.key()] = rec
    return sha, records


def save(path: Path, sha: str, records: dict[tuple[int, str], Record]) -> None:
    lines = [json.dumps({"format": FORMAT, "version": VERSION, "sha256": sha.lower()}, separators=(",", ":"))]
    for rec in sorted(records.values(), key=lambda r: (r.address, r.mode)):
        lines.append(json.dumps(rec.to_json(), separators=(",", ":")))
    path.write_text("\n".join(lines) + "\n")


def merge_evidence(dst: Record, src: Record) -> Record:
    """Append unique evidence; fill missing end/name; keep extra keys."""
    seen = {e.key() for e in dst.evidence}
    ev = list(dst.evidence)
    for e in src.evidence:
        if e.key() not in seen:
            ev.append(e)
            seen.add(e.key())
    extra = dict(dst.extra)
    for k, v in src.extra.items():
        extra.setdefault(k, v)
    conflicts = list(dict.fromkeys([*dst.conflicts, *src.conflicts]))
    return replace(
        dst,
        end=dst.end if dst.end is not None else src.end,
        name=dst.name or src.name,
        evidence=ev,
        conflicts=conflicts,
        extra=extra,
    )


def merge_status(current: str, incoming: str) -> str:
    """Monotonic ladder. rejected only wins if current is unresolved."""
    if incoming == REJECTED:
        return REJECTED if current == UNRESOLVED else current
    if current == REJECTED:
        return REJECTED
    cr, ir = _RANK.get(current, 0), _RANK.get(incoming, 0)
    return incoming if ir > cr else current


def upsert(path: Path, rom_sha: str, rec: Record) -> Record:
    """Create or merge one record. Status never drops, never skips the gate."""
    if path.exists():
        sha, recs = load(path, expected_sha=rom_sha)
    else:
        recs = {}
        sha = rom_sha.lower()
    key = rec.key()
    if key in recs:
        old = recs[key]
        merged = merge_evidence(old, rec)
        merged.status = merge_status(old.status, rec.status)
        # encoding_verified may only arrive through promote_encoding_verified.
        if rec.status == ENCODING_VERIFIED and old.status != ENCODING_VERIFIED:
            merged.status = old.status
        recs[key] = merged
    else:
        if rec.status == ENCODING_VERIFIED:
            rec = replace(rec, status=UNRESOLVED)
        recs[key] = rec
    save(path, sha, recs)
    return recs[key]


def record_range_verified(
    path: Path,
    rom_sha: str,
    address: int,
    mode: str,
    end: int,
    name: str | None,
    evidence: Evidence,
) -> Record:
    """Write RANGE_VERIFIED. Callers must only use this after make check."""
    rec = Record(
        address=address,
        mode=mode,
        status=RANGE_VERIFIED,
        end=end,
        name=name,
        evidence=[evidence],
    )
    return upsert(path, rom_sha, rec)


def record_range_after_check(
    check_passed: bool,
    path: Path,
    rom_sha: str,
    address: int,
    mode: str,
    end: int,
    name: str | None,
    *,
    source: str = "make-check",
) -> Record | None:
    """RANGE_VERIFIED only if make check already passed. No write on failure."""
    if not check_passed:
        return None
    return record_range_verified(
        path,
        rom_sha,
        address,
        mode,
        end,
        name,
        Evidence(
            type="peel-incbin",
            source=source,
            detail=(
                f"make check SHA-256 match; incbin range "
                f"[{address:#x}, {end:#x}); mode unproven"
            ),
        ),
    )


def clear_range_verified(
    path: Path, rom_sha: str, address: int, mode: str,
) -> bool:
    """Drop a RANGE_VERIFIED record for (address, mode). Other records stay.

    encoding_verified and unresolved (e.g. decomp-reference) are not touched.
    Returns True if a range_verified record was removed.
    """
    if not path.exists():
        return False
    sha, recs = load(path, expected_sha=rom_sha)
    key = (address, mode)
    rec = recs.get(key)
    if rec is None or rec.status != RANGE_VERIFIED:
        return False
    del recs[key]
    if recs:
        save(path, sha, recs)
    else:
        path.unlink()
    return True


def run_make_check(tree: Path) -> bool:
    proc = subprocess.run(
        ["make", "-C", str(tree), "check"],
        capture_output=True, text=True,
    )
    if proc.stdout:
        sys.stdout.write(proc.stdout)
    if proc.returncode != 0 and proc.stderr:
        sys.stderr.write(proc.stderr)
    return proc.returncode == 0


def promote_encoding_verified(record: Record) -> Record:
    """Isolated gate. Not called from the Phase 1 mapping pipeline.

    Requires RANGE_VERIFIED, established mode, exclusive end, no
    conflicts, and an encoding-roundtrip evidence item.
    """
    missing: list[str] = []
    if record.status != RANGE_VERIFIED:
        missing.append(f"status is {record.status!r}, need {RANGE_VERIFIED!r}")
    if record.mode not in ("arm", "thumb"):
        missing.append(f"mode is {record.mode!r}")
    if record.end is None:
        missing.append("end is missing")
    if record.conflicts:
        missing.append(f"conflicts: {record.conflicts}")
    if not any(e.type == "encoding-roundtrip" for e in record.evidence):
        missing.append("missing encoding-roundtrip evidence")
    if missing:
        raise PromotionError("; ".join(missing))
    return replace(record, status=ENCODING_VERIFIED)


def iter_encoding_verified(records: Iterable[Record]) -> Iterator[Record]:
    for rec in records:
        if rec.status == ENCODING_VERIFIED:
            yield rec


def _hex(addr: int) -> str:
    return f"0x{addr:08x}"


def _parse_addr(value) -> int:
    if isinstance(value, int):
        return value
    s = str(value).strip().lower().replace("_", "")
    if s.startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def _cli_record_range(argv: list[str] | None = None) -> int:
    """make check, then RANGE_VERIFIED. Red check writes nothing."""
    import labels_toml
    from peel import find_rom

    p = argparse.ArgumentParser(prog="evidence.py record-range")
    p.add_argument("--tree", type=Path, default=Path("."))
    p.add_argument("--rom")
    p.add_argument("--start", required=True, type=lambda s: int(s, 0))
    p.add_argument("--end", required=True, type=lambda s: int(s, 0))
    p.add_argument("--mode", required=True, choices=["arm", "thumb"])
    p.add_argument("--name")
    a = p.parse_args(argv)

    tree = a.tree.resolve()
    rom = find_rom(tree, a.rom)
    if not run_make_check(tree):
        print("record-range: make check RED — not recording RANGE_VERIFIED",
              file=sys.stderr)
        return 1
    sha = labels_toml.rom_sha256(rom)
    side = sidecar_path(labels_toml.state_path(rom))
    rec = record_range_after_check(
        True, side, sha, a.start, a.mode, a.end, a.name, source="make-check",
    )
    print(f"record-range: RANGE_VERIFIED {a.start:#010x} {a.mode} → {side.name}")
    return 0 if rec is not None else 1


def _cli_clear_range(argv: list[str] | None = None) -> int:
    import labels_toml
    from peel import find_rom

    p = argparse.ArgumentParser(prog="evidence.py clear-range")
    p.add_argument("--tree", type=Path, default=Path("."))
    p.add_argument("--rom")
    p.add_argument("--start", required=True, type=lambda s: int(s, 0))
    p.add_argument("--mode", required=True, choices=["arm", "thumb"])
    a = p.parse_args(argv)
    tree = a.tree.resolve()
    rom = find_rom(tree, a.rom)
    sha = labels_toml.rom_sha256(rom)
    side = sidecar_path(labels_toml.state_path(rom))
    clear_range_verified(side, sha, a.start, a.mode)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: evidence.py record-range|clear-range ...", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "record-range":
        return _cli_record_range(rest)
    if cmd == "clear-range":
        return _cli_clear_range(rest)
    print(f"unknown command {cmd!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
