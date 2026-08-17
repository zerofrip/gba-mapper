#!/usr/bin/env python3
"""Harvest FUNC symbols from a decomp ELF as unverified candidates.

Decompilation repositories are benchmark/reference evidence, not a
verification authority. ELF symbols become sidecar records:

    status = unresolved
    evidence.type = decomp-reference

They do NOT enter labels.toml. Each candidate still has to go through
the normal peel / RANGE_VERIFIED / ENCODING_VERIFIED pipeline.

Usage:
  python3 tools/seed_from_decomp.py --elf game.elf --rom baserom.gba
  python3 tools/seed_from_decomp.py --elf game.elf --rom baserom.gba \\
      --out game.evidence.jsonl
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence
import labels_toml
from labels_toml import Fn, ROM_BASE

# readelf -sW row:
#    920: 08006519   116 FUNC    LOCAL  DEFAULT    2 Name
_SYM_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+|0x[0-9a-f]+)\s+FUNC\s+(\w+)\s+\w+\s+\S+\s+(\S+)\s*$",
    re.I,
)


def harvest(elf: Path, readelf: str) -> list[tuple[Fn, str]]:
    text = subprocess.run(
        [readelf, "-sW", str(elf)], capture_output=True, text=True, check=True
    ).stdout
    out: list[tuple[Fn, str]] = []
    for line in text.splitlines():
        m = _SYM_RE.match(line)
        if not m:
            continue
        value = int(m.group(1), 16)
        size = int(m.group(2), 0)
        bind = m.group(3).upper()
        name = m.group(4)
        thumb = value & 1
        addr = value & ~1
        out.append((
            Fn(
                address=addr,
                mode="thumb" if thumb else "arm",
                end=addr + size if size > 0 else None,
                name=name,
            ),
            bind,
        ))
    return out


def candidates_from_harvest(
    syms: list[tuple[Fn, str]], rom_size: int,
) -> tuple[dict[tuple[int, str], evidence.Record], dict[str, int]]:
    """Turn harvested FUNC symbols into unresolved decomp-reference records."""
    recs: dict[tuple[int, str], evidence.Record] = {}
    kept = dropped = dupes = 0
    for fn, bind in syms:
        if not (ROM_BASE <= fn.address < ROM_BASE + rom_size):
            dropped += 1
            continue
        rec = evidence.Record(
            address=fn.address,
            mode=fn.mode,
            status=evidence.UNRESOLVED,
            end=fn.end,
            name=fn.name,
            evidence=[evidence.Evidence(
                type="decomp-reference",
                source="seed_from_decomp",
                detail=(
                    f"elf FUNC {fn.name or '?'} bind={bind} "
                    f"size={0 if fn.end is None else fn.end - fn.address}"
                ),
            )],
        )
        key = rec.key()
        if key in recs:
            dupes += 1
            old = recs[key]
            prefer = bind == "GLOBAL" or (old.name or "").startswith("sub_")
            recs[key] = evidence.merge_evidence(rec if prefer else old, old if prefer else rec)
            recs[key].status = evidence.UNRESOLVED
            continue
        recs[key] = rec
        kept += 1
    return recs, {"kept": kept, "dropped": dropped, "dupes": dupes}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--elf", required=True, type=Path)
    p.add_argument("--rom", required=True, type=Path)
    p.add_argument("--out", type=Path,
                   help="evidence sidecar (default: <rom stem>.evidence.jsonl)")
    p.add_argument("--readelf", default="arm-none-eabi-readelf")
    a = p.parse_args()

    if a.out is not None and a.out.name.endswith(".labels.toml"):
        print(
            "ERROR: decomp seeds are not verified mappings; "
            "refusing to write labels.toml. Use --out <stem>.evidence.jsonl",
            file=sys.stderr,
        )
        return 1

    rom_size = a.rom.stat().st_size
    sha = labels_toml.rom_sha256(a.rom)
    recs, stats = candidates_from_harvest(harvest(a.elf, a.readelf), rom_size)

    out = a.out or evidence.sidecar_path_for_rom(a.rom)
    existing = 0
    if out.exists():
        _, prev = evidence.load(out, expected_sha=sha)
        existing = len(prev)
        for key, rec in recs.items():
            evidence.upsert(out, sha, rec)
        # upsert one-by-one already saved; recount
        _, recs = evidence.load(out, expected_sha=sha)
    else:
        evidence.save(out, sha, recs)

    print(
        f"seeded {out}: {len(recs)} unresolved candidates "
        f"(decomp-reference; not verified; not written to labels.toml) "
        f"({stats['kept']} from ELF, {existing} pre-existing sidecar, "
        f"{stats['dupes']} alias dupes, {stats['dropped']} outside ROM)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
