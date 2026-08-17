#!/usr/bin/env python3
"""Import Ghidra JSON/JSONL as unverified ghidra-seed evidence.

Ghidra is a STATIC_ANALYSIS_ORACLE. Its output becomes frontier
discovery evidence only:

    type = ghidra-seed
    source = ghidra

It does NOT write labels.toml, the evidence sidecar, or gamedb.
It does NOT produce RANGE_VERIFIED or ENCODING_VERIFIED.
Ghidra is not a runtime dependency; this tool only consumes files.

Usage:
  python3 tools/import_ghidra.py INPUT [--output PATH]
  python3 tools/import_ghidra.py --input INPUT [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence
import frontier

ROM_BASE = 0x08000000
ROM_WINDOW_END = 0x0A000000
FILE_OFFSET_LIM = 0x02000000


@dataclass(frozen=True)
class GhidraRecord:
    address: int
    mode: str
    end: int | None = None
    size: int | None = None
    name: str | None = None


def parse_addr(value) -> int:
    """Parse an int or hex string. Reject bool, negative, empty, junk."""
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid address")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("invalid address")
        return value
    if isinstance(value, float):
        raise ValueError("invalid address")
    s = str(value).strip()
    if not s or s.startswith("-"):
        raise ValueError("invalid address")
    s = s.lower().replace("_", "")
    try:
        if s.startswith("0x"):
            return int(s, 16)
        return int(s, 16)
    except ValueError as exc:
        raise ValueError("invalid address") from exc


def normalize_rom_addr(addr: int) -> int:
    """Map file offsets into the GBA ROM window. Do not infer mode."""
    if 0 <= addr < FILE_OFFSET_LIM:
        return addr + ROM_BASE
    if ROM_BASE <= addr < ROM_WINDOW_END:
        return addr
    raise ValueError("invalid address")


def _opt_addr(raw: dict, key: str) -> int | None:
    if key not in raw or raw[key] is None:
        return None
    return normalize_rom_addr(parse_addr(raw[key]))


def parse_ghidra_record(raw) -> tuple[bool, GhidraRecord | dict]:
    """Return (True, GhidraRecord) or (False, {reason, raw})."""
    if not isinstance(raw, dict):
        return False, {"reason": "record is not an object", "raw": raw}
    if "address" not in raw:
        return False, {"reason": "missing address", "raw": raw}
    if "mode" not in raw or raw["mode"] in (None, ""):
        return False, {"reason": "missing mode", "raw": raw}
    mode = str(raw["mode"]).strip().lower()
    if mode not in ("arm", "thumb"):
        return False, {"reason": f"invalid mode {raw['mode']!r}", "raw": raw}
    try:
        address = normalize_rom_addr(parse_addr(raw["address"]))
    except ValueError:
        return False, {"reason": "invalid address", "raw": raw}
    end = None
    size = None
    try:
        if "end" in raw and raw["end"] is not None:
            end = normalize_rom_addr(parse_addr(raw["end"]))
            if end <= address:
                return False, {"reason": "invalid end", "raw": raw}
        if "size" in raw and raw["size"] is not None:
            if isinstance(raw["size"], bool) or not isinstance(raw["size"], int):
                return False, {"reason": "invalid size", "raw": raw}
            size = raw["size"]
            if size <= 0:
                return False, {"reason": "invalid size", "raw": raw}
    except ValueError:
        return False, {"reason": "invalid end", "raw": raw}
    name = raw.get("name")
    if name is not None:
        name = str(name)
    return True, GhidraRecord(address=address, mode=mode, end=end, size=size, name=name)


def parse_ghidra_json(text: str) -> tuple[list[GhidraRecord], list[dict]]:
    """Parse a JSON array or single object. Broken syntax rejects the file."""
    accepted: list[GhidraRecord] = []
    rejected: list[dict] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], [{"reason": "malformed JSON", "raw": text}]
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]
    else:
        return [], [{"reason": "JSON root is not an object or array", "raw": data}]
    for item in items:
        ok, rec = parse_ghidra_record(item)
        if ok:
            accepted.append(rec)  # type: ignore[arg-type]
        else:
            rejected.append(rec)  # type: ignore[arg-type]
    return accepted, rejected


def parse_ghidra_jsonl(text: str) -> tuple[list[GhidraRecord], list[dict]]:
    """One JSON object per non-empty line. Syntax errors reject the file."""
    items: list[object] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            return [], [{"reason": "malformed JSONL", "raw": text}]
    accepted: list[GhidraRecord] = []
    rejected: list[dict] = []
    for item in items:
        ok, rec = parse_ghidra_record(item)
        if ok:
            accepted.append(rec)  # type: ignore[arg-type]
        else:
            rejected.append(rec)  # type: ignore[arg-type]
    return accepted, rejected


def ghidra_record_to_evidence(record: GhidraRecord) -> evidence.Evidence:
    parts: list[str] = []
    if record.name:
        parts.append(f"ghidra function: {record.name}")
    else:
        parts.append("ghidra function")
    if record.size is not None:
        parts.append(f"ghidra_size={record.size}")
    if record.end is not None:
        parts.append(f"ghidra_end={record.end:#x}")
    return evidence.Evidence(
        type="ghidra-seed",
        source="ghidra",
        detail="; ".join(parts),
        target_addr=record.address,
        target_mode=record.mode,
    )


def ingest_ghidra(store: frontier.FrontierStore, records: list[GhidraRecord]) -> None:
    for rec in records:
        store.add_candidate(rec.address, rec.mode, ghidra_record_to_evidence(rec))


def import_ghidra_text(text: str) -> dict:
    store = frontier.FrontierStore()
    if not text.strip():
        return {
            "candidates": store.to_json_list(),
            "unresolved": [],
            "rejected": [],
        }
    if text.lstrip().startswith("["):
        accepted, rejected = parse_ghidra_json(text)
    else:
        try:
            json.loads(text)
        except json.JSONDecodeError:
            accepted, rejected = parse_ghidra_jsonl(text)
        else:
            accepted, rejected = parse_ghidra_json(text)
    ingest_ghidra(store, accepted)
    return {
        "candidates": store.to_json_list(),
        "unresolved": [e.to_json() for e in store.unresolved],
        "rejected": rejected,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input_pos", nargs="?", help="Ghidra JSON/JSONL path")
    p.add_argument("--input", dest="input_opt", help="Ghidra JSON/JSONL path")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    path = a.input_opt or a.input_pos
    if not path:
        p.error("INPUT or --input is required")
    text = Path(path).read_text()
    result = import_ghidra_text(text)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
