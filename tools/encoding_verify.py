#!/usr/bin/env python3
"""Phase 8E ROM encoding verification. Authoritative encoding_verified only here.

Reads Phase 7A candidates and a local ROM file. Emits a standalone
verification artifact. Does not alter selection/disposition, mint
candidates, or invoke 7B/7C/RANGE.

    8D claim != encoding_verified
    LLM claim != encoding_verified
    human claim != encoding_verified

Usage:
  python3 tools/encoding_verify.py INPUT --rom ROM.gba [--output PATH]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from encoding_claim import _candidate_keys
from encoding_decoder import ROM_BASE, ROM_WINDOW_END, verify_encoding

_DECODER_VERSION = "8e-v1"


def _load_rom(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def verify(phase7a: dict, rom: bytes | None) -> dict:
    errors: list[dict] = []
    results: list[dict] = []
    if rom is None:
        errors.append({"error": "rom-unavailable"})
        return _artifact(results, errors)
    candidates = _candidate_keys(phase7a)
    for key, row in sorted(candidates.items()):
        addr_s = str(row.get("address"))
        mode_s = key[1]
        err = verify_encoding(rom, key[0], mode_s)
        if err is None:
            results.append({
                "address": addr_s,
                "mode": mode_s,
                "encoding_verified": True,
            })
        else:
            errors.append({
                "address": addr_s,
                "mode": mode_s,
                "error": err,
            })
    return _artifact(results, errors)


def _artifact(results: list[dict], errors: list[dict]) -> dict:
    return {
        "format": "gba-mapper-encoding-verification",
        "version": 1,
        "run": {
            "deterministic": True,
            "decoder_version": _DECODER_VERSION,
        },
        "results": results,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--rom", type=Path, required=True, help="local ROM file (read-only)")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    a = p.parse_args(argv)
    phase7a = json.loads(a.input.read_text())
    rom = _load_rom(a.rom)
    result = verify(phase7a, rom)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
