"""ARM/Thumb encoding validity for Phase 8E. Not control-flow.

Validates that ROM bytes at an address can be decoded as a single
instruction in the requested mode. Does not analyze control flow,
function boundaries, ends, or peel semantics.
"""
from __future__ import annotations

ROM_BASE = 0x08000000
ROM_WINDOW_END = 0x0A000000


def u16(data: bytes, off: int) -> int | None:
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "little")


def u32(data: bytes, off: int) -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def rom_offset(addr: int, rom_size: int) -> int | None:
    if not (ROM_BASE <= addr < ROM_WINDOW_END):
        return None
    off = addr - ROM_BASE
    if off >= rom_size:
        return None
    return off


def verify_thumb_encoding(data: bytes, offset: int) -> str | None:
    """Return error code or None when encoding is valid."""
    h = u16(data, offset)
    if h is None:
        return "truncated-instruction"
    if (h & 0xF800) == 0xE800:
        return "invalid-encoding"
    if (h & 0xF800) == 0xF000:
        h2 = u16(data, offset + 2)
        if h2 is None:
            return "truncated-instruction"
        if (h2 & 0xF800) != 0xF800:
            return "invalid-encoding"
    return None


def verify_arm_encoding(data: bytes, offset: int, addr: int) -> str | None:
    """Return error code or None when encoding is valid."""
    if addr % 4 != 0:
        return "invalid-encoding"
    w = u32(data, offset)
    if w is None:
        return "truncated-instruction"
    if (w & 0xFE000000) == 0xFA000000:
        return "invalid-encoding"
    return None


def verify_encoding(data: bytes, addr: int, mode: str) -> str | None:
    off = rom_offset(addr, len(data))
    if off is None:
        return "invalid-address"
    if mode == "thumb":
        return verify_thumb_encoding(data, off)
    if mode == "arm":
        return verify_arm_encoding(data, off, addr)
    return "invalid-mode"
