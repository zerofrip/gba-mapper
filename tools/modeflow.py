#!/usr/bin/env python3
"""ARMv4T control-flow decode from ROM bytes. No objdump, no toolchain.

CandidateKey = (address, mode) with mode in {"arm", "thumb"}.
Immediate BLX is ARMv5 and is never treated as a valid edge.
"""
from __future__ import annotations

from dataclasses import dataclass, field

ROM_BASE = 0x08000000
HEADER_DATA_LO = ROM_BASE + 0x4
HEADER_DATA_HI = ROM_BASE + 0xC0

MODES = ("arm", "thumb")
CandidateKey = tuple[int, str]


def _mode(m: str | None) -> str | None:
    if m is None:
        return None
    if m not in MODES:
        raise ValueError(f"invalid mode {m!r}")
    return m


def pointer_mode(ptr: int) -> tuple[int, str]:
    """GBA interworking: bit 0 selects Thumb. Address is even."""
    return ptr & ~1, ("thumb" if ptr & 1 else "arm")


@dataclass(frozen=True)
class FlowEdge:
    src: int
    src_mode: str
    insn: str
    target: int | None
    target_mode: str | None
    evidence_type: str

    def __post_init__(self) -> None:
        _mode(self.src_mode)
        if self.target_mode is not None:
            _mode(self.target_mode)


@dataclass
class Candidate:
    address: int
    mode: str
    evidence: list[dict] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def key(self) -> tuple[int, str]:
        return (self.address, self.mode)


def u16(data: bytes, off: int) -> int | None:
    if off < 0 or off + 2 > len(data):
        return None
    return int.from_bytes(data[off:off + 2], "little")


def u32(data: bytes, off: int) -> int | None:
    if off < 0 or off + 4 > len(data):
        return None
    return int.from_bytes(data[off:off + 4], "little")


def _sign(val: int, bits: int) -> int:
    s = 1 << (bits - 1)
    return (val & (s - 1)) - (val & s)


def _in_rom(addr: int, size: int) -> bool:
    return ROM_BASE <= addr < ROM_BASE + size


def _header_data(addr: int) -> bool:
    return HEADER_DATA_LO <= addr < HEADER_DATA_HI


# --- Thumb ---------------------------------------------------------------

def decode_thumb(data: bytes, vma: int, size: int | None = None) -> list[FlowEdge]:
    """Linear Thumb walk. Literal-pool words are skipped, not decoded as code."""
    size = size if size is not None else len(data)
    edges: list[FlowEdge] = []
    pool: set[int] = set()
    last_ldr: dict[int, int] = {}  # rd -> loaded pointer (one-hit, not speculative DF)
    i = 0
    while i + 2 <= len(data):
        addr = vma + i
        if addr in pool:
            i += 2
            continue
        h = u16(data, i)
        if h is None:
            break

        # v5 BLX prefix 11101 — not valid v4T. Do not emit blx-target.
        if (h & 0xF800) == 0xE800:
            i += 2
            continue

        # BL pair: 11110 + 11111
        if (h & 0xF800) == 0xF000 and i + 4 <= len(data):
            h2 = u16(data, i + 2)
            if h2 is not None and (h2 & 0xF800) == 0xF800:
                imm = (_sign(h & 0x7FF, 11) << 12) | ((h2 & 0x7FF) << 1)
                tgt = (addr + 4 + imm) & 0xFFFFFFFF
                edges.append(FlowEdge(addr, "thumb", "bl", tgt, "thumb", "bl-target"))
                i += 4
                last_ldr.clear()
                continue

        # B unconditional 11100. Same mode; not a function-entry harvest.
        if (h & 0xF800) == 0xE000:
            imm = _sign(h & 0x7FF, 11) << 1
            tgt = (addr + 4 + imm) & 0xFFFFFFFF
            edges.append(FlowEdge(addr, "thumb", "b", tgt, "thumb", "cfg-consistency"))
            i += 2
            last_ldr.clear()
            continue

        # B conditional 1101 (not SWI 11011111)
        if (h & 0xF000) == 0xD000 and (h & 0x0F00) != 0x0F00:
            imm = _sign(h & 0xFF, 8) << 1
            tgt = (addr + 4 + imm) & 0xFFFFFFFF
            edges.append(FlowEdge(addr, "thumb", "b", tgt, "thumb", "cfg-consistency"))
            i += 2
            last_ldr.clear()
            continue

        # BX: 010001110 Rm000
        if (h & 0xFF87) == 0x4700:
            rm = (h >> 3) & 0xF
            ptr = last_ldr.get(rm)
            if ptr is None:
                edges.append(FlowEdge(addr, "thumb", "bx", None, None, "indirect-branch"))
            else:
                tgt, tmode = pointer_mode(ptr)
                edges.append(FlowEdge(addr, "thumb", "bx", tgt, tmode, "bx-target"))
            i += 2
            last_ldr.clear()
            continue

        # LDR Rd, [pc, #imm]  01001
        if (h & 0xF800) == 0x4800:
            rd = (h >> 8) & 7
            imm = (h & 0xFF) << 2
            pool_addr = ((addr + 4) & ~3) + imm
            pool.add(pool_addr)
            off = pool_addr - vma
            word = u32(data, off)
            if word is not None:
                last_ldr[rd] = word
                edges.append(FlowEdge(
                    addr, "thumb", "ldr-literal", pool_addr, None, "literal-pool",
                ))
            i += 2
            continue

        i += 2
        last_ldr.clear()
    return edges


# --- ARM -----------------------------------------------------------------

def _arm_branch_target(addr: int, word: int) -> int:
    imm = _sign(word & 0xFFFFFF, 24) << 2
    return (addr + 8 + imm) & 0xFFFFFFFF


def decode_arm(data: bytes, vma: int, size: int | None = None) -> list[FlowEdge]:
    size = size if size is not None else len(data)
    edges: list[FlowEdge] = []
    pool: set[int] = set()
    last_ldr: dict[int, int] = {}
    i = 0
    # ARM must be word-aligned; skip odd lead.
    if vma % 4:
        i = 4 - (vma % 4)
    while i + 4 <= len(data):
        addr = vma + i
        if addr in pool:
            i += 4
            continue
        w = u32(data, i)
        if w is None:
            break

        # ARMv5 immediate BLX: cond=1111, 101x. Not valid v4T.
        if (w & 0xFE000000) == 0xFA000000:
            i += 4
            last_ldr.clear()
            continue

        # B / BL: cond != 1111, 101 L imm24
        if (w >> 25) & 7 == 0b101 and (w >> 28) != 0xF:
            tgt = _arm_branch_target(addr, w)
            link = (w >> 24) & 1
            if link:
                edges.append(FlowEdge(addr, "arm", "bl", tgt, "arm", "bl-target"))
            elif addr == ROM_BASE:
                edges.append(FlowEdge(addr, "arm", "b", tgt, "arm", "vector-entry"))
            else:
                edges.append(FlowEdge(addr, "arm", "b", tgt, "arm", "cfg-consistency"))
            i += 4
            last_ldr.clear()
            continue

        # BX: xxxx 0001 0010 1111 1111 1111 0001 nnnn
        if (w & 0x0FFFFFF0) == 0x012FFF10:
            rm = w & 0xF
            ptr = last_ldr.get(rm)
            if ptr is None:
                edges.append(FlowEdge(addr, "arm", "bx", None, None, "indirect-branch"))
            else:
                tgt, tmode = pointer_mode(ptr)
                edges.append(FlowEdge(addr, "arm", "bx", tgt, tmode, "bx-target"))
            i += 4
            last_ldr.clear()
            continue

        # LDR pc, [pc, #+/-imm12]  — statically resolvable PC write
        # 01 0 P U B W L Rn=15 Rd=15
        if (w & 0x0E5FF000) == 0x041FF000 and ((w >> 16) & 0xF) == 15 and ((w >> 12) & 0xF) == 15:
            imm = w & 0xFFF
            up = (w >> 23) & 1
            pre = (w >> 24) & 1
            if pre:
                pool_addr = addr + 8 + (imm if up else -imm)
                word = u32(data, pool_addr - vma)
                if word is not None:
                    tgt, tmode = pointer_mode(word)
                    edges.append(FlowEdge(addr, "arm", "ldr-pc", tgt, tmode, "bx-target"))
                    pool.add(pool_addr)
                    edges.append(FlowEdge(
                        addr, "arm", "ldr-literal", pool_addr, None, "literal-pool",
                    ))
            i += 4
            last_ldr.clear()
            continue

        # LDR rd, [pc, #+/-imm12]  rd != pc  → literal pool, track rd
        if (w & 0x0E5F0000) == 0x041F0000 and ((w >> 16) & 0xF) == 15 and ((w >> 20) & 1):
            rd = (w >> 12) & 0xF
            if rd != 15:
                imm = w & 0xFFF
                up = (w >> 23) & 1
                pre = (w >> 24) & 1
                if pre:
                    pool_addr = addr + 8 + (imm if up else -imm)
                    pool.add(pool_addr)
                    word = u32(data, pool_addr - vma)
                    if word is not None:
                        last_ldr[rd] = word
                    edges.append(FlowEdge(
                        addr, "arm", "ldr-literal", pool_addr, None, "literal-pool",
                    ))
                i += 4
                continue

        # Obvious jump table: LDR{cond} pc, [pc, rm, lsl #2]
        if (
            ((w >> 25) & 7) == 0b011
            and ((w >> 24) & 1) == 1
            and ((w >> 22) & 1) == 0
            and ((w >> 21) & 1) == 0
            and ((w >> 20) & 1) == 1
            and ((w >> 16) & 0xF) == 15
            and ((w >> 12) & 0xF) == 15
            and ((w >> 7) & 0x1F) == 2
            and ((w >> 5) & 3) == 0
            and ((w >> 4) & 1) == 0
        ):
            edges.append(FlowEdge(addr, "arm", "ldr-jt", None, None, "jump-table"))
            i += 4
            last_ldr.clear()
            continue

        i += 4
        last_ldr.clear()
    return edges


def header_vector_edge(data: bytes, vma: int = ROM_BASE) -> FlowEdge | None:
    """ARM B at 0x08000000 is vector-entry. Does not cover the logo."""
    if vma != ROM_BASE or len(data) < 4:
        return None
    w = u32(data, 0)
    if w is None:
        return None
    if (w >> 25) & 7 != 0b101 or (w >> 24) & 1:
        return None  # not B (must not be BL)
    if (w >> 28) == 0xF:
        return None
    tgt = _arm_branch_target(ROM_BASE, w)
    return FlowEdge(ROM_BASE, "arm", "b", tgt, "arm", "vector-entry")


def decode(data: bytes, vma: int, mode: str) -> list[FlowEdge]:
    mode = _mode(mode)  # type: ignore[assignment]
    if mode == "thumb":
        return decode_thumb(data, vma)
    return decode_arm(data, vma)


def _edge_evidence(edge: FlowEdge) -> dict:
    d = {
        "type": edge.evidence_type,
        "source": "modeflow",
        "insn": edge.insn,
        "from_addr": edge.src,
        "source_mode": edge.src_mode,
    }
    if edge.target is not None:
        d["target_addr"] = edge.target
    if edge.target_mode is not None:
        d["target_mode"] = edge.target_mode
    return d


# Evidence types that mint a function candidate at the target.
_ENTRY_TYPES = frozenset({"bl-target", "bx-target", "vector-entry"})


def candidates_from_edges(
    edges: list[FlowEdge],
    rom_size: int,
    *,
    skip_header_data: bool = True,
) -> dict[tuple[int, str], Candidate]:
    """Mint candidates only for statically known (target, target_mode).

    indirect-branch / jump-table / literal-pool / cfg-consistency (B)
    do not create functions.
    """
    out: dict[tuple[int, str], Candidate] = {}
    for e in edges:
        if e.evidence_type not in _ENTRY_TYPES:
            continue
        if e.target is None or e.target_mode is None:
            continue
        if not _in_rom(e.target, rom_size):
            continue
        if skip_header_data and _header_data(e.target):
            continue
        # vector-entry: candidate is the *target* (stub), not the header word
        # covering the logo.
        key = (e.target, e.target_mode)
        ev = _edge_evidence(e)
        if key not in out:
            out[key] = Candidate(e.target, e.target_mode, evidence=[ev])
        else:
            if ev not in out[key].evidence:
                out[key].evidence.append(ev)

    # Dual-mode at the same address: keep both, mark conflicts. Never pick one.
    by_addr: dict[int, list[Candidate]] = {}
    for c in out.values():
        by_addr.setdefault(c.address, []).append(c)
    for addr, group in by_addr.items():
        modes = {c.mode for c in group}
        if modes == {"arm", "thumb"}:
            msg = f"mode conflict at {addr:#010x}: arm and thumb evidence"
            for c in group:
                if msg not in c.conflicts:
                    c.conflicts.append(msg)
    return out


def merge_candidates(
    groups: list[dict[tuple[int, str], Candidate]],
) -> dict[tuple[int, str], Candidate]:
    acc: dict[tuple[int, str], Candidate] = {}
    for g in groups:
        for key, c in g.items():
            if key not in acc:
                acc[key] = Candidate(c.address, c.mode, list(c.evidence), list(c.conflicts))
                continue
            dst = acc[key]
            for ev in c.evidence:
                if ev not in dst.evidence:
                    dst.evidence.append(ev)
            for msg in c.conflicts:
                if msg not in dst.conflicts:
                    dst.conflicts.append(msg)
    by_addr: dict[int, list[Candidate]] = {}
    for c in acc.values():
        by_addr.setdefault(c.address, []).append(c)
    for addr, group in by_addr.items():
        modes = {c.mode for c in group}
        if modes == {"arm", "thumb"}:
            msg = f"mode conflict at {addr:#010x}: arm and thumb evidence"
            for c in group:
                if msg not in c.conflicts:
                    c.conflicts.append(msg)
    return acc
