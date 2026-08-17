"""ARMv4T modeflow: synthetic bytes, no ROM / objdump / toolchain."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import modeflow  # noqa: E402

VMA = 0x08001000
ROM_SIZE = 0x20000


def h16(x: int) -> bytes:
    return int(x).to_bytes(2, "little")


def w32(x: int) -> bytes:
    return int(x).to_bytes(4, "little")


def thumb_bl(src: int, tgt: int) -> bytes:
    off = tgt - src - 4
    hi = (off >> 12) & 0x7FF
    lo = (off >> 1) & 0x7FF
    return h16(0xF000 | hi) + h16(0xF800 | lo)


def arm_b(src: int, tgt: int, *, link: bool = False) -> bytes:
    imm = ((tgt - src - 8) >> 2) & 0xFFFFFF
    return w32((0xEB000000 if link else 0xEA000000) | imm)


def types(edges) -> list[str]:
    return [e.evidence_type for e in edges]


class ThumbBL(unittest.TestCase):
    def test_thumb_bl_stays_thumb(self):
        src, tgt = VMA, VMA + 0x40
        edges = modeflow.decode_thumb(thumb_bl(src, tgt), src)
        self.assertEqual(len(edges), 1)
        e = edges[0]
        self.assertEqual(e.insn, "bl")
        self.assertEqual(e.src_mode, "thumb")
        self.assertEqual(e.target, tgt)
        self.assertEqual(e.target_mode, "thumb")
        self.assertEqual(e.evidence_type, "bl-target")
        cands = modeflow.candidates_from_edges(edges, ROM_SIZE)
        self.assertIn((tgt, "thumb"), cands)
        self.assertNotIn((tgt, "arm"), cands)

    def test_thumb_bl_backward_stays_thumb(self):
        src, tgt = 0x08002040, 0x08001000
        edges = modeflow.decode_thumb(thumb_bl(src, tgt), src)
        self.assertEqual(len(edges), 1)
        e = edges[0]
        self.assertEqual(e.target, tgt)
        self.assertEqual(e.target_mode, "thumb")
        self.assertEqual(e.evidence_type, "bl-target")


class ArmBL(unittest.TestCase):
    def test_arm_bl_stays_arm(self):
        src, tgt = VMA, VMA + 0x40
        edges = modeflow.decode_arm(arm_b(src, tgt, link=True), src)
        self.assertEqual(len(edges), 1)
        e = edges[0]
        self.assertEqual(e.insn, "bl")
        self.assertEqual(e.src_mode, "arm")
        self.assertEqual(e.target, tgt)
        self.assertEqual(e.target_mode, "arm")
        self.assertEqual(e.evidence_type, "bl-target")
        cands = modeflow.candidates_from_edges(edges, ROM_SIZE)
        self.assertIn((tgt, "arm"), cands)
        self.assertNotIn((tgt, "thumb"), cands)


class BxPointer(unittest.TestCase):
    def test_bx_known_pointer_bit0_thumb(self):
        # ldr r0, [pc, #0]; bx r0; .word thumb_ptr
        ptr = 0x08002001
        data = h16(0x4800) + h16(0x4700) + w32(ptr)
        edges = modeflow.decode_thumb(data, VMA)
        bx = [e for e in edges if e.insn == "bx"]
        self.assertEqual(len(bx), 1)
        self.assertEqual(bx[0].target, ptr & ~1)
        self.assertEqual(bx[0].target_mode, "thumb")
        self.assertEqual(bx[0].evidence_type, "bx-target")
        cands = modeflow.candidates_from_edges(edges, ROM_SIZE)
        self.assertIn((ptr & ~1, "thumb"), cands)

    def test_bx_known_pointer_bit0_arm(self):
        ptr = 0x08002000
        # ARM: ldr r0, [pc, #0]; bx r0; .word ptr
        data = w32(0xE59F0000) + w32(0xE12FFF10) + w32(ptr)
        edges = modeflow.decode_arm(data, VMA)
        bx = [e for e in edges if e.insn == "bx"]
        self.assertEqual(len(bx), 1)
        self.assertEqual(bx[0].target, ptr)
        self.assertEqual(bx[0].target_mode, "arm")
        self.assertEqual(bx[0].evidence_type, "bx-target")

    def test_unknown_bx_is_indirect_no_candidate(self):
        data = h16(0x4700)  # bx r0, no prior literal
        edges = modeflow.decode_thumb(data, VMA)
        self.assertEqual(len(edges), 1)
        e = edges[0]
        self.assertIsNone(e.target)
        self.assertIsNone(e.target_mode)
        self.assertEqual(e.evidence_type, "indirect-branch")
        self.assertEqual(modeflow.candidates_from_edges(edges, ROM_SIZE), {})

    def test_arm_unknown_bx_is_indirect_no_candidate(self):
        data = w32(0xE12FFF10)  # bx r0
        edges = modeflow.decode_arm(data, VMA)
        self.assertEqual(edges[0].evidence_type, "indirect-branch")
        self.assertIsNone(edges[0].target)
        self.assertEqual(modeflow.candidates_from_edges(edges, ROM_SIZE), {})


class Armv5BlxRejected(unittest.TestCase):
    def test_arm_immediate_blx_not_a_v4t_edge(self):
        data = w32(0xFA00000E) + w32(0xFB00000E)
        edges = modeflow.decode_arm(data, VMA)
        self.assertEqual(edges, [])
        self.assertNotIn("blx-target", types(edges))

    def test_thumb_blx_prefix_not_a_v4t_edge(self):
        data = h16(0xE800) + h16(0xE800)
        edges = modeflow.decode_thumb(data, VMA)
        self.assertEqual(edges, [])
        self.assertNotIn("blx-target", types(edges))


class CandidateIdentity(unittest.TestCase):
    def test_same_address_arm_and_thumb_are_separate_keys(self):
        tgt = 0x08001234
        thumb_e = modeflow.FlowEdge(VMA, "thumb", "bl", tgt, "thumb", "bl-target")
        arm_e = modeflow.FlowEdge(VMA + 4, "arm", "bl", tgt, "arm", "bl-target")
        cands = modeflow.candidates_from_edges([thumb_e, arm_e], ROM_SIZE)
        self.assertIn((tgt, "thumb"), cands)
        self.assertIn((tgt, "arm"), cands)
        self.assertEqual(len(cands), 2)
        for c in cands.values():
            self.assertTrue(any("mode conflict" in m for m in c.conflicts))

    def test_evidence_merging_does_not_overwrite(self):
        tgt = 0x08001234
        a = modeflow.FlowEdge(VMA, "thumb", "bl", tgt, "thumb", "bl-target")
        b = modeflow.FlowEdge(VMA + 8, "thumb", "bl", tgt, "thumb", "bl-target")
        g1 = modeflow.candidates_from_edges([a], ROM_SIZE)
        g2 = modeflow.candidates_from_edges([b], ROM_SIZE)
        merged = modeflow.merge_candidates([g1, g2])
        key = (tgt, "thumb")
        self.assertEqual(len(merged[key].evidence), 2)
        srcs = {ev["from_addr"] for ev in merged[key].evidence}
        self.assertEqual(srcs, {VMA, VMA + 8})

    def test_conflicting_modes_kept(self):
        tgt = 0x08001234
        g1 = modeflow.candidates_from_edges(
            [modeflow.FlowEdge(VMA, "thumb", "bl", tgt, "thumb", "bl-target")],
            ROM_SIZE,
        )
        g2 = modeflow.candidates_from_edges(
            [modeflow.FlowEdge(VMA, "arm", "bl", tgt, "arm", "bl-target")],
            ROM_SIZE,
        )
        merged = modeflow.merge_candidates([g1, g2])
        self.assertEqual(set(merged), {(tgt, "arm"), (tgt, "thumb")})
        self.assertTrue(all(c.conflicts for c in merged.values()))

    def test_unconditional_b_does_not_mint_a_function(self):
        src, tgt = VMA, VMA + 0x20
        # Thumb B uncond: 11100 imm11
        off = (tgt - src - 4) >> 1
        data = h16(0xE000 | (off & 0x7FF))
        edges = modeflow.decode_thumb(data, src)
        self.assertEqual(edges[0].insn, "b")
        self.assertEqual(edges[0].evidence_type, "cfg-consistency")
        self.assertEqual(modeflow.candidates_from_edges(edges, ROM_SIZE), {})

    def test_invalid_mode_rejected(self):
        with self.assertRaises(ValueError):
            modeflow.FlowEdge(VMA, "thumb2", "bl", VMA, "thumb", "bl-target")


class LiteralPoolAndJumpTable(unittest.TestCase):
    def test_literal_pool_not_harvested_as_code(self):
        # ldr r1, [pc, #0] at VMA → pool at VMA+4. Pool bytes look like a BL.
        fake_bl = thumb_bl(VMA + 4, VMA + 0x44)
        data = h16(0x4900) + h16(0x0000) + fake_bl
        edges = modeflow.decode_thumb(data, VMA)
        self.assertTrue(any(e.evidence_type == "literal-pool" for e in edges))
        self.assertFalse(any(e.src == VMA + 4 for e in edges))
        bls = [e for e in edges if e.insn == "bl"]
        self.assertEqual(bls, [])

    def test_obvious_jump_table_evidence_only(self):
        # LDR pc, [pc, r2, lsl #2]
        data = w32(0xE79FF102)
        edges = modeflow.decode_arm(data, VMA)
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0].evidence_type, "jump-table")
        self.assertIsNone(edges[0].target)
        self.assertEqual(modeflow.candidates_from_edges(edges, ROM_SIZE), {})


class VectorEntry(unittest.TestCase):
    def test_header_arm_b_is_vector_entry_not_logo_function(self):
        stub = 0x080000C0
        header = arm_b(modeflow.ROM_BASE, stub) + bytes(0xC0 - 4)
        edges = modeflow.decode_arm(header, modeflow.ROM_BASE)
        vec = [e for e in edges if e.evidence_type == "vector-entry"]
        self.assertEqual(len(vec), 1)
        self.assertEqual(vec[0].src, modeflow.ROM_BASE)
        self.assertEqual(vec[0].target, stub)
        self.assertEqual(vec[0].target_mode, "arm")
        cands = modeflow.candidates_from_edges(edges, 0x200)
        self.assertIn((stub, "arm"), cands)
        self.assertNotIn((modeflow.ROM_BASE + 4, "arm"), cands)
        logo = modeflow.candidates_from_edges(
            [modeflow.FlowEdge(
                modeflow.ROM_BASE, "arm", "b",
                modeflow.ROM_BASE + 0x20, "arm", "vector-entry",
            )],
            0x200,
        )
        self.assertEqual(logo, {})


if __name__ == "__main__":
    unittest.main()
