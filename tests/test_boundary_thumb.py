"""Thumb boundary regressions from synthetic insns. No objdump / ROM / as."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import boundary  # noqa: E402

START = 0x08001000


def insn(addr: int, raw: str, mnemonic: str, operands: str = "") -> dict:
    return {
        "addr": addr,
        "raw_bytes": raw,
        "bytes_num": int(raw.replace(" ", ""), 16),
        "mnemonic": mnemonic,
        "operands": operands,
    }


class ThumbEpilogue(unittest.TestCase):
    def test_pop_pc_is_epilogue(self):
        self.assertTrue(boundary.is_epilogue(insn(START, "bd10", "pop", "{r4, pc}")))

    def test_bx_lr_is_epilogue(self):
        self.assertTrue(boundary.is_epilogue(insn(START, "4770", "bx", "lr")))

    def test_bx_r3_is_not_epilogue(self):
        self.assertFalse(boundary.is_epilogue(insn(START, "4718", "bx", "r3")))

    def test_unconditional_b_is_not_epilogue(self):
        for mn, raw in (("b", "e000"), ("b.n", "e000"), ("b.w", "f000 b800")):
            self.assertFalse(
                boundary.is_epilogue(insn(START, raw, mn, "0x08001040")),
                msg=mn,
            )


class ThumbPushPop(unittest.TestCase):
    def test_push_lr_pop_pc_boundary(self):
        lines = [
            insn(START, "b510", "push", "{r4, lr}"),
            insn(START + 2, "1c00", "mov", "r0, r0"),
            insn(START + 4, "bd10", "pop", "{r4, pc}"),
            insn(START + 6, "b510", "push", "{r4, lr}"),
        ]
        rep = boundary.detect_boundary_from_insns(START, lines)
        self.assertEqual(rep["recommendedEnd"], START + 6)
        kinds = [e["type"] for e in rep["evidence"]]
        self.assertIn("prologue", kinds)
        self.assertIn("epilogue", kinds)

    def test_unconditional_b_does_not_end_function(self):
        lines = [
            insn(START, "b510", "push", "{r4, lr}"),
            insn(START + 2, "e001", "b", "0x08001008"),
            insn(START + 4, "1c00", "mov", "r0, r0"),
            insn(START + 6, "bd10", "pop", "{r4, pc}"),
            insn(START + 8, "b510", "push", "{r4, lr}"),
        ]
        rep = boundary.detect_boundary_from_insns(START, lines)
        self.assertEqual(rep["recommendedEnd"], START + 8)
        self.assertGreater(rep["recommendedEnd"], START + 4)

    def test_bx_rn_does_not_end_function(self):
        lines = [
            insn(START, "b510", "push", "{r4, lr}"),
            insn(START + 2, "4718", "bx", "r3"),
            insn(START + 4, "bd10", "pop", "{r4, pc}"),
            insn(START + 6, "b510", "push", "{r4, lr}"),
        ]
        rep = boundary.detect_boundary_from_insns(START, lines)
        self.assertEqual(rep["recommendedEnd"], START + 6)


class ThumbInteriorBl(unittest.TestCase):
    def test_interior_bl_revises_end(self):
        inner = START + 0x10
        lines = [
            insn(START, "b510", "push", "{r4, lr}"),
            insn(START + 2, "f000 f806", "bl", f"{inner:#x}"),
            insn(START + 6, "1c00", "mov", "r0, r0"),
            insn(START + 8, "bd10", "pop", "{r4, pc}"),
            insn(START + 0x20, "b510", "push", "{r4, lr}"),
        ]
        rep = boundary.detect_boundary_from_insns(START, lines)
        self.assertEqual(rep["recommendedEnd"], inner)
        kinds = [e["type"] for e in rep["evidence"]]
        self.assertIn("interior-bl", kinds)


class ThumbLiteralPool(unittest.TestCase):
    def test_pool_word_after_epilogue_is_evidence_not_code(self):
        # 0x08001234 as two halfwords after pop pc, then next push.
        pool = START + 4
        lines = [
            insn(START, "b510", "push", "{r4, lr}"),
            insn(START + 2, "bd00", "pop", "{pc}"),
            insn(pool, "1234", "lsls", "r4, r6, #4"),  # low half of 0x08001234
            insn(pool + 2, "0800", "lsrs", "r0, r0, #32"),  # high half 0x0800
            insn(pool + 4, "b510", "push", "{r4, lr}"),
        ]
        self.assertTrue(boundary.is_likely_pool_word(pool, lines))
        rep = boundary.detect_boundary_from_insns(START, lines)
        self.assertEqual(rep["recommendedEnd"], pool + 4)
        self.assertIn("literal-pool", [e["type"] for e in rep["evidence"]])


if __name__ == "__main__":
    unittest.main()
