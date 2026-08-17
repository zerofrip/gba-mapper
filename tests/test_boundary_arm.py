"""Conservative ARM boundary from synthetic bytes. No objdump / ROM / as."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import boundary  # noqa: E402

START = 0x08001000


def w32(x: int) -> bytes:
    return int(x).to_bytes(4, "little")


class ArmBoundary(unittest.TestCase):
    def test_prologue_stmdb_evidence(self):
        # stmfd sp!, {r4, lr}
        data = w32(0xE92D4010) + w32(0xE12FFF1E)
        rep = boundary.detect_boundary_arm_bytes(data, START)
        types = [e["type"] for e in rep["evidence"]]
        self.assertIn("prologue", types)
        self.assertTrue(boundary.is_arm_prologue(0xE92D4010))

    def test_epilogue_ldm_pc(self):
        data = w32(0xE92D4010) + w32(0xE8BD8010)  # ldmfd sp!, {r4, pc}
        rep = boundary.detect_boundary_arm_bytes(data, START)
        self.assertEqual(rep["recommendedEnd"], START + 8)
        self.assertIn("epilogue", [e["type"] for e in rep["evidence"]])
        self.assertTrue(boundary.is_arm_epilogue(0xE8BD8010))

    def test_epilogue_bx_lr(self):
        data = w32(0xE92D4010) + w32(0xE12FFF1E)
        rep = boundary.detect_boundary_arm_bytes(data, START)
        self.assertEqual(rep["recommendedEnd"], START + 8)
        self.assertTrue(boundary.is_arm_epilogue(0xE12FFF1E))

    def test_epilogue_mov_pc_lr(self):
        data = w32(0xE92D4010) + w32(0xE1A0F00E)
        rep = boundary.detect_boundary_arm_bytes(data, START)
        self.assertEqual(rep["recommendedEnd"], START + 8)
        self.assertTrue(boundary.is_arm_epilogue(0xE1A0F00E))

    def test_unconditional_b_does_not_terminate(self):
        # stmfd; b somewhere; ldmfd pc. End is the LDM, not the B.
        b = 0xEA000000  # b .+8 (imm24=0) still a B
        data = w32(0xE92D4010) + w32(b) + w32(0xE8BD8010)
        self.assertFalse(boundary.is_arm_epilogue(b))
        rep = boundary.detect_boundary_arm_bytes(data, START)
        self.assertEqual(rep["recommendedEnd"], START + 12)
        epi = [e for e in rep["evidence"] if e["type"] == "epilogue"]
        self.assertEqual(epi[0]["addr"], START + 8)


if __name__ == "__main__":
    unittest.main()
