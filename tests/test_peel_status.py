"""Peel emits .incbin; RANGE_VERIFIED only after make check."""
from __future__ import annotations

import inspect
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import evidence  # noqa: E402
import labels_toml  # noqa: E402
import peel  # noqa: E402
from peel import emit  # noqa: E402


class IncbinPreserved(unittest.TestCase):
    def test_emit_is_incbin_not_mnemonics(self):
        text = emit("baserom.gba", 0x08000000, 0x08000004, "arm", "entry",
                    ["08000000: ea00002e  b 0x080000c0"])
        self.assertIn('.incbin "baserom.gba"', text)
        self.assertIn("arm_func_start", text)
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("b ") or stripped.startswith("bl "):
                self.fail(f"bare mnemonic in peel body: {line}")

    def test_peel_module_does_not_record_range(self):
        src = inspect.getsource(peel)
        self.assertNotIn("record_range_verified", src)
        self.assertNotIn("record_range_after_check", src)


class RangeAfterCheck(unittest.TestCase):
    def test_failed_check_does_not_write(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "game.evidence.jsonl"
            rec = evidence.record_range_after_check(
                False, path, "c" * 64, 0x080000C0, "thumb", 0x080000F0, "sub",
            )
            self.assertIsNone(rec)
            self.assertFalse(path.exists())

    def test_successful_check_writes_range_not_encoding(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "game.evidence.jsonl"
            rec = evidence.record_range_after_check(
                True, path, "c" * 64, 0x080000C0, "thumb", 0x080000F0, "sub_080000C0",
            )
            self.assertIsNotNone(rec)
            self.assertEqual(rec.status, evidence.RANGE_VERIFIED)
            with self.assertRaises(evidence.PromotionError):
                evidence.promote_encoding_verified(rec)
            _, recs = evidence.load(path, "c" * 64)
            self.assertEqual(recs[(0x080000C0, "thumb")].status, evidence.RANGE_VERIFIED)

    def test_clear_drops_range_keeps_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "game.evidence.jsonl"
            sha = "d" * 64
            other = evidence.Record(
                address=0x08000100, mode="thumb", status=evidence.UNRESOLVED,
                evidence=[evidence.Evidence("decomp-reference", "seed_from_decomp", "elf")],
            )
            evidence.save(path, sha, {other.key(): other})
            evidence.record_range_after_check(
                True, path, sha, 0x080000C0, "thumb", 0x080000F0, "sub",
            )
            self.assertTrue(evidence.clear_range_verified(path, sha, 0x080000C0, "thumb"))
            _, recs = evidence.load(path, sha)
            self.assertNotIn((0x080000C0, "thumb"), recs)
            self.assertEqual(recs[(0x08000100, "thumb")].status, evidence.UNRESOLVED)

    def test_cli_make_check_green_records(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rom = td / "game.gba"
            rom.write_bytes(bytes(64))
            (td / "Makefile").write_text("check:\n\t@exit 0\n")
            proc = subprocess.run(
                [
                    sys.executable, str(TOOLS / "evidence.py"), "record-range",
                    "--tree", str(td), "--rom", rom.name,
                    "--start", "0x08000000", "--end", "0x08000004",
                    "--mode", "arm", "--name", "entry",
                ],
                capture_output=True, text=True, cwd=td,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            side = td / "game.evidence.jsonl"
            self.assertTrue(side.exists())
            _, recs = evidence.load(side, labels_toml.rom_sha256(rom))
            self.assertEqual(recs[(0x08000000, "arm")].status, evidence.RANGE_VERIFIED)

    def test_cli_make_check_red_does_not_record(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rom = td / "game.gba"
            rom.write_bytes(bytes(64))
            (td / "Makefile").write_text("check:\n\t@exit 1\n")
            proc = subprocess.run(
                [
                    sys.executable, str(TOOLS / "evidence.py"), "record-range",
                    "--tree", str(td), "--rom", rom.name,
                    "--start", "0x08000000", "--end", "0x08000004",
                    "--mode", "arm",
                ],
                capture_output=True, text=True, cwd=td,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse((td / "game.evidence.jsonl").exists())


class LabelsTomlUntouchedByRangeRecord(unittest.TestCase):
    def test_recording_range_does_not_create_labels(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rom = td / "game.gba"
            rom.write_bytes(bytes(64))
            side = td / "game.evidence.jsonl"
            evidence.record_range_after_check(
                True, side, labels_toml.rom_sha256(rom),
                0x08000000, "arm", 0x08000004, "entry",
            )
            self.assertFalse((td / "game.labels.toml").exists())


if __name__ == "__main__":
    unittest.main()
