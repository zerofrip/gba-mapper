"""decomp ELF harvest becomes unresolved decomp-reference, not labels.toml."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import evidence  # noqa: E402
import labels_toml  # noqa: E402
from labels_toml import Fn  # noqa: E402
import seed_from_decomp  # noqa: E402


class HarvestCandidates(unittest.TestCase):
    def test_unresolved_decomp_reference(self):
        syms = [
            (Fn(0x080001C8, "thumb", 0x08000220, "AgbMain"), "GLOBAL"),
            (Fn(0x02000000, "arm", 0x02000010, "ram"), "GLOBAL"),  # outside ROM
        ]
        recs, stats = seed_from_decomp.candidates_from_harvest(syms, rom_size=0x1000)
        self.assertEqual(stats["kept"], 1)
        self.assertEqual(stats["dropped"], 1)
        rec = recs[(0x080001C8, "thumb")]
        self.assertEqual(rec.status, evidence.UNRESOLVED)
        self.assertEqual(rec.name, "AgbMain")
        self.assertEqual(rec.end, 0x08000220)
        self.assertEqual(rec.evidence[0].type, "decomp-reference")
        self.assertEqual(rec.evidence[0].source, "seed_from_decomp")
        self.assertEqual(list(evidence.iter_encoding_verified(recs.values())), [])

    def test_alias_dupe_prefers_global(self):
        syms = [
            (Fn(0x080001C8, "thumb", 0x08000200, "sub_080001C8"), "LOCAL"),
            (Fn(0x080001C8, "thumb", 0x08000220, "AgbMain"), "GLOBAL"),
        ]
        recs, stats = seed_from_decomp.candidates_from_harvest(syms, rom_size=0x1000)
        self.assertEqual(stats["dupes"], 1)
        self.assertEqual(recs[(0x080001C8, "thumb")].name, "AgbMain")
        self.assertEqual(recs[(0x080001C8, "thumb")].status, evidence.UNRESOLVED)


class DoesNotWriteLabels(unittest.TestCase):
    def test_sidecar_not_labels(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rom = td / "game.gba"
            rom.write_bytes(bytes(256))
            sha = labels_toml.rom_sha256(rom)
            recs, _ = seed_from_decomp.candidates_from_harvest(
                [(Fn(0x08000000, "arm", 0x08000004, "entry"), "GLOBAL")],
                rom_size=256,
            )
            side = td / "game.evidence.jsonl"
            labels = td / "game.labels.toml"
            evidence.save(side, sha, recs)
            self.assertTrue(side.exists())
            self.assertFalse(labels.exists())
            _, loaded = evidence.load(side, sha)
            self.assertEqual(loaded[(0x08000000, "arm")].status, evidence.UNRESOLVED)

    def test_existing_labels_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rom = td / "game.gba"
            rom.write_bytes(bytes(256))
            sha = labels_toml.rom_sha256(rom)
            labels = td / "game.labels.toml"
            original = {(0x08000100, "thumb"): Fn(0x08000100, "thumb", 0x08000110, "keep")}
            labels_toml.save(labels, sha, original)
            before = labels.read_text()
            recs, _ = seed_from_decomp.candidates_from_harvest(
                [(Fn(0x08000000, "arm", 0x08000004, "entry"), "GLOBAL")],
                rom_size=256,
            )
            evidence.save(td / "game.evidence.jsonl", sha, recs)
            self.assertEqual(labels.read_text(), before)
            _, fns = labels_toml.load(labels)
            self.assertEqual(set(fns), set(original))

    def test_cli_refuses_labels_toml_out(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            rom = td / "game.gba"
            rom.write_bytes(bytes(256))
            proc = subprocess.run(
                [
                    sys.executable, str(TOOLS / "seed_from_decomp.py"),
                    "--elf", str(td / "missing.elf"),
                    "--rom", str(rom),
                    "--out", str(td / "game.labels.toml"),
                ],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 1)
            self.assertIn("refusing to write labels.toml", proc.stderr)
            self.assertFalse((td / "game.labels.toml").exists())


if __name__ == "__main__":
    unittest.main()
