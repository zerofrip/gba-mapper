"""Phase 8E ROM encoding verification: authoritative encoding_verified only here."""
from __future__ import annotations

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import encoding_decoder  # noqa: E402
import encoding_verify  # noqa: E402

CLI = TOOLS / "encoding_verify.py"
ROM_BASE = encoding_decoder.ROM_BASE
ROM_WINDOW_END = encoding_decoder.ROM_WINDOW_END
ADDR = ROM_BASE + 0x200
ADDR_HEX = f"0x{ADDR:08X}"
ARM_ADDR = ROM_BASE + 0x400
ARM_HEX = f"0x{ARM_ADDR:08X}"
SEL_ADDR = ROM_BASE + 0x100
SEL_HEX = f"0x{SEL_ADDR:08X}"
ROM_SIZE = 0x2000


def h16(x: int) -> bytes:
    return int(x).to_bytes(2, "little")


def w32(x: int) -> bytes:
    return int(x).to_bytes(4, "little")


def thumb_nop() -> bytes:
    return h16(0x46C0)


def arm_nop() -> bytes:
    return w32(0xE1A00000)


def build_rom(size: int, patches: dict[int, bytes]) -> bytes:
    rom = bytearray(size)
    for addr, blob in patches.items():
        off = addr - ROM_BASE
        rom[off:off + len(blob)] = blob
    return bytes(rom)


def skipped(*, addr=ADDR_HEX, mode="thumb", disposition="heuristic", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "selection": "skipped",
        "disposition": disposition,
        "deterministic": False,
        "sources": ["ghidra"],
        "classes": ["oracle-seed"],
    }
    if extra:
        row.update(extra)
    return row


def doc(*, selected=None, skipped=None, unresolved=None):
    return {
        "selected": list(selected or []),
        "skipped": list(skipped or []),
        "unresolved": list(unresolved or []),
    }


def selected_peel_ready():
    return {
        "address": SEL_HEX,
        "mode": "thumb",
        "selection": "selected",
        "disposition": "peel-ready",
        "deterministic": True,
        "sources": ["modeflow"],
        "classes": ["control-flow"],
    }


class Decoder(unittest.TestCase):
    def test_valid_thumb_and_arm(self):
        rom = build_rom(ROM_SIZE, {
            ADDR: thumb_nop(),
            ARM_ADDR: arm_nop(),
        })
        self.assertIsNone(encoding_decoder.verify_encoding(rom, ADDR, "thumb"))
        self.assertIsNone(encoding_decoder.verify_encoding(rom, ARM_ADDR, "arm"))

    def test_invalid_mode(self):
        rom = build_rom(ROM_SIZE, {ADDR: thumb_nop()})
        self.assertEqual(encoding_decoder.verify_encoding(rom, ADDR, "invalid"), "invalid-mode")

    def test_invalid_thumb_and_arm(self):
        rom = build_rom(ROM_SIZE, {
            ADDR: h16(0xE800),
            ARM_ADDR: w32(0xFA000000),
        })
        self.assertEqual(encoding_decoder.verify_encoding(rom, ADDR, "thumb"), "invalid-encoding")
        self.assertEqual(encoding_decoder.verify_encoding(rom, ARM_ADDR, "arm"), "invalid-encoding")

    def test_truncated_thumb_and_arm(self):
        rom = build_rom(ADDR - ROM_BASE + 1, {ADDR: thumb_nop()[:1]})
        self.assertEqual(encoding_decoder.verify_encoding(rom, ADDR, "thumb"), "truncated-instruction")
        rom2 = build_rom(ARM_ADDR - ROM_BASE + 2, {ARM_ADDR: arm_nop()[:2]})
        self.assertEqual(encoding_decoder.verify_encoding(rom2, ARM_ADDR, "arm"), "truncated-instruction")

    def test_address_boundaries(self):
        rom = build_rom(0x1000, {ROM_BASE: thumb_nop()})
        self.assertIsNone(encoding_decoder.verify_encoding(rom, ROM_BASE, "thumb"))
        self.assertEqual(encoding_decoder.verify_encoding(rom, ROM_BASE - 1, "thumb"), "invalid-address")
        last = ROM_WINDOW_END - 2
        rom2 = build_rom(last - ROM_BASE + 2, {last: thumb_nop()})
        self.assertIsNone(encoding_decoder.verify_encoding(rom2, last, "thumb"))
        self.assertEqual(encoding_decoder.verify_encoding(rom2, ROM_WINDOW_END, "thumb"), "invalid-address")

    def test_file_size_boundary(self):
        off = ADDR - ROM_BASE
        rom = build_rom(off + 1, {})
        self.assertEqual(encoding_decoder.verify_encoding(rom, ADDR, "thumb"), "truncated-instruction")
        rom2 = build_rom(off + 2, {ADDR: thumb_nop()})
        self.assertIsNone(encoding_decoder.verify_encoding(rom2, ADDR, "thumb"))


class CandidatePopulation(unittest.TestCase):
    def _rom(self):
        return build_rom(ROM_SIZE, {ADDR: thumb_nop(), ARM_ADDR: arm_nop(), SEL_ADDR: thumb_nop()})

    def test_selected_and_target_skipped_verified(self):
        out = encoding_verify.verify(doc(
            selected=[selected_peel_ready()],
            skipped=[skipped(), skipped(addr=ARM_HEX, mode="arm", disposition="conflicted")],
        ), self._rom())
        keys = {(r["address"], r["mode"]) for r in out["results"]}
        self.assertIn((SEL_HEX, "thumb"), keys)
        self.assertIn((ADDR_HEX, "thumb"), keys)
        self.assertIn((ARM_HEX, "arm"), keys)

    def test_non_target_skipped_ignored(self):
        out = encoding_verify.verify(doc(
            skipped=[skipped(disposition="peel-ready")],
        ), self._rom())
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"], [])

    def test_unresolved_no_verification(self):
        out = encoding_verify.verify(doc(
            unresolved=[{"type": "indirect-branch", "from_addr": "0x08000f00"}],
        ), self._rom())
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"], [])


class ArmThumbIndependent(unittest.TestCase):
    def test_same_address_independent(self):
        rom = build_rom(ROM_SIZE, {ADDR: thumb_nop(), ARM_ADDR: arm_nop()})
        out = encoding_verify.verify(doc(
            skipped=[
                skipped(addr=ARM_HEX, mode="arm", disposition="conflicted"),
                skipped(),
            ],
        ), rom)
        self.assertEqual(len(out["results"]), 2)
        modes = {r["mode"] for r in out["results"]}
        self.assertEqual(modes, {"arm", "thumb"})


    def test_input_encoding_verified_not_trusted(self):
        rom = build_rom(ROM_SIZE, {ADDR: h16(0xE800)})
        row = skipped(extra={"encoding_verified": True})
        out = encoding_verify.verify(doc(skipped=[row]), rom)
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"][0]["error"], "invalid-encoding")

    def test_no_winner_in_output(self):
        rom = build_rom(ROM_SIZE, {ADDR: thumb_nop()})
        out = encoding_verify.verify(doc(skipped=[skipped()]), rom)
        self.assertNotIn("winner", json.dumps(out))

    def test_llm_import_absent(self):
        src = inspect.getsource(encoding_verify)
        self.assertNotIn("llm_suggest", src)
        self.assertNotIn("llm_providers", src)


class MalformedCli(unittest.TestCase):
    def test_malformed_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bad = td / "bad.json"
            rom = td / "rom.bin"
            bad.write_text("{")
            rom.write_bytes(build_rom(ROM_SIZE, {ADDR: thumb_nop()}))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(bad), "--rom", str(rom)],
                cwd=td, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)


class TrustBoundary(unittest.TestCase):
    def test_8d_claim_cannot_verify_without_rom(self):
        claim_doc = {
            "format": "gba-mapper-encoding-claim",
            "version": 1,
            "claims": [{"address": ADDR_HEX, "mode": "thumb", "source": "human", "claim": "thumb"}],
        }
        out = encoding_verify.verify(doc(skipped=[skipped()]), None)
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"][0]["error"], "rom-unavailable")
        self.assertNotIn("encoding_verified", json.dumps(claim_doc))

    def test_invalid_encoding_no_verified(self):
        rom = build_rom(ROM_SIZE, {ADDR: h16(0xE800)})
        out = encoding_verify.verify(doc(skipped=[skipped()]), rom)
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"][0]["error"], "invalid-encoding")

    def test_output_schema(self):
        rom = build_rom(ROM_SIZE, {ADDR: thumb_nop()})
        out = encoding_verify.verify(doc(skipped=[skipped()]), rom)
        self.assertEqual(out["format"], "gba-mapper-encoding-verification")
        self.assertEqual(out["version"], 1)
        self.assertTrue(out["run"]["deterministic"])
        self.assertTrue(out["results"][0]["encoding_verified"])
        blob = json.dumps(out)
        for field in (
            "selection", "disposition", "winner", "end", "suggested_end",
            "range_verified", "eligible-for-peel",
        ):
            self.assertNotIn(field, blob)

    def test_disposition_immutable(self):
        row = skipped()
        src = doc(skipped=[row])
        before = json.dumps(src)
        rom = build_rom(ROM_SIZE, {ADDR: thumb_nop()})
        encoding_verify.verify(src, rom)
        self.assertEqual(json.dumps(src), before)


class RomFailure(unittest.TestCase):
    def test_missing_rom(self):
        out = encoding_verify.verify(doc(skipped=[skipped()]), None)
        self.assertEqual(out["errors"][0]["error"], "rom-unavailable")


class CliAndPersistence(unittest.TestCase):
    def test_cli_and_input_not_overwritten(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            rom = td / "rom.bin"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            rom.write_bytes(build_rom(ROM_SIZE, {ADDR: thumb_nop()}))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--rom", str(rom)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertTrue(result["run"]["deterministic"])
            self.assertFalse((td / "labels.toml").exists())
            original = json.loads(src.read_text())
            self.assertEqual(original["skipped"][0]["selection"], "skipped")
            out = td / "out.json"
            subprocess.run(
                [sys.executable, str(CLI), str(src), "--rom", str(rom), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(json.loads(src.read_text()), original)


class SecurityBoundary(unittest.TestCase):
    def test_no_rom_bytes_in_output(self):
        rom = build_rom(ROM_SIZE, {ADDR: thumb_nop()})
        out = encoding_verify.verify(doc(skipped=[skipped()]), rom)
        blob = json.dumps(out)
        self.assertNotIn(thumb_nop().hex(), blob)
        self.assertNotIn("deadbeef", blob)

    def test_production_code_boundaries(self):
        src = inspect.getsource(encoding_verify) + inspect.getsource(encoding_decoder)
        for token in (
            "run_peel", "run_check", "record_range", "promote_encoding",
            "wire", "llm_suggest", "llm_providers", "ends_approve",
            "frontier", "evidence", "subprocess", "urllib", "socket",
            "requests", "openai",
        ):
            self.assertNotIn(token, src)
        for token in ("import ghidra", "import modeflow"):
            self.assertNotIn(token, src)


if __name__ == "__main__":
    unittest.main()
