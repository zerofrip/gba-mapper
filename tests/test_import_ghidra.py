"""Ghidra JSON/JSONL importer: unverified ghidra-seed only."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import evidence  # noqa: E402
import frontier  # noqa: E402
import import_ghidra  # noqa: E402

IMPORTER = TOOLS / "import_ghidra.py"
ADDR = 0x08000100


def rec(**kwargs):
    raw = {"address": "0x08000100", "mode": "thumb"}
    raw.update(kwargs)
    return raw


def cand(result: dict, addr: int = ADDR, mode: str = "thumb") -> dict | None:
    for c in result["candidates"]:
        if int(c["address"], 16) == addr and c["mode"] == mode:
            return c
    return None


class ParseAddr(unittest.TestCase):
    def test_int_address(self):
        self.assertEqual(import_ghidra.parse_addr(0x08000100), 0x08000100)

    def test_hex_string_address(self):
        self.assertEqual(import_ghidra.parse_addr("0x08000100"), 0x08000100)
        self.assertEqual(import_ghidra.parse_addr("08000100"), 0x08000100)

    def test_invalid_address_values(self):
        for bad in (True, False, None, "", "not-an-addr", -1, "-1", 1.5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    import_ghidra.parse_addr(bad)


class NormalizeRom(unittest.TestCase):
    def test_short_rom_offset(self):
        self.assertEqual(import_ghidra.normalize_rom_addr(0x100), 0x08000100)

    def test_already_normalized(self):
        self.assertEqual(import_ghidra.normalize_rom_addr(0x08000100), 0x08000100)

    def test_invalid_address_window(self):
        for bad in (0x02000000, 0x0A000000, 0x0E000000, -1):
            with self.subTest(bad=hex(bad) if isinstance(bad, int) and bad >= 0 else bad):
                with self.assertRaises(ValueError):
                    import_ghidra.normalize_rom_addr(bad)

    def test_does_not_infer_mode_from_alignment(self):
        self.assertEqual(import_ghidra.normalize_rom_addr(0x08000101), 0x08000101)


class ParseRecord(unittest.TestCase):
    def test_valid_arm(self):
        ok, got = import_ghidra.parse_ghidra_record(
            {"address": "0x08000100", "mode": "arm"}
        )
        self.assertTrue(ok)
        self.assertEqual(got.address, ADDR)
        self.assertEqual(got.mode, "arm")

    def test_valid_thumb(self):
        ok, got = import_ghidra.parse_ghidra_record(rec())
        self.assertTrue(ok)
        self.assertEqual(got.mode, "thumb")

    def test_invalid_mode(self):
        ok, rej = import_ghidra.parse_ghidra_record(rec(mode="thumb2"))
        self.assertFalse(ok)
        self.assertIn("mode", rej["reason"])

    def test_invalid_address(self):
        ok, rej = import_ghidra.parse_ghidra_record(rec(address="nope"))
        self.assertFalse(ok)
        self.assertEqual(rej["reason"], "invalid address")

    def test_invalid_end(self):
        ok, rej = import_ghidra.parse_ghidra_record(
            rec(end="0x08000080")
        )
        self.assertFalse(ok)
        self.assertEqual(rej["reason"], "invalid end")

    def test_invalid_size(self):
        for size in (0, -4, True, "16"):
            with self.subTest(size=size):
                ok, rej = import_ghidra.parse_ghidra_record(rec(size=size))
                self.assertFalse(ok)
                self.assertEqual(rej["reason"], "invalid size")


class JsonParsers(unittest.TestCase):
    def test_json_array(self):
        text = json.dumps([
            {"address": "0x08000100", "mode": "arm"},
            {"address": "0x08000200", "mode": "thumb"},
        ])
        accepted, rejected = import_ghidra.parse_ghidra_json(text)
        self.assertEqual(len(accepted), 2)
        self.assertEqual(rejected, [])

    def test_json_single_object(self):
        text = json.dumps({"address": 0x08000100, "mode": "thumb"})
        accepted, rejected = import_ghidra.parse_ghidra_json(text)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(accepted[0].address, ADDR)
        self.assertEqual(rejected, [])

    def test_jsonl(self):
        text = (
            '{"address":"0x08000100","mode":"arm"}\n'
            "\n"
            '{"address":"0x100","mode":"thumb"}\n'
        )
        accepted, rejected = import_ghidra.parse_ghidra_jsonl(text)
        self.assertEqual(len(accepted), 2)
        self.assertEqual(rejected, [])
        self.assertEqual(accepted[1].address, ADDR)

    def test_malformed_json(self):
        blob = '[{"address":"0x08000100","mode":"arm"'
        accepted, rejected = import_ghidra.parse_ghidra_json(blob)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected[0]["reason"], "malformed JSON")
        result = import_ghidra.import_ghidra_text(blob)
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["rejected"][0]["reason"], "malformed JSON")

    def test_malformed_jsonl(self):
        text = '{"address":"0x08000100","mode":"arm"}\n{not json\n'
        accepted, rejected = import_ghidra.parse_ghidra_jsonl(text)
        self.assertEqual(accepted, [])
        self.assertEqual(rejected[0]["reason"], "malformed JSONL")
        result = import_ghidra.import_ghidra_text(text)
        self.assertEqual(result["candidates"], [])


class EvidenceGeneration(unittest.TestCase):
    def test_ghidra_seed_evidence(self):
        ok, record = import_ghidra.parse_ghidra_record(rec())
        self.assertTrue(ok)
        ev = import_ghidra.ghidra_record_to_evidence(record)
        self.assertEqual(ev.type, "ghidra-seed")
        self.assertEqual(ev.source, "ghidra")
        self.assertEqual(ev.target_addr, ADDR)
        self.assertEqual(ev.target_mode, "thumb")

    def test_name_size_end_in_detail(self):
        ok, record = import_ghidra.parse_ghidra_record(rec(
            name="FUN_08000100", size=32, end="0x08000120",
        ))
        self.assertTrue(ok)
        ev = import_ghidra.ghidra_record_to_evidence(record)
        self.assertIn("ghidra function: FUN_08000100", ev.detail)
        self.assertIn("ghidra_size=32", ev.detail)
        self.assertIn("ghidra_end=0x8000120", ev.detail)

    def test_detail_omits_missing_fields(self):
        ev = import_ghidra.ghidra_record_to_evidence(
            import_ghidra.GhidraRecord(ADDR, "thumb")
        )
        self.assertEqual(ev.detail, "ghidra function")
        self.assertNotIn("ghidra_size", ev.detail)
        self.assertNotIn("ghidra_end", ev.detail)

    def test_confidence_does_not_affect_scoring(self):
        a = rec(name="f", confidence=0.99)
        b = rec(name="f", confidence=0.01)
        store = frontier.FrontierStore()
        for raw in (a, b):
            ok, record = import_ghidra.parse_ghidra_record(raw)
            self.assertTrue(ok)
            import_ghidra.ingest_ghidra(store, [record])
        rows = store.to_json_list()
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["evidence_items"]), 1)
        self.assertFalse(rows[0]["deterministic"])
        self.assertNotIn("confidence", rows[0]["evidence_items"][0]["detail"])


class IngestAndMerge(unittest.TestCase):
    def test_existing_bl_plus_ghidra_merge(self):
        store = frontier.FrontierStore()
        store.add_candidate(
            ADDR, "thumb",
            evidence.Evidence(
                "bl-target", "modeflow", "bl",
                from_addr=0x08000080, target_addr=ADDR,
                source_mode="thumb", target_mode="thumb", insn="bl",
            ),
        )
        ok, record = import_ghidra.parse_ghidra_record(rec())
        self.assertTrue(ok)
        import_ghidra.ingest_ghidra(store, [record])
        rows = store.to_json_list()
        self.assertEqual(len(rows), 1)
        types = [e["type"] for e in rows[0]["evidence_items"]]
        self.assertEqual(types, ["bl-target", "ghidra-seed"])
        self.assertTrue(rows[0]["deterministic"])

    def test_same_address_arm_thumb_conflict(self):
        result = import_ghidra.import_ghidra_text(json.dumps([
            {"address": "0x08000100", "mode": "arm"},
            {"address": "0x08000100", "mode": "thumb"},
        ]))
        self.assertEqual(len(result["candidates"]), 2)
        for c in result["candidates"]:
            self.assertTrue(c["conflicts"])
            self.assertIn("arm and thumb", c["conflicts"][0])

    def test_invalid_record_rejected_not_unresolved(self):
        result = import_ghidra.import_ghidra_text(json.dumps([
            rec(),
            rec(mode="banana"),
        ]))
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["unresolved"], [])
        self.assertEqual(len(result["rejected"]), 1)
        self.assertIn("reason", result["rejected"][0])
        self.assertIn("raw", result["rejected"][0])
        self.assertIsNone(cand(result, mode="banana"))

    def test_ghidra_only_deterministic_false(self):
        result = import_ghidra.import_ghidra_text(json.dumps(rec()))
        row = cand(result)
        self.assertIsNotNone(row)
        self.assertFalse(row["deterministic"])

    def test_no_verification_status_fields(self):
        result = import_ghidra.import_ghidra_text(json.dumps(rec()))
        row = cand(result)
        self.assertNotIn("status", row)
        self.assertNotIn("range_verified", row)
        self.assertNotIn("encoding_verified", row)
        self.assertNotIn("status", result)
        self.assertNotIn("range_verified", result)
        self.assertNotIn("encoding_verified", result)

    def test_frontier_json_keys(self):
        result = import_ghidra.import_ghidra_text(json.dumps(rec()))
        self.assertIn("candidates", result)
        self.assertIn("unresolved", result)
        self.assertIn("rejected", result)
        row = cand(result)
        self.assertIn("evidence", row)
        self.assertIn("evidence_items", row)
        self.assertEqual(row["evidence"], "ghidra-seed")
        self.assertEqual(row["evidence_items"][0]["type"], "ghidra-seed")

    def test_duplicate_ghidra_evidence_deduped(self):
        result = import_ghidra.import_ghidra_text(json.dumps([rec(), rec()]))
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(len(result["candidates"][0]["evidence_items"]), 1)

    def test_mixed_valid_and_rejected(self):
        result = import_ghidra.import_ghidra_text(json.dumps([
            rec(mode="arm"),
            rec(address="bogus", mode="thumb"),
            rec(address="0x08000200", mode="thumb", size=0),
        ]))
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(len(result["rejected"]), 2)
        self.assertEqual(result["unresolved"], [])


class Phase1Compat(unittest.TestCase):
    def test_phase1_jsonl_without_optional_fields_loads(self):
        old = {
            "address": "0x080001c8", "mode": "thumb",
            "status": "unresolved",
            "evidence": [{"type": "peel-incbin", "source": "peel", "detail": "range"}],
            "conflicts": [],
        }
        rec_old = evidence.Record.from_json(old)
        self.assertEqual(rec_old.address, 0x080001C8)
        self.assertIsNone(rec_old.evidence[0].target_addr)
        self.assertIsNone(rec_old.evidence[0].source_mode)
        self.assertIsNone(rec_old.evidence[0].insn)
        result = import_ghidra.import_ghidra_text(json.dumps(rec()))
        self.assertEqual(result["candidates"][0]["evidence_items"][0]["type"], "ghidra-seed")


class DoesNotWriteLabels(unittest.TestCase):
    def test_labels_toml_not_created(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "ghidra.json"
            out = td / "frontier.json"
            src.write_text(json.dumps(rec()))
            subprocess.run(
                [sys.executable, str(IMPORTER), str(src), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertTrue(out.is_file())
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            self.assertEqual(list(td.glob("*.labels.toml")), [])


class Cli(unittest.TestCase):
    def test_cli_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(rec(mode="arm")))
            proc = subprocess.run(
                [sys.executable, str(IMPORTER), str(src)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(len(result["candidates"]), 1)
            self.assertEqual(result["candidates"][0]["mode"], "arm")
            self.assertFalse((td / "labels.toml").exists())

    def test_cli_output_file_and_input_flag(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.jsonl"
            src.write_text('{"address":"0x100","mode":"thumb"}\n')
            out = td / "out.json"
            proc = subprocess.run(
                [sys.executable, str(IMPORTER), "--input", str(src), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(proc.stdout, "")
            result = json.loads(out.read_text())
            self.assertEqual(int(result["candidates"][0]["address"], 16), ADDR)
            self.assertFalse(result["candidates"][0]["deterministic"])


if __name__ == "__main__":
    unittest.main()
