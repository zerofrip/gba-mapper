"""PeelSelector: peel-ready selection only, not peel or verification."""
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
import select_peel  # noqa: E402

CLI = TOOLS / "select_peel.py"
ADDR = 0x08001200


def ev_bl(*, src=0x08001000, mode="thumb", addr=ADDR):
    return evidence.Evidence(
        "bl-target", "modeflow", "bl",
        from_addr=src, target_addr=addr,
        source_mode=mode, target_mode=mode, insn="bl",
    )


def ev_ghidra(*, mode="thumb", addr=ADDR):
    return evidence.Evidence(
        "ghidra-seed", "ghidra", "ghidra function",
        target_addr=addr, target_mode=mode,
    )


def ev_manual():
    return evidence.Evidence(
        "manual-seed", "manual-seed", "hand",
        target_addr=ADDR, target_mode="thumb",
    )


def ev_gap():
    return evidence.Evidence(
        "gap", "gap", "inherited thumb",
        target_addr=ADDR, target_mode="thumb",
    )


def find(rows, addr=ADDR, mode="thumb"):
    for c in rows:
        if int(c["address"], 16) == addr and c["mode"] == mode:
            return c
    return None


def run_select(*adds, limit=None):
    sel = select_peel.PeelSelector(limit=limit)
    for args in adds:
        sel.add(*args)
    return sel.select()


class Policy(unittest.TestCase):
    def test_peel_ready_selected(self):
        result = run_select((ADDR, "thumb", ev_bl()))
        self.assertEqual(len(result["selected"]), 1)
        row = result["selected"][0]
        self.assertEqual(row["disposition"], "peel-ready")
        self.assertEqual(row["selection"], "selected")
        self.assertNotIn("skip_reason", row)
        self.assertTrue(row["deterministic"])

    def test_agreed_seed_skipped(self):
        result = run_select((ADDR, "thumb", [ev_ghidra(), ev_manual()]))
        self.assertEqual(result["selected"], [])
        row = find(result["skipped"])
        self.assertEqual(row["disposition"], "agreed-seed")
        self.assertEqual(row["selection"], "skipped")
        self.assertEqual(row["skip_reason"], "no control-flow")

    def test_heuristic_ghidra_and_gap_skipped(self):
        g = run_select((ADDR, "thumb", ev_ghidra()))
        grow = find(g["skipped"])
        self.assertEqual(grow["disposition"], "heuristic")
        self.assertEqual(grow["skip_reason"], "heuristic/oracle only")
        self.assertEqual(g["selected"], [])
        gp = run_select((ADDR, "thumb", ev_gap()))
        prow = find(gp["skipped"])
        self.assertEqual(prow["disposition"], "heuristic")
        self.assertEqual(prow["skip_reason"], "heuristic/oracle only")

    def test_conflicted_both_skipped_no_winner(self):
        result = run_select(
            (ADDR, "thumb", ev_bl()),
            (ADDR, "arm", ev_ghidra(mode="arm")),
        )
        self.assertEqual(result["selected"], [])
        self.assertEqual(len(result["skipped"]), 2)
        for c in result["skipped"]:
            self.assertEqual(c["disposition"], "conflicted")
            self.assertEqual(c["skip_reason"], "dual-mode conflict")
            self.assertNotIn("winner", c)
        self.assertIsNotNone(find(result["skipped"], mode="arm"))
        self.assertIsNotNone(find(result["skipped"], mode="thumb"))

    def test_candidate_key_not_address_only(self):
        result = run_select(
            (ADDR, "arm", ev_ghidra(mode="arm")),
            (ADDR, "thumb", ev_ghidra()),
        )
        keys = {(int(c["address"], 16), c["mode"]) for c in result["skipped"]}
        self.assertEqual(keys, {(ADDR, "arm"), (ADDR, "thumb")})


class Invariants(unittest.TestCase):
    def test_deterministic_preserved(self):
        ready = run_select((ADDR, "thumb", ev_bl()))
        self.assertTrue(find(ready["selected"])["deterministic"])
        heur = run_select((ADDR, "thumb", ev_ghidra()))
        self.assertFalse(find(heur["skipped"])["deterministic"])

    def test_no_verification_fields(self):
        result = run_select((ADDR, "thumb", ev_bl()))
        row = result["selected"][0]
        for obj in (result, row):
            self.assertNotIn("status", obj)
            self.assertNotIn("range_verified", obj)
            self.assertNotIn("encoding_verified", obj)
            self.assertNotIn("winner", obj)
            self.assertNotIn("confidence", obj)
            self.assertNotIn("score", obj)

    def test_evidence_items_preserved(self):
        result = run_select((ADDR, "thumb", [ev_bl(), ev_ghidra()]))
        types = [e["type"] for e in result["selected"][0]["evidence_items"]]
        self.assertEqual(types, ["bl-target", "ghidra-seed"])

    def test_unresolved_passthrough(self):
        sel = select_peel.PeelSelector()
        sel.ingest({
            "candidates": [],
            "unresolved": [{
                "type": "indirect-branch",
                "source": "modeflow",
                "detail": "bx r3",
                "from_addr": "0x08001000",
                "source_mode": "thumb",
            }],
        })
        result = sel.select()
        self.assertEqual(result["selected"], [])
        self.assertEqual(len(result["unresolved"]), 1)
        self.assertNotIn("selection", result["unresolved"][0])
        self.assertNotIn("skip_reason", result["unresolved"][0])

    def test_empty_provenance_not_minted(self):
        sel = select_peel.PeelSelector()
        sel.add(ADDR, "thumb", [])
        sel.ingest({"candidates": [{"address": hex(ADDR), "mode": "thumb"}]})
        result = sel.select()
        self.assertEqual(result["selected"], [])
        self.assertEqual(result["skipped"], [])

    def test_peel_ready_before_others(self):
        result = run_select(
            (0x08001400, "thumb", ev_gap()),
            (ADDR, "thumb", ev_bl()),
            (0x08001300, "thumb", [ev_ghidra(addr=0x08001300), ev_manual()]),
        )
        self.assertEqual(result["selected"][0]["disposition"], "peel-ready")
        skipped_disp = [c["disposition"] for c in result["skipped"]]
        self.assertEqual(skipped_disp, ["agreed-seed", "heuristic"])

    def test_limit_caps_selected_only(self):
        result = run_select(
            (0x08001000, "thumb", ev_bl(addr=0x08001000)),
            (0x08001200, "thumb", ev_bl()),
            (0x08001400, "thumb", ev_bl(addr=0x08001400)),
            (0x08001600, "thumb", ev_gap()),
            limit=2,
        )
        self.assertEqual(len(result["selected"]), 2)
        self.assertEqual(
            [int(c["address"], 16) for c in result["selected"]],
            [0x08001000, 0x08001200],
        )
        capped = find(result["skipped"], addr=0x08001400)
        self.assertEqual(capped["skip_reason"], "selection-cap")
        self.assertEqual(capped["disposition"], "peel-ready")
        heur = find(result["skipped"], addr=0x08001600)
        self.assertEqual(heur["skip_reason"], "heuristic/oracle only")

    def test_no_end_invention(self):
        result = run_select((ADDR, "thumb", ev_bl()))
        row = result["selected"][0]
        self.assertNotIn("end", row)
        self.assertNotIn("size", row)
        self.assertNotIn("recommendedEnd", row)


class MergeAndCli(unittest.TestCase):
    def test_multi_input_union_and_dedupe(self):
        sel = select_peel.PeelSelector()
        sel.ingest({"candidates": [{
            "address": hex(ADDR), "mode": "thumb",
            "evidence_items": [ev_bl().to_json()],
        }]})
        sel.ingest({"candidates": [{
            "address": hex(ADDR), "mode": "thumb",
            "evidence_items": [ev_bl().to_json(), ev_ghidra().to_json()],
        }]})
        result = sel.select()
        types = [e["type"] for e in result["selected"][0]["evidence_items"]]
        self.assertEqual(types, ["bl-target", "ghidra-seed"])

    def test_cli_no_side_effects_and_stdout(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps({
                "candidates": [{
                    "address": hex(ADDR), "mode": "thumb",
                    "evidence_items": [ev_bl().to_json()],
                }],
                "unresolved": [],
            }))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["selected"][0]["selection"], "selected")
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            self.assertFalse((td / "asm").exists())
            self.assertEqual(list(td.glob("gamedb*")), [])

    def test_cli_output_and_limit(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            out = td / "sel.json"
            src.write_text(json.dumps({
                "candidates": [
                    {"address": "0x08001000", "mode": "thumb",
                     "evidence_items": [ev_bl(addr=0x08001000).to_json()]},
                    {"address": "0x08001200", "mode": "thumb",
                     "evidence_items": [ev_bl().to_json()]},
                ],
                "unresolved": [],
            }))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--limit", "1", "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(proc.stdout, "")
            result = json.loads(out.read_text())
            self.assertEqual(len(result["selected"]), 1)
            self.assertEqual(int(result["selected"][0]["address"], 16), 0x08001000)
            self.assertFalse((td / "labels.toml").exists())

    def test_negative_limit_rejected(self):
        with self.assertRaises(ValueError):
            select_peel.PeelSelector(limit=-1)


if __name__ == "__main__":
    unittest.main()
