"""Adjudicator: read-only disposition, not verification."""
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

import adjudicate  # noqa: E402
import evidence  # noqa: E402
import frontier  # noqa: E402

CLI = TOOLS / "adjudicate.py"
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


def ev_decomp():
    return evidence.Evidence(
        "decomp-reference", "seed_from_decomp", "elf FUNC Foo",
        target_addr=ADDR, target_mode="thumb",
    )


def ev_gap():
    return evidence.Evidence(
        "gap", "gap", "inherited thumb",
        target_addr=ADDR, target_mode="thumb",
    )


def find(result, addr=ADDR, mode="thumb"):
    for c in result["candidates"]:
        if int(c["address"], 16) == addr and c["mode"] == mode:
            return c
    return None


def frontier_row(addr, mode, items):
    store = frontier.FrontierStore()
    store.add_candidate(addr, mode, items)
    return store.to_json_list()[0]


class Dispositions(unittest.TestCase):
    def test_modeflow_only_peel_ready(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_bl())
        row = find(a.to_json())
        self.assertEqual(row["disposition"], "peel-ready")
        self.assertTrue(row["deterministic"])
        self.assertEqual(row["classes"], ["control-flow"])
        self.assertEqual(row["sources"], ["modeflow"])

    def test_ghidra_only_heuristic(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_ghidra())
        row = find(a.to_json())
        self.assertEqual(row["disposition"], "heuristic")
        self.assertFalse(row["deterministic"])
        self.assertEqual(row["classes"], ["oracle-seed"])
        self.assertEqual(row["sources"], ["ghidra"])

    def test_modeflow_plus_ghidra_same_key(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_bl())
        a.add(ADDR, "thumb", ev_ghidra())
        row = find(a.to_json())
        self.assertEqual(row["disposition"], "peel-ready")
        self.assertEqual(row["sources"], ["modeflow", "ghidra"])
        types = [e["type"] for e in row["evidence_items"]]
        self.assertEqual(types, ["bl-target", "ghidra-seed"])
        self.assertIn("control-flow", row["classes"])
        self.assertIn("oracle-seed", row["classes"])

    def test_modeflow_thumb_ghidra_arm_conflicted(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_bl())
        a.add(ADDR, "arm", ev_ghidra(mode="arm"))
        result = a.to_json()
        self.assertEqual(len(result["candidates"]), 2)
        for c in result["candidates"]:
            self.assertEqual(c["disposition"], "conflicted")
            self.assertNotIn("winner", c)
        self.assertIsNotNone(find(result, mode="arm"))
        self.assertIsNotNone(find(result, mode="thumb"))

    def test_gap_only_heuristic(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_gap())
        row = find(a.to_json())
        self.assertEqual(row["disposition"], "heuristic")
        self.assertFalse(row["deterministic"])
        self.assertEqual(row["classes"], ["heuristic"])

    def test_manual_seed_heuristic(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_manual())
        self.assertEqual(find(a.to_json())["disposition"], "heuristic")

    def test_decomp_reference_heuristic_oracle_seed(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_decomp())
        row = find(a.to_json())
        self.assertEqual(row["disposition"], "heuristic")
        self.assertEqual(row["classes"], ["oracle-seed"])
        self.assertEqual(row["evidence_items"][0]["type"], "decomp-reference")


class MergeAndKeys(unittest.TestCase):
    def test_same_key_keeps_all_evidence(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", [ev_ghidra(), ev_manual()])
        types = [e["type"] for e in find(a.to_json())["evidence_items"]]
        self.assertEqual(types, ["ghidra-seed", "manual-seed"])
        self.assertEqual(find(a.to_json())["disposition"], "agreed-seed")

    def test_duplicate_evidence_deduped(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_ghidra())
        a.add(ADDR, "thumb", ev_ghidra())
        self.assertEqual(len(find(a.to_json())["evidence_items"]), 1)

    def test_unresolved_not_a_candidate(self):
        a = adjudicate.Adjudicator()
        a.ingest({
            "candidates": [],
            "unresolved": [{
                "type": "indirect-branch",
                "source": "modeflow",
                "detail": "bx r3",
                "from_addr": "0x08001000",
                "source_mode": "thumb",
            }],
        })
        result = a.to_json()
        self.assertEqual(result["candidates"], [])
        self.assertEqual(len(result["unresolved"]), 1)
        self.assertNotIn("disposition", result["unresolved"][0])

    def test_empty_provenance_does_not_mint(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", [])
        a.add(ADDR, "thumb", None)
        a.ingest({"candidates": [{"address": hex(ADDR), "mode": "thumb"}]})
        self.assertEqual(a.to_json()["candidates"], [])

    def test_same_address_arm_thumb_remain_separate(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "arm", ev_ghidra(mode="arm"))
        a.add(ADDR, "thumb", ev_ghidra())
        keys = {(int(c["address"], 16), c["mode"]) for c in a.to_json()["candidates"]}
        self.assertEqual(keys, {(ADDR, "arm"), (ADDR, "thumb")})


class VerificationBoundary(unittest.TestCase):
    def test_no_status_range_or_encoding(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_ghidra())
        result = a.to_json()
        row = find(result)
        for obj in (result, row):
            self.assertNotIn("status", obj)
            self.assertNotIn("range_verified", obj)
            self.assertNotIn("encoding_verified", obj)
            self.assertNotIn("winner", obj)
            self.assertNotIn("confidence", obj)
            self.assertNotIn("score", obj)

    def test_deterministic_matches_frontier(self):
        store = frontier.FrontierStore()
        store.add_candidate(ADDR, "thumb", ev_bl())
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", ev_bl())
        self.assertEqual(
            store.to_json_list()[0]["deterministic"],
            find(a.to_json())["deterministic"],
        )
        store2 = frontier.FrontierStore()
        store2.add_candidate(ADDR, "thumb", ev_ghidra())
        b = adjudicate.Adjudicator()
        b.add(ADDR, "thumb", ev_ghidra())
        self.assertEqual(
            store2.to_json_list()[0]["deterministic"],
            find(b.to_json())["deterministic"],
        )
        self.assertFalse(find(b.to_json())["deterministic"])


class Serialization(unittest.TestCase):
    def test_roundtrip_keeps_evidence_items(self):
        a = adjudicate.Adjudicator()
        a.add(ADDR, "thumb", [ev_bl(), ev_ghidra()])
        blob = json.dumps(a.to_json())
        again = adjudicate.Adjudicator()
        again.ingest(json.loads(blob))
        self.assertEqual(
            a.to_json()["candidates"][0]["evidence_items"],
            again.to_json()["candidates"][0]["evidence_items"],
        )

    def test_phase1_and_frontier_keys(self):
        old = {
            "address": "0x080001c8", "mode": "thumb",
            "status": "unresolved",
            "evidence": [{"type": "peel-incbin", "source": "peel", "detail": "range"}],
            "conflicts": [],
        }
        rec = evidence.Record.from_json(old)
        self.assertEqual(rec.address, 0x080001C8)
        a = adjudicate.Adjudicator()
        a.ingest({"candidates": [frontier_row(ADDR, "thumb", ev_bl())]})
        row = find(a.to_json())
        for key in (
            "address", "mode", "evidence", "evidence_items",
            "conflicts", "deterministic", "disposition", "sources", "classes",
        ):
            self.assertIn(key, row)

    def test_output_order_is_stable(self):
        def run():
            a = adjudicate.Adjudicator()
            a.add(0x08001400, "thumb", ev_gap())
            a.add(ADDR, "thumb", ev_bl())
            a.add(0x08001300, "thumb", [ev_ghidra(addr=0x08001300), ev_manual()])
            a.add(0x08001100, "arm", ev_ghidra(mode="arm", addr=0x08001100))
            a.add(0x08001100, "thumb", ev_bl(addr=0x08001100))
            return [(c["disposition"], c["address"], c["mode"]) for c in a.to_json()["candidates"]]

        first = run()
        self.assertEqual(first, run())
        self.assertEqual(
            [d for d, _, _ in first],
            ["peel-ready", "agreed-seed", "heuristic", "conflicted", "conflicted"],
        )
        self.assertEqual(first[-2][2], "arm")
        self.assertEqual(first[-1][2], "thumb")


class Cli(unittest.TestCase):
    def test_cli_does_not_write_labels_or_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            out = td / "out.json"
            src.write_text(json.dumps({
                "candidates": [frontier_row(ADDR, "thumb", ev_ghidra())],
                "unresolved": [],
            }))
            subprocess.run(
                [sys.executable, str(CLI), str(src), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(out.read_text())
            self.assertEqual(find(result)["disposition"], "heuristic")
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])

    def test_cli_stdout_multi_input(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            a = td / "modeflow.json"
            b = td / "ghidra.json"
            a.write_text(json.dumps({
                "candidates": [frontier_row(ADDR, "thumb", ev_bl())],
                "unresolved": [],
            }))
            b.write_text(json.dumps({
                "candidates": [frontier_row(ADDR, "thumb", ev_ghidra())],
                "unresolved": [],
            }))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(a), str(b)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            row = find(result)
            self.assertEqual(row["disposition"], "peel-ready")
            self.assertEqual(row["sources"], ["modeflow", "ghidra"])
            self.assertFalse((td / "labels.toml").exists())


if __name__ == "__main__":
    unittest.main()
