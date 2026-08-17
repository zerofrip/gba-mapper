"""EvidenceMerger: provenance union, not verification."""
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

import evidence  # noqa: E402
import evidence_merge  # noqa: E402
import frontier  # noqa: E402

MERGER = TOOLS / "evidence_merge.py"
ADDR = 0x08001200


def ev_bl(*, src=0x08001000):
    return evidence.Evidence(
        "bl-target", "modeflow", "bl",
        from_addr=src, target_addr=ADDR,
        source_mode="thumb", target_mode="thumb", insn="bl",
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


def cand_row(addr, mode, items):
    store = frontier.FrontierStore()
    store.add_candidate(addr, mode, items)
    return store.to_json_list()[0]


def find(result, addr=ADDR, mode="thumb"):
    for c in result["candidates"]:
        if int(c["address"], 16) == addr and c["mode"] == mode:
            return c
    return None


class MergeSources(unittest.TestCase):
    def test_modeflow_plus_ghidra_same_key(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", ev_bl())
        m.add(ADDR, "thumb", ev_ghidra())
        rows = m.to_json()["candidates"]
        self.assertEqual(len(rows), 1)
        types = [e["type"] for e in rows[0]["evidence_items"]]
        self.assertEqual(types, ["bl-target", "ghidra-seed"])
        self.assertEqual(m.sources(ADDR, "thumb"), ["modeflow", "ghidra"])
        self.assertTrue(rows[0]["deterministic"])

    def test_ghidra_plus_manual_seed(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", ev_ghidra())
        m.add(ADDR, "thumb", ev_manual())
        types = [e["type"] for e in m.to_json()["candidates"][0]["evidence_items"]]
        self.assertEqual(types, ["ghidra-seed", "manual-seed"])
        self.assertFalse(m.to_json()["candidates"][0]["deterministic"])

    def test_identical_evidence_deduped(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", ev_ghidra())
        m.add(ADDR, "thumb", ev_ghidra())
        self.assertEqual(len(m.to_json()["candidates"][0]["evidence_items"]), 1)

    def test_distinct_evidence_kept(self):
        m = evidence_merge.EvidenceMerger()
        a = evidence.Evidence("ghidra-seed", "ghidra", "ghidra function: Foo",
                              target_addr=ADDR, target_mode="thumb")
        b = evidence.Evidence("ghidra-seed", "ghidra", "ghidra function: Bar",
                              target_addr=ADDR, target_mode="thumb")
        m.add(ADDR, "thumb", a)
        m.add(ADDR, "thumb", b)
        details = [e["detail"] for e in m.to_json()["candidates"][0]["evidence_items"]]
        self.assertEqual(details, ["ghidra function: Foo", "ghidra function: Bar"])

    def test_evidence_order_is_deterministic(self):
        def run():
            m = evidence_merge.EvidenceMerger()
            m.merge_frontier({"candidates": [
                cand_row(ADDR, "thumb", ev_ghidra()),
                cand_row(ADDR, "thumb", ev_bl()),
            ]})
            return [e["type"] for e in m.to_json()["candidates"][0]["evidence_items"]]

        self.assertEqual(run(), run())
        self.assertEqual(run(), ["ghidra-seed", "bl-target"])

    def test_empty_evidence_does_not_mint(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", [])
        m.add(ADDR, "thumb", None)
        m.merge_candidate({"address": hex(ADDR), "mode": "thumb"})
        m.merge_candidate({"address": hex(ADDR), "mode": "thumb", "evidence_items": []})
        self.assertEqual(m.to_json()["candidates"], [])


class ArmThumb(unittest.TestCase):
    def test_same_address_arm_thumb_are_two_candidates(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "arm", ev_ghidra(mode="arm"))
        m.add(ADDR, "thumb", ev_ghidra())
        keys = {(int(c["address"], 16), c["mode"]) for c in m.to_json()["candidates"]}
        self.assertEqual(keys, {(ADDR, "arm"), (ADDR, "thumb")})

    def test_arm_thumb_conflict_keeps_both(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "arm", ev_ghidra(mode="arm"))
        m.add(ADDR, "thumb", ev_bl())
        rows = m.to_json()["candidates"]
        self.assertEqual(len(rows), 2)
        for c in rows:
            self.assertTrue(c["conflicts"])
            self.assertIn("arm and thumb", c["conflicts"][0])

    def test_ghidra_arm_modeflow_thumb_no_winner(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "arm", ev_ghidra(mode="arm"))
        m.add(ADDR, "thumb", ev_bl())
        result = m.to_json()
        self.assertIsNotNone(find(result, mode="arm"))
        self.assertIsNotNone(find(result, mode="thumb"))
        self.assertNotIn("winner", result)
        self.assertNotIn("accepted", result)
        for c in result["candidates"]:
            self.assertNotIn("winner", c)
            self.assertNotIn("confidence", c)
            self.assertNotIn("score", c)
            self.assertNotIn("verified", c)
            self.assertNotIn("accepted", c)
            self.assertNotIn("trusted", c)


class VerificationBoundary(unittest.TestCase):
    def test_no_status_range_or_encoding_fields(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", ev_ghidra())
        result = m.to_json()
        row = find(result)
        for obj in (result, row):
            self.assertNotIn("status", obj)
            self.assertNotIn("range_verified", obj)
            self.assertNotIn("encoding_verified", obj)

    def test_does_not_call_promote_encoding_verified(self):
        src = inspect.getsource(evidence_merge)
        self.assertNotIn("promote_encoding_verified", src)

    def test_ghidra_seed_stays_unverified(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", ev_ghidra())
        row = find(m.to_json())
        item = row["evidence_items"][0]
        self.assertEqual(item["type"], "ghidra-seed")
        self.assertEqual(item["source"], "ghidra")
        self.assertFalse(row["deterministic"])

    def test_gap_provenance_preserved(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", evidence.Evidence(
            "gap", "gap", "inherited thumb", target_addr=ADDR, target_mode="thumb",
        ))
        item = find(m.to_json())["evidence_items"][0]
        self.assertEqual(item["type"], "gap")
        self.assertEqual(item["source"], "gap")
        self.assertFalse(find(m.to_json())["deterministic"])

    def test_vector_entry_provenance_preserved(self):
        m = evidence_merge.EvidenceMerger()
        m.add(0x080001C0, "arm", evidence.Evidence(
            "vector-entry", "modeflow", "b",
            from_addr=0x08000000, target_addr=0x080001C0,
            source_mode="arm", target_mode="arm", insn="b",
        ))
        row = find(m.to_json(), addr=0x080001C0, mode="arm")
        self.assertEqual(row["evidence_items"][0]["type"], "vector-entry")
        self.assertTrue(row["deterministic"])


class UnresolvedAndMap(unittest.TestCase):
    def test_unresolved_is_not_a_candidate(self):
        m = evidence_merge.EvidenceMerger()
        m.merge_frontier({
            "candidates": [],
            "unresolved": [{
                "type": "indirect-branch",
                "source": "modeflow",
                "detail": "bx r3",
                "from_addr": "0x08001000",
                "source_mode": "thumb",
            }],
        })
        result = m.to_json()
        self.assertEqual(result["candidates"], [])
        self.assertEqual(len(result["unresolved"]), 1)
        self.assertEqual(result["unresolved"][0]["type"], "indirect-branch")

    def test_existing_map_does_not_mint(self):
        m = evidence_merge.EvidenceMerger()
        m.merge_candidate({
            "address": "0x08001200",
            "mode": "thumb",
            "end": "0x08001240",
            "name": "AlreadyMapped",
        })
        m.merge_frontier({
            "candidates": [{
                "address": "0x08001300",
                "mode": "arm",
                "source": "existing-map",
            }],
        })
        self.assertEqual(m.to_json()["candidates"], [])


class Serialization(unittest.TestCase):
    def test_roundtrip_preserves_evidence_items(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", [ev_bl(), ev_ghidra()])
        blob = json.dumps(m.to_json())
        again = evidence_merge.EvidenceMerger()
        again.merge_frontier(json.loads(blob))
        a = m.to_json()["candidates"][0]["evidence_items"]
        b = again.to_json()["candidates"][0]["evidence_items"]
        self.assertEqual(a, b)
        self.assertEqual(len(a), 2)

    def test_evidence_string_and_items_kept(self):
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", [ev_bl(), ev_ghidra()])
        row = find(m.to_json())
        self.assertIn("evidence", row)
        self.assertIn("evidence_items", row)
        self.assertEqual(row["evidence"], "bl-target, ghidra-seed")
        self.assertEqual(len(row["evidence_items"]), 2)

    def test_phase1_jsonl_without_optional_fields_loads(self):
        old = {
            "address": "0x080001c8", "mode": "thumb",
            "status": "unresolved",
            "evidence": [{"type": "peel-incbin", "source": "peel", "detail": "range"}],
            "conflicts": [],
        }
        rec = evidence.Record.from_json(old)
        self.assertEqual(rec.address, 0x080001C8)
        self.assertIsNone(rec.evidence[0].target_addr)
        m = evidence_merge.EvidenceMerger()
        m.add(ADDR, "thumb", ev_ghidra())
        self.assertNotIn("status", m.to_json())

    def test_phase234_frontier_json_keys(self):
        m = evidence_merge.EvidenceMerger()
        m.merge_frontier({"candidates": [cand_row(ADDR, "thumb", ev_bl())]})
        row = find(m.to_json())
        for key in (
            "address", "mode", "evidence", "evidence_items",
            "conflicts", "deterministic",
        ):
            self.assertIn(key, row)


class DoesNotWriteArtifacts(unittest.TestCase):
    def test_cli_does_not_write_labels_or_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "a.json"
            out = td / "merged.json"
            src.write_text(json.dumps({
                "candidates": [cand_row(ADDR, "thumb", ev_ghidra())],
                "unresolved": [],
            }))
            subprocess.run(
                [sys.executable, str(MERGER), str(src), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertTrue(out.is_file())
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.labels.toml")), [])
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            result = json.loads(out.read_text())
            self.assertEqual(result["candidates"][0]["evidence_items"][0]["type"], "ghidra-seed")

    def test_cli_stdout_and_multi_input(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            a = td / "modeflow.json"
            b = td / "ghidra.json"
            a.write_text(json.dumps({
                "candidates": [cand_row(ADDR, "thumb", ev_bl())],
                "unresolved": [],
            }))
            b.write_text(json.dumps({
                "candidates": [cand_row(ADDR, "thumb", ev_ghidra())],
                "unresolved": [],
            }))
            proc = subprocess.run(
                [sys.executable, str(MERGER), str(a), str(b)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            types = [e["type"] for e in result["candidates"][0]["evidence_items"]]
            self.assertEqual(types, ["bl-target", "ghidra-seed"])
            self.assertFalse((td / "labels.toml").exists())


if __name__ == "__main__":
    unittest.main()
