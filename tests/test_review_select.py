"""Review overlay: audit-only. Does not change 7A selection or verify."""
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

import review_select  # noqa: E402

CLI = TOOLS / "review_select.py"
ADDR = 0x08001200
ADDR_HEX = "0x08001200"


def skipped_row(*, addr=ADDR_HEX, mode="thumb", disposition="heuristic",
                skip_reason="heuristic/oracle only", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "selection": "skipped",
        "disposition": disposition,
        "skip_reason": skip_reason,
        "deterministic": False,
        "evidence_items": [{"type": "ghidra-seed", "source": "ghidra"}],
        "sources": ["ghidra"],
        "classes": ["oracle-seed"],
    }
    if extra:
        row.update(extra)
    return row


def selected_row(*, addr="0x08001000", mode="thumb"):
    return {
        "address": addr,
        "mode": mode,
        "selection": "selected",
        "disposition": "peel-ready",
        "deterministic": True,
        "evidence_items": [{"type": "bl-target", "source": "modeflow"}],
        "sources": ["modeflow"],
        "classes": ["control-flow"],
    }


def phase7a(*, selected=None, skipped=None, unresolved=None):
    return {
        "selected": list(selected or []),
        "skipped": list(skipped or []),
        "unresolved": list(unresolved or []),
    }


def review_file(decisions, **extra):
    doc = {"format": "gba-mapper-review", "version": 1, "decisions": decisions}
    doc.update(extra)
    return doc


def decision(addr=ADDR_HEX, mode="thumb", decision="select-for-peel", **kw):
    d = {"address": addr, "mode": mode, "decision": decision}
    d.update(kw)
    return d


class Overlay(unittest.TestCase):
    def test_queue_lists_skipped_and_unresolved(self):
        doc = phase7a(
            selected=[selected_row()],
            skipped=[skipped_row()],
            unresolved=[{"type": "indirect-branch", "from_addr": "0x08000f00"}],
        )
        out = review_select.review_select(doc)
        kinds = [q["kind"] for q in out["queue"]]
        self.assertEqual(kinds, ["skipped", "unresolved"])
        self.assertEqual(out["queue"][0]["address"], ADDR_HEX)
        self.assertEqual(out["queue"][1]["type"], "indirect-branch")

    def test_selected_unchanged(self):
        sel = selected_row()
        out = review_select.review_select(
            phase7a(selected=[sel], skipped=[skipped_row()]),
            review_file([decision()]),
        )
        self.assertEqual(len(out["selected"]), 1)
        self.assertEqual(out["selected"][0]["selection"], "selected")
        self.assertEqual(out["selected"][0]["disposition"], "peel-ready")
        self.assertNotIn("review_decision", out["selected"][0])

    def test_select_for_peel_records_only(self):
        skipped = skipped_row()
        original = json.loads(json.dumps(skipped))
        out = review_select.review_select(
            phase7a(skipped=[skipped]),
            review_file([decision(note="looks like code", reviewer="alice")]),
        )
        row = out["skipped"][0]
        self.assertEqual(row["review_decision"], "select-for-peel")
        self.assertEqual(row["review_note"], "looks like code")
        self.assertEqual(row["reviewer"], "alice")
        self.assertEqual(row["selection"], "skipped")
        self.assertEqual(row["disposition"], "heuristic")
        self.assertEqual(row["deterministic"], False)
        self.assertEqual(skipped, original)

    def test_allowed_decisions_round_trip(self):
        for dec in ("select-for-peel", "keep-skipped", "defer", "reject-as-data"):
            with self.subTest(dec=dec):
                out = review_select.review_select(
                    phase7a(skipped=[skipped_row()]),
                    review_file([decision(decision=dec)]),
                )
                self.assertEqual(out["skipped"][0]["review_decision"], dec)
                self.assertEqual(out["skipped"][0]["selection"], "skipped")

    def test_invalid_entries_ignored(self):
        cases = [
            [decision(addr="0x08001200")],  # address-only: missing mode replaced below
            [{"address": ADDR_HEX, "decision": "select-for-peel"}],
            [decision(addr="zz")],
            [decision(mode="both")],
            [decision(decision="peel-now")],
            [decision(end="0x08001240")],
            [decision(winner="thumb")],
            [decision(addr="0x08009999")],
        ]
        # first case is duplicate of second; keep explicit list
        for decisions in (
            [{"address": ADDR_HEX, "decision": "select-for-peel"}],
            [decision(addr="zz")],
            [decision(mode="both")],
            [decision(decision="peel-now")],
            [decision(end="0x08001240")],
            [decision(status="verified")],
            [decision(addr="0x08009999")],
        ):
            with self.subTest(decisions=decisions):
                out = review_select.review_select(
                    phase7a(skipped=[skipped_row()]),
                    review_file(decisions),
                )
                self.assertNotIn("review_decision", out["skipped"][0])
                self.assertEqual(out["skipped"][0]["selection"], "skipped")

    def test_duplicate_first_wins(self):
        out = review_select.review_select(
            phase7a(skipped=[skipped_row()]),
            review_file([
                decision(decision="defer"),
                decision(decision="select-for-peel"),
            ]),
        )
        self.assertEqual(out["skipped"][0]["review_decision"], "defer")

    def test_arm_thumb_independent_no_winner(self):
        doc = phase7a(skipped=[
            skipped_row(mode="arm", disposition="conflicted",
                        skip_reason="dual-mode conflict"),
            skipped_row(mode="thumb", disposition="conflicted",
                        skip_reason="dual-mode conflict"),
        ])
        out = review_select.review_select(
            doc,
            review_file([
                decision(mode="arm", decision="select-for-peel"),
                decision(mode="thumb", decision="select-for-peel"),
            ]),
        )
        self.assertEqual(len(out["skipped"]), 2)
        modes = {r["mode"]: r for r in out["skipped"]}
        self.assertEqual(modes["arm"]["review_decision"], "select-for-peel")
        self.assertEqual(modes["thumb"]["review_decision"], "select-for-peel")
        self.assertEqual(modes["arm"]["disposition"], "conflicted")
        self.assertEqual(modes["thumb"]["disposition"], "conflicted")
        blob = json.dumps(out)
        self.assertNotIn('"winner"', blob)

    def test_unresolved_not_promoted(self):
        un = {"type": "indirect-branch", "from_addr": "0x08000f00"}
        out = review_select.review_select(
            phase7a(unresolved=[un]),
            review_file([decision(decision="select-for-peel")]),
        )
        self.assertEqual(out["selected"], [])
        self.assertEqual(out["skipped"], [])
        self.assertEqual(len(out["unresolved"]), 1)
        self.assertEqual(out["unresolved"][0]["type"], "indirect-branch")
        self.assertNotIn("selection", out["unresolved"][0])
        self.assertNotIn("review_decision", out["unresolved"][0])

    def test_evidence_and_queue_stable(self):
        doc = phase7a(
            skipped=[
                skipped_row(addr="0x08001400"),
                skipped_row(addr="0x08001200"),
            ],
        )
        a = review_select.review_select(doc)
        b = review_select.review_select(doc)
        self.assertEqual(a, b)
        self.assertEqual(
            [q["address"] for q in a["queue"]],
            ["0x08001200", "0x08001400"],
        )
        items = a["skipped"][0]["evidence_items"]
        self.assertEqual(items, [{"type": "ghidra-seed", "source": "ghidra"}])


class Boundary(unittest.TestCase):
    def test_no_verification_end_or_imports(self):
        src = inspect.getsource(review_select)
        self.assertNotIn("record_range", src)
        self.assertNotIn("promote_encoding", src)
        self.assertNotIn("run_peel", src)
        self.assertNotIn("peel.py", src)
        self.assertNotIn("openai", src)
        self.assertNotIn("anthropic", src)
        out = review_select.review_select(
            phase7a(skipped=[skipped_row()]),
            review_file([decision()]),
        )
        blob = json.dumps(out)
        for k in ("status", "range_verified", "encoding_verified", "winner",
                  "confidence", "score", "end"):
            self.assertNotIn(f'"{k}"', blob)

    def test_cli_stdout_output_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            rev = td / "rev.json"
            src.write_text(json.dumps(phase7a(skipped=[skipped_row()])))
            rev.write_text(json.dumps(review_file([decision()])))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--review", str(rev)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["skipped"][0]["review_decision"], "select-for-peel")
            self.assertEqual(result["skipped"][0]["selection"], "skipped")
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            self.assertEqual(list(td.glob("gamedb*")), [])
            out = td / "out.json"
            proc2 = subprocess.run(
                [sys.executable, str(CLI), str(src), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(proc2.stdout, "")
            queued = json.loads(out.read_text())
            self.assertEqual(queued["queue"][0]["kind"], "skipped")
            self.assertNotIn("review_decision", queued["skipped"][0])


if __name__ == "__main__":
    unittest.main()
