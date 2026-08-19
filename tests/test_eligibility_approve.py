"""Phase 8A human eligibility approval: overlay only. Not 7B."""
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

import eligibility_approve  # noqa: E402

CLI = TOOLS / "eligibility_approve.py"
ADDR_HEX = "0x08001200"


def skipped(*, addr=ADDR_HEX, mode="thumb", disposition="heuristic", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "selection": "skipped",
        "disposition": disposition,
        "deterministic": False,
        "sources": ["ghidra"],
        "classes": ["oracle-seed"],
        "evidence_items": [{"type": "ghidra-seed", "source": "ghidra"}],
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
        "address": "0x08001000",
        "mode": "thumb",
        "selection": "selected",
        "disposition": "peel-ready",
        "deterministic": True,
        "sources": ["modeflow"],
        "classes": ["control-flow"],
    }


def human(*items):
    return {
        "format": "gba-mapper-eligibility-approval",
        "version": 1,
        "approvals": list(items),
    }


def decision(addr=ADDR_HEX, mode="thumb", eligibility="eligible-for-peel", **kw):
    d = {"address": addr, "mode": mode, "eligibility": eligibility}
    d.update(kw)
    return d


class TargetFilter(unittest.TestCase):
    def test_human_approve_three_dispositions(self):
        rows = [
            skipped(disposition="agreed-seed"),
            skipped(addr="0x08001300", disposition="heuristic"),
            skipped(addr="0x08001400", mode="arm", disposition="conflicted"),
            skipped(addr="0x08001400", mode="thumb", disposition="conflicted"),
        ]
        appr = human(
            decision(),
            decision("0x08001300"),
            decision("0x08001400", "arm"),
            decision("0x08001400", "thumb"),
        )
        out = eligibility_approve.approve(doc(skipped=rows), appr)
        keys = {(a["address"], a["mode"], a["eligibility"]) for a in out["approvals"]}
        self.assertEqual(len(out["approvals"]), 4)
        self.assertIn((ADDR_HEX, "thumb", "eligible-for-peel"), keys)
        self.assertIn(("0x08001400", "arm", "eligible-for-peel"), keys)
        self.assertIn(("0x08001400", "thumb", "eligible-for-peel"), keys)
        self.assertNotIn("winner", json.dumps(out))
        for a in out["approvals"]:
            self.assertFalse(a["deterministic"])

    def test_selected_peel_ready_unresolved_not_approved(self):
        appr = human(
            decision("0x08001000"),
            decision(),
            decision("0x08000f00"),
        )
        out = eligibility_approve.approve(doc(
            selected=[selected_peel_ready()],
            skipped=[skipped(disposition="peel-ready")],
            unresolved=[{"type": "indirect-branch", "from_addr": "0x08000f00",
                         "address": "0x08000f00", "mode": "thumb"}],
        ), appr)
        self.assertEqual(out["approvals"], [])
        errs = {e["error"] for e in out["errors"]}
        self.assertIn("unknown-candidate", errs)

    def test_no_human_file_does_not_infer(self):
        elig = {
            "format": "gba-mapper-eligibility",
            "version": 1,
            "entries": [{
                "address": ADDR_HEX, "mode": "thumb",
                "eligibility": "eligible-for-review",
                "deterministic": False,
            }],
        }
        out = eligibility_approve.approve(doc(skipped=[skipped()]), None, elig)
        self.assertEqual(out["approvals"], [])


class Gates(unittest.TestCase):
    def test_mismatch_still_approves(self):
        elig = {
            "format": "gba-mapper-eligibility",
            "version": 1,
            "entries": [{
                "address": ADDR_HEX, "mode": "thumb",
                "eligibility": "not-eligible", "deterministic": False,
            }],
        }
        out = eligibility_approve.approve(
            doc(skipped=[skipped()]), human(decision()), elig,
        )
        self.assertEqual(out["approvals"][0]["eligibility"], "eligible-for-peel")
        self.assertEqual(out["errors"][0]["error"], "eligibility-mismatch")
        self.assertEqual(out["errors"][0]["seven_dc"], "not-eligible")

    def test_first_wins_after_filter(self):
        rows = [
            skipped(disposition="peel-ready"),
            skipped(disposition="heuristic"),
        ]
        dup = human(decision(), decision(eligibility="eligible-for-peel"))
        out = eligibility_approve.approve(doc(skipped=rows), dup)
        self.assertEqual(len(out["approvals"]), 1)
        self.assertEqual(out["approvals"][0]["eligibility"], "eligible-for-peel")

    def test_invalid_and_forbidden(self):
        row = skipped()
        out = eligibility_approve.approve(
            doc(skipped=[row]),
            human(decision(eligibility="select-for-peel")),
        )
        self.assertEqual(out["approvals"], [])
        self.assertEqual(out["errors"][0]["error"], "invalid-eligibility")

        out = eligibility_approve.approve(
            doc(skipped=[row]),
            human(decision(end="0x08001280")),
        )
        self.assertEqual(out["approvals"], [])
        self.assertEqual(out["errors"][0]["error"], "forbidden-field")

        addr_only = {
            "format": "gba-mapper-eligibility-approval",
            "version": 1,
            "approvals": [{"address": ADDR_HEX, "eligibility": "eligible-for-peel"}],
        }
        out = eligibility_approve.approve(doc(skipped=[row]), addr_only)
        self.assertEqual(out["approvals"], [])
        self.assertEqual(out["errors"][0]["error"], "invalid-approval-key")


class Boundary(unittest.TestCase):
    def test_schema_and_immutability(self):
        row = skipped()
        out = eligibility_approve.approve(doc(skipped=[row]), human(decision()))
        self.assertEqual(out["format"], "gba-mapper-eligibility-approval")
        self.assertEqual(out["version"], 1)
        self.assertFalse(out["run"]["deterministic"])
        blob = json.dumps(out)
        for banned in (
            "select-for-peel", "range_verified", "encoding_verified",
            "winner", "suggested_end", "review_decision",
        ):
            self.assertNotIn(f'"{banned}"', blob)
        self.assertNotIn('"selection"', json.dumps(out["approvals"][0]))
        self.assertEqual(row["selection"], "skipped")
        self.assertEqual(row["disposition"], "heuristic")

    def test_source_has_no_pipeline(self):
        src = inspect.getsource(eligibility_approve)
        self.assertNotIn("review_select", src)
        self.assertNotIn("llm_suggest", src)
        self.assertNotIn("import eligibility\n", src)
        self.assertNotIn("run_peel", src)
        self.assertNotIn("run_check", src)
        self.assertNotIn("record_range", src)
        self.assertNotIn("subprocess", src)

    def test_cli_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            ap = td / "ap.json"
            ap.write_text(json.dumps(human(decision())))
            orig = src.read_text()
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--approval", str(ap)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["approvals"][0]["eligibility"], "eligible-for-peel")
            self.assertEqual(src.read_text(), orig)
            self.assertFalse((td / "labels.toml").exists())
            out = td / "out.json"
            subprocess.run(
                [sys.executable, str(CLI), str(src), "--approval", str(ap),
                 "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(json.loads(out.read_text())["format"],
                             "gba-mapper-eligibility-approval")


if __name__ == "__main__":
    unittest.main()
