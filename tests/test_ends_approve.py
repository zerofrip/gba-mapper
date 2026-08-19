"""Phase 8B human explicit-end writer: not verification, not 7B."""
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

import ends_approve  # noqa: E402

CLI = TOOLS / "ends_approve.py"
ADDR_HEX = "0x08001200"
END_HEX = "0x08001240"


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
        "address": "0x08001000",
        "mode": "thumb",
        "selection": "selected",
        "disposition": "peel-ready",
        "deterministic": True,
    }


def human(*items):
    return {
        "format": "gba-mapper-explicit-end",
        "version": 1,
        "ends": list(items),
    }


def entry(addr=ADDR_HEX, mode="thumb", end=END_HEX, **kw):
    d = {"address": addr, "mode": mode, "end": end}
    d.update(kw)
    return d


class Output(unittest.TestCase):
    def test_explicit_end_endmap(self):
        ends, audit = ends_approve.approve(
            human(entry()),
            doc(skipped=[skipped()]),
        )
        self.assertEqual(ends, {f"{ADDR_HEX}:thumb": {"end": END_HEX}})
        self.assertEqual(audit["format"], "gba-mapper-explicit-end-run")
        self.assertFalse(audit["run"]["deterministic"])
        blob = json.dumps(ends)
        for banned in (
            "verified", "range_verified", "encoding_verified", "winner",
            "selection", "disposition", "eligible-for-peel", "suggested_end",
            "confidence", "score", "status", "deterministic", "format",
        ):
            self.assertNotIn(f'"{banned}"', blob)

    def test_suggested_end_never_copied(self):
        ends, audit = ends_approve.approve(
            human({"address": ADDR_HEX, "mode": "thumb", "suggested_end": END_HEX}),
            doc(skipped=[skipped()]),
        )
        self.assertEqual(ends, {})
        self.assertEqual(audit["errors"][0]["error"], "forbidden-field")

        elig = {
            "format": "gba-mapper-eligibility",
            "version": 1,
            "entries": [{
                "address": ADDR_HEX, "mode": "thumb",
                "eligibility": "eligible-for-review",
                "suggested_end": END_HEX, "end_source": "llm",
            }],
        }
        ends, _ = ends_approve.approve(
            human(),  # no explicit end entries
            doc(skipped=[skipped()]),
            None,
            elig,
        )
        self.assertEqual(ends, {})

        elig_alias = {
            "format": "gba-mapper-eligibility",
            "version": 1,
            "entries": [{
                "address": ADDR_HEX, "mode": "thumb",
                "eligibility": "eligible-for-review",
                "end": END_HEX,
            }],
        }
        ends, _ = ends_approve.approve(
            human(entry()),
            doc(skipped=[skipped()]),
            None,
            elig_alias,
        )
        self.assertEqual(ends, {f"{ADDR_HEX}:thumb": {"end": END_HEX}})

    def test_conflicted_independent_no_winner(self):
        rows = [
            skipped(mode="arm", disposition="conflicted"),
            skipped(mode="thumb", disposition="conflicted"),
        ]
        ends, _ = ends_approve.approve(
            human(
                entry(mode="arm", end="0x08001210"),
                entry(mode="thumb", end="0x08001220"),
            ),
            doc(skipped=rows),
        )
        self.assertEqual(ends[f"{ADDR_HEX}:arm"]["end"], "0x08001210")
        self.assertEqual(ends[f"{ADDR_HEX}:thumb"]["end"], "0x08001220")
        self.assertNotIn("winner", json.dumps(ends))


class Filters(unittest.TestCase):
    def test_unresolved_selected_peel_ready(self):
        human_in = human(
            entry("0x08000f00"),
            entry("0x08001000"),
            entry(),
        )
        ends, audit = ends_approve.approve(human_in, doc(
            selected=[selected_peel_ready()],
            skipped=[skipped(disposition="peel-ready")],
            unresolved=[{"address": "0x08000f00", "mode": "thumb",
                         "type": "indirect-branch"}],
        ))
        self.assertEqual(ends, {})
        errs = {e["error"] for e in audit["errors"]}
        self.assertIn("unknown-candidate", errs)

    def test_address_only_and_invalid(self):
        ends, audit = ends_approve.approve(
            {"format": "gba-mapper-explicit-end", "version": 1, "ends": [
                {"address": ADDR_HEX, "end": END_HEX},
            ]},
            doc(skipped=[skipped()]),
        )
        self.assertEqual(ends, {})
        self.assertEqual(audit["errors"][0]["error"], "invalid-end-key")

        ends, audit = ends_approve.approve(
            human(entry(end="0x08001100")),
            doc(skipped=[skipped()]),
        )
        self.assertEqual(ends, {})
        self.assertEqual(audit["errors"][0]["error"], "end-le-start")

    def test_first_wins_after_filter(self):
        rows = [
            skipped(disposition="peel-ready"),
            skipped(disposition="heuristic"),
        ]
        ends, _ = ends_approve.approve(
            human(entry(), entry(end="0x08001300")),
            doc(skipped=rows),
        )
        self.assertEqual(ends, {f"{ADDR_HEX}:thumb": {"end": END_HEX}})

    def test_8a_optional(self):
        eight_a = {
            "format": "gba-mapper-eligibility-approval",
            "version": 1,
            "approvals": [],
        }
        ends, audit = ends_approve.approve(
            human(entry()),
            doc(skipped=[skipped()]),
            eight_a,
        )
        self.assertEqual(ends, {f"{ADDR_HEX}:thumb": {"end": END_HEX}})
        self.assertEqual(audit["errors"][0]["error"], "eligibility-mismatch")

        ends, audit = ends_approve.approve(
            human(entry()),
            doc(skipped=[skipped()]),
            None,
        )
        self.assertEqual(ends, {f"{ADDR_HEX}:thumb": {"end": END_HEX}})
        self.assertEqual(audit["errors"], [])


class Boundary(unittest.TestCase):
    def test_source_has_no_pipeline(self):
        src = inspect.getsource(ends_approve)
        self.assertNotIn("review_select", src)
        self.assertNotIn("llm_suggest", src)
        self.assertNotIn("eligibility_approve", src)
        self.assertNotIn("run_peel", src)
        self.assertNotIn("run_check", src)
        self.assertNotIn("record_range", src)
        self.assertNotIn("subprocess", src)

    def test_cli_stdout_output_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            hi = td / "human.json"
            hi.write_text(json.dumps(human(entry())))
            orig = src.read_text()
            orig_h = hi.read_text()
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--ends-input", str(hi)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result, {f"{ADDR_HEX}:thumb": {"end": END_HEX}})
            self.assertEqual(src.read_text(), orig)
            self.assertEqual(hi.read_text(), orig_h)
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            self.assertEqual(list(td.glob("gamedb*")), [])
            out = td / "ends.json"
            audit = td / "audit.json"
            proc2 = subprocess.run(
                [sys.executable, str(CLI), str(src), "--ends-input", str(hi),
                 "--output", str(out), "--audit", str(audit)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(proc2.stdout, "")
            self.assertEqual(json.loads(out.read_text())[f"{ADDR_HEX}:thumb"]["end"],
                             END_HEX)
            self.assertFalse(json.loads(audit.read_text())["run"]["deterministic"])
            malformed = td / "bad.json"
            malformed.write_text("{")
            bad = subprocess.run(
                [sys.executable, str(CLI), "--ends-input", str(malformed)],
                cwd=td, capture_output=True, text=True,
            )
            self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
