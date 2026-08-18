"""Phase 7D-C eligibility overlay: advisory only. Not verification."""
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

import eligibility  # noqa: E402

CLI = TOOLS / "eligibility.py"
ADDR = 0x08001200
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
        "evidence_items": [
            {"type": "ghidra-seed", "source": "ghidra", "detail": "INJECT /bin/sh"},
        ],
        "skip_reason": "heuristic/oracle only",
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
        "evidence_items": [{"type": "bl-target", "source": "modeflow"}],
    }


def suggest_artifact(pairs):
    suggestions = []
    for row, action, extra in pairs:
        req = eligibility.build_request(row)
        item = {
            "address": row["address"],
            "mode": row["mode"],
            "action": action,
            "rationale": "advisory text",
            "provider": "fake",
            "model": "fixture",
            "prompt_version": "7db-v1",
            "input_hash": extra.get("input_hash") if extra and "input_hash" in extra
            else eligibility.input_hash(req),
            "deterministic": False,
        }
        if extra:
            item.update({k: v for k, v in extra.items() if k != "input_hash" or "input_hash" in extra})
            if "input_hash" in extra:
                item["input_hash"] = extra["input_hash"]
        suggestions.append(item)
    return {
        "format": "gba-mapper-llm-suggestion",
        "version": 1,
        "run": {"provider": "fake", "model": "fixture", "prompt_version": "7db-v1",
                "input_hash": "00"},
        "suggestions": suggestions,
        "errors": [],
    }


class TargetFilter(unittest.TestCase):
    def test_skipped_three_dispositions(self):
        out = eligibility.overlay(doc(skipped=[
            skipped(disposition="agreed-seed"),
            skipped(addr="0x08001300", disposition="heuristic"),
            skipped(addr="0x08001400", mode="arm", disposition="conflicted"),
            skipped(addr="0x08001400", mode="thumb", disposition="conflicted"),
        ]))
        keys = {(e["address"], e["mode"], e["disposition"], e["eligibility"])
                for e in out["entries"]}
        self.assertEqual(len(out["entries"]), 4)
        self.assertIn((ADDR_HEX, "thumb", "agreed-seed", "needs-human-review"), keys)
        self.assertIn(("0x08001300", "thumb", "heuristic", "needs-human-review"), keys)
        self.assertIn(("0x08001400", "arm", "conflicted", "needs-human-review"), keys)
        self.assertIn(("0x08001400", "thumb", "conflicted", "needs-human-review"), keys)
        blob = json.dumps(out)
        self.assertNotIn("winner", blob)
        self.assertNotIn("preferred_mode", blob)

    def test_selected_peel_ready_unresolved_ignored(self):
        out = eligibility.overlay(doc(
            selected=[selected_peel_ready()],
            skipped=[skipped(disposition="peel-ready")],
            unresolved=[{"type": "indirect-branch", "from_addr": "0x08000f00"}],
        ))
        self.assertEqual(out["entries"], [])
        self.assertNotIn("eligibility", json.dumps(out.get("unresolved", [])))

    def test_first_wins_after_target_filter(self):
        rows = [
            skipped(disposition="peel-ready"),
            skipped(disposition="heuristic", extra={"sources": ["modeflow"]}),
            skipped(disposition="agreed-seed"),
        ]
        out = eligibility.overlay(doc(skipped=rows))
        self.assertEqual(len(out["entries"]), 1)
        self.assertEqual(out["entries"][0]["disposition"], "heuristic")
        self.assertEqual(out["entries"][0]["disposition"], rows[1]["disposition"])


class MappingAndHash(unittest.TestCase):
    def test_suggestion_mapping_and_mode_lock(self):
        rows = [
            skipped(disposition="heuristic"),
            skipped(addr="0x08001300", disposition="heuristic"),
            skipped(addr="0x08001400", disposition="heuristic"),
            skipped(addr="0x08001500", disposition="heuristic"),
            skipped(addr="0x08001600", mode="arm", disposition="conflicted"),
            skipped(addr="0x08001600", mode="thumb", disposition="conflicted"),
        ]
        art = suggest_artifact([
            (rows[0], "possible-control-flow", None),
            (rows[1], "possible-data", None),
            (rows[2], "possible-invalid", None),
            (rows[3], "insufficient-evidence", None),
            (rows[4], "arm-plausible", None),
            (rows[5], "thumb-plausible", None),
        ])
        out = eligibility.overlay(doc(skipped=rows), art)
        by = {(e["address"], e["mode"]): e for e in out["entries"]}
        self.assertEqual(by[(ADDR_HEX, "thumb")]["eligibility"], "eligible-for-review")
        self.assertEqual(by[("0x08001300", "thumb")]["eligibility"], "not-eligible")
        self.assertEqual(by[("0x08001400", "thumb")]["eligibility"], "not-eligible")
        self.assertEqual(by[("0x08001500", "thumb")]["eligibility"], "needs-human-review")
        self.assertEqual(by[("0x08001600", "arm")]["eligibility"], "eligible-for-review")
        self.assertEqual(by[("0x08001600", "thumb")]["eligibility"], "eligible-for-review")
        self.assertEqual(by[(ADDR_HEX, "thumb")]["suggestion"]["provider"], "fake")
        self.assertFalse(by[(ADDR_HEX, "thumb")]["deterministic"])

    def test_arm_plausible_on_thumb_not_mapped(self):
        row = skipped(mode="thumb")
        art = suggest_artifact([(row, "arm-plausible", None)])
        out = eligibility.overlay(doc(skipped=[row]), art)
        self.assertEqual(out["entries"][0]["eligibility"], "needs-human-review")
        self.assertEqual(out["errors"][0]["error"], "action-mode-mismatch")

    def test_stale_unknown_forbidden_address_only(self):
        row = skipped()
        stale = suggest_artifact([(row, "possible-control-flow", {"input_hash": "dead"})])
        out = eligibility.overlay(doc(skipped=[row]), stale)
        self.assertEqual(out["entries"][0]["eligibility"], "needs-human-review")
        self.assertEqual(out["errors"][0]["error"], "stale-input-hash")

        unknown = suggest_artifact([(row, "select-for-peel", None)])
        out = eligibility.overlay(doc(skipped=[row]), unknown)
        self.assertEqual(out["entries"][0]["eligibility"], "needs-human-review")
        self.assertEqual(out["errors"][0]["error"], "unknown-action")

        forbid = suggest_artifact([(row, "review", {"end": "0x1"})])
        out = eligibility.overlay(doc(skipped=[row]), forbid)
        self.assertEqual(out["entries"][0]["eligibility"], "needs-human-review")
        self.assertEqual(out["errors"][0]["error"], "forbidden-suggestion-field")

        addr_only = {
            "format": "gba-mapper-llm-suggestion", "version": 1,
            "suggestions": [{
                "address": ADDR_HEX, "action": "review",
                "provider": "fake", "model": "fixture",
                "prompt_version": "7db-v1", "input_hash": "00",
            }],
        }
        out = eligibility.overlay(doc(skipped=[row]), addr_only)
        self.assertEqual(out["entries"][0]["eligibility"], "needs-human-review")
        self.assertEqual(out["errors"][0]["error"], "invalid-suggestion-key")


class SuggestedEnd(unittest.TestCase):
    def test_candidate_key_end_and_no_inference(self):
        row = skipped(extra={"size": 64, "recommendedEnd": "0x08001280", "end": "0x08001280"})
        ends = {f"{ADDR_HEX}:thumb": {"suggested_end": "0x08001240", "end_source": "human"}}
        out = eligibility.overlay(doc(skipped=[row]), None, ends)
        e = out["entries"][0]
        self.assertEqual(e["suggested_end"], "0x08001240")
        self.assertEqual(e["end_source"], "human")
        self.assertEqual(e["eligibility"], "needs-human-review")
        self.assertNotEqual(e["suggested_end"], row["recommendedEnd"])

        none = eligibility.overlay(doc(skipped=[row]))
        self.assertNotIn("suggested_end", none["entries"][0])

        arm = skipped(mode="arm")
        thumb = skipped(mode="thumb")
        both = {
            f"{ADDR_HEX}:arm": {"suggested_end": "0x08001210", "end_source": "manual"},
            f"{ADDR_HEX}:thumb": {"suggested_end": "0x08001220", "end_source": "manual"},
        }
        out = eligibility.overlay(doc(skipped=[arm, thumb]), None, both)
        by = {e["mode"]: e["suggested_end"] for e in out["entries"]}
        self.assertEqual(by["arm"], "0x08001210")
        self.assertEqual(by["thumb"], "0x08001220")

    def test_invalid_and_address_only_end(self):
        row = skipped()
        out = eligibility.overlay(doc(skipped=[row]), None, {f"{ADDR_HEX}:thumb": "0x08001100"})
        self.assertNotIn("suggested_end", out["entries"][0])
        self.assertEqual(out["errors"][0]["error"], "invalid-suggested-end")

        out = eligibility.overlay(doc(skipped=[row]), None, {ADDR_HEX: "0x08001280"})
        self.assertNotIn("suggested_end", out["entries"][0])
        self.assertEqual(out["errors"][0]["error"], "address-only-end-mapping")


class Boundary(unittest.TestCase):
    def test_output_schema_and_immutability(self):
        row = skipped()
        out = eligibility.overlay(doc(skipped=[row]))
        e = out["entries"][0]
        self.assertEqual(out["format"], "gba-mapper-eligibility")
        self.assertEqual(out["version"], 1)
        self.assertEqual(e["disposition"], "heuristic")
        self.assertFalse(e["deterministic"])
        blob = json.dumps(out)
        for banned in (
            "review_decision", "select-for-peel", "range_verified",
            "encoding_verified", "winner", "confidence", "score", "status",
        ):
            self.assertNotIn(f'"{banned}"', blob)
        self.assertNotIn('"selection"', json.dumps(e))
        self.assertEqual(row["disposition"], "heuristic")
        self.assertEqual(row["selection"], "skipped")

    def test_source_has_no_pipeline(self):
        src = inspect.getsource(eligibility)
        self.assertNotIn("review_select", src)
        self.assertNotIn("select_peel", src)
        self.assertNotIn("run_peel", src)
        self.assertNotIn("run_check", src)
        self.assertNotIn("record_range", src)
        self.assertNotIn("promote_encoding", src)
        self.assertNotIn("subprocess", src)
        self.assertNotIn("openai", src)
        self.assertNotIn("import requests", src)

    def test_cli_stdout_output_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["entries"][0]["eligibility"], "needs-human-review")
            self.assertFalse(result["entries"][0]["deterministic"])
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            self.assertEqual(list(td.glob("gamedb*")), [])
            out = td / "out.json"
            ends = td / "ends.json"
            ends.write_text(json.dumps({
                f"{ADDR_HEX}:thumb": {"suggested_end": "0x08001240", "end_source": "human"},
            }))
            proc2 = subprocess.run(
                [sys.executable, str(CLI), str(src),
                 "--suggested-ends", str(ends), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(proc2.stdout, "")
            written = json.loads(out.read_text())
            self.assertEqual(written["format"], "gba-mapper-eligibility")
            self.assertEqual(written["entries"][0]["suggested_end"], "0x08001240")
            self.assertFalse((td / "ends-for-7b.json").exists())


if __name__ == "__main__":
    unittest.main()
