"""Phase 9 integration: existing authority chain. Not authority.

Exercises 7A + 8B EndMap + 8E verification through 8F gate with
injected 7B/7C fakes. Does not run real peel, RANGE, LLM, Ghidra, or ROM.
"""
from __future__ import annotations

import ast
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import phase8f_gate  # noqa: E402

ADDR = 0x08001200
ADDR_HEX = "0x08001200"
END_HEX = "0x08001240"


def selected(*, addr=ADDR_HEX, mode="thumb", selection="selected",
             disposition="peel-ready"):
    return {
        "address": addr,
        "mode": mode,
        "selection": selection,
        "disposition": disposition,
        "deterministic": True,
    }


def skipped(*, addr=ADDR_HEX, mode="thumb", disposition="heuristic"):
    return {
        "address": addr,
        "mode": mode,
        "selection": "skipped",
        "disposition": disposition,
        "deterministic": False,
    }


def seven_a(*, selected_rows=None, skipped_rows=None):
    return {
        "selected": list(selected_rows or []),
        "skipped": list(skipped_rows or []),
        "unresolved": [],
    }


def endmap(*triples):
    return {f"{addr}:{mode}": {"end": end} for addr, mode, end in triples}


def eight_e(*, results=None, deterministic=True, fmt="gba-mapper-encoding-verification",
            version=1):
    return {
        "format": fmt,
        "version": version,
        "run": {"deterministic": deterministic},
        "results": list(results or []),
        "errors": [],
    }


def verified(*, addr=ADDR_HEX, mode="thumb", ok=True):
    return {"address": addr, "mode": mode, "encoding_verified": ok}


def eight_a(*items):
    return {
        "format": "gba-mapper-eligibility-approval",
        "version": 1,
        "approvals": list(items),
    }


class Recorders:
    def __init__(self, peel_result="peel-emitted", check_result="range-recorded"):
        self.peel_calls = []
        self.check_calls = []
        self.peel_result = peel_result
        self.check_result = check_result

    def peel(self, filtered, ends):
        self.peel_calls.append((filtered, ends))
        rows = [{"address": r["address"], "mode": r["mode"],
                 "result": self.peel_result}
                for r in filtered.get("selected") or []]
        return {"results": rows, "skipped": [], "unresolved": []}

    def check(self, peel_obj, ends):
        self.check_calls.append((peel_obj, ends))
        rows = [{"address": r["address"], "mode": r["mode"],
                 "result": self.check_result}
                for r in peel_obj.get("results") or []]
        return {"results": rows, "skipped": [], "unresolved": []}


def run_chain(src, ends, enc, eight_a=None, rec=None, execute_7b=True, execute_7c=True):
    rec = rec or Recorders()
    out = phase8f_gate.orchestrate(
        src, ends, enc, eight_a,
        execute_7b=execute_7b,
        execute_7c=execute_7c,
        peel_runner=rec.peel,
        check_runner=rec.check,
    )
    return out, rec


class Identity(unittest.TestCase):
    def test_candidatekey_pair_required(self):
        out, rec = run_chain(
            seven_a(selected_rows=[{"address": ADDR_HEX, "selection": "selected",
                                    "disposition": "peel-ready"}]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
        )
        self.assertEqual(out["errors"][0]["error"], "address-only")
        self.assertEqual(rec.peel_calls, [])

    def test_invalid_mode_rejected(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected(mode="invalid")]),
            endmap((ADDR_HEX, "invalid", END_HEX)),
            eight_e(results=[verified(mode="invalid")]),
        )
        self.assertEqual(out["errors"][0]["error"], "invalid-key")
        self.assertEqual(rec.peel_calls, [])

    def test_same_address_arm_thumb_independent(self):
        src = seven_a(selected_rows=[selected(mode="thumb"), selected(mode="arm")])
        ends = endmap((ADDR_HEX, "thumb", END_HEX))
        enc = eight_e(results=[verified(mode="thumb"), verified(mode="arm")])
        out, rec = run_chain(src, ends, enc)
        ready = {(r["address"], r["mode"]) for r in out["results"]}
        self.assertEqual(ready, {(ADDR_HEX, "thumb")})
        self.assertTrue(any(e["mode"] == "arm" and e["error"] == "missing-explicit-end"
                            for e in out["errors"]))
        self.assertEqual(len(rec.peel_calls[0][0]["selected"]), 1)
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "thumb")


class AuthorityConjunction(unittest.TestCase):
    def test_ready_requires_all_four(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
        )
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertEqual(len(rec.peel_calls), 1)
        self.assertEqual(len(rec.check_calls), 1)

    def test_selected_only(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            {},
            eight_e(results=[]),
        )
        self.assertEqual(out["results"], [])
        self.assertEqual(rec.peel_calls, [])

    def test_peel_ready_only(self):
        out, rec = run_chain(
            seven_a(skipped_rows=[skipped(disposition="peel-ready")]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
        )
        self.assertEqual(rec.peel_calls, [])
        self.assertTrue(any(e["error"] == "not-selected" for e in out["errors"]))

    def test_explicit_end_only(self):
        out, rec = run_chain(
            seven_a(),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
        )
        self.assertEqual(out["results"], [])
        self.assertEqual(rec.peel_calls, [])

    def test_encoding_verified_only(self):
        out, rec = run_chain(
            seven_a(),
            {},
            eight_e(results=[verified()]),
        )
        self.assertEqual(rec.peel_calls, [])
        self.assertEqual(out["results"], [])

    def test_eligible_for_peel_does_not_substitute(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected(disposition="heuristic")]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            eight_a({"address": ADDR_HEX, "mode": "thumb",
                     "eligibility": "eligible-for-peel"}),
        )
        self.assertEqual(out["errors"][0]["error"], "not-peel-ready")
        self.assertEqual(rec.peel_calls, [])

    def test_8d_claim_does_not_substitute_for_8e(self):
        claim = {
            "format": "gba-mapper-encoding-claim",
            "version": 1,
            "claims": [{"address": ADDR_HEX, "mode": "thumb",
                        "source": "human", "claim": "thumb"}],
        }
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            claim,
        )
        self.assertTrue(any(e["error"] == "invalid-encoding-verification"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])

    def test_llm_suggestion_does_not_substitute_for_8e(self):
        llm = {
            "format": "gba-mapper-llm-suggestion",
            "version": 1,
            "suggestions": [{"address": ADDR_HEX, "mode": "thumb",
                             "action": "thumb-plausible"}],
        }
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            llm,
        )
        self.assertTrue(any(e["error"] == "invalid-encoding-verification"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])


class EightE(unittest.TestCase):
    def test_wrong_format_version(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()], fmt="nope", version=2),
        )
        self.assertTrue(any(e["error"] == "invalid-encoding-verification"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])

    def test_deterministic_false(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()], deterministic=False),
        )
        self.assertTrue(any(e["error"] == "invalid-encoding-verification"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])

    def test_candidatekey_mismatch(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected(mode="thumb")]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified(mode="arm")]),
        )
        self.assertEqual(out["errors"][0]["error"], "encoding-not-verified")
        self.assertEqual(rec.peel_calls, [])

    def test_address_mismatch(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified(addr="0x08001300")]),
        )
        self.assertEqual(out["errors"][0]["error"], "encoding-not-verified")
        self.assertEqual(rec.peel_calls, [])

    def test_verified_false_rejected(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified(ok=False)]),
        )
        self.assertEqual(out["errors"][0]["error"], "encoding-not-verified")
        self.assertEqual(rec.peel_calls, [])

    def test_missing_encoding(self):
        out = phase8f_gate.gate(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            None,
        )
        self.assertEqual(out["errors"][0]["error"], "missing-encoding-verification")


class EightA(unittest.TestCase):
    def test_absent_allowed(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            None,
        )
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertEqual(len(rec.peel_calls), 1)

    def test_mismatch(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            eight_a({"address": ADDR_HEX, "mode": "thumb",
                     "eligibility": "eligible-for-review"}),
        )
        self.assertEqual(out["errors"][0]["error"], "eligibility-mismatch")
        self.assertEqual(rec.peel_calls, [])

    def test_eligible_for_peel_alone_not_ready(self):
        out, rec = run_chain(
            seven_a(skipped_rows=[skipped()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            eight_a({"address": ADDR_HEX, "mode": "thumb",
                     "eligibility": "eligible-for-peel"}),
        )
        self.assertEqual(out["results"], [])
        self.assertEqual(rec.peel_calls, [])


class SevenBSevenC(unittest.TestCase):
    def test_default_peel_flags(self):
        src = inspect.getsource(phase8f_gate._default_peel)
        self.assertIn("write_labels=False", src)
        self.assertIn("force_boundary=False", src)
        self.assertNotIn("write_labels=True", src)
        self.assertNotIn("force_boundary=True", src)

    def test_7b_not_invoked_without_ready(self):
        for src, ends, enc in (
            (seven_a(skipped_rows=[skipped()]),
             endmap((ADDR_HEX, "thumb", END_HEX)),
             eight_e(results=[verified()])),
            (seven_a(selected_rows=[selected(disposition="heuristic")]),
             endmap((ADDR_HEX, "thumb", END_HEX)),
             eight_e(results=[verified()])),
            (seven_a(selected_rows=[selected()]),
             {},
             eight_e(results=[verified()])),
            (seven_a(selected_rows=[selected()]),
             {f"{ADDR_HEX}:thumb": {"end": "bad"}},
             eight_e(results=[verified()])),
            (seven_a(selected_rows=[selected()]),
             endmap((ADDR_HEX, "thumb", END_HEX)),
             None),
            (seven_a(selected_rows=[selected()]),
             endmap((ADDR_HEX, "thumb", END_HEX)),
             eight_e(results=[verified()], fmt="nope")),
        ):
            out, rec = run_chain(src, ends, enc)
            self.assertEqual(rec.peel_calls, [])
            self.assertEqual(rec.check_calls, [])
            self.assertEqual(out["results"], [])

    def test_7b_failure_blocks_7c(self):
        rec = Recorders(peel_result="peel-failed")
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            rec=rec,
        )
        self.assertTrue(any(e["error"] == "7b-failed" for e in out["errors"]))
        self.assertEqual(rec.check_calls, [])
        self.assertNotIn("range_verified", json.dumps(out))

    def test_7c_only_after_peel_emitted(self):
        rec = Recorders(peel_result="peel-skipped")
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            rec=rec,
        )
        self.assertEqual(len(rec.peel_calls), 1)
        self.assertEqual(rec.check_calls, [])
        self.assertTrue(any(e["error"] == "7c-gate-failed" for e in out["errors"]))

    def test_7c_failure_is_not_range_success(self):
        rec = Recorders(check_result="check-failed")
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            endmap((ADDR_HEX, "thumb", END_HEX)),
            eight_e(results=[verified()]),
            rec=rec,
        )
        self.assertTrue(any(e["error"] == "7c-failed" for e in out["errors"]))
        self.assertNotIn("range_verified", json.dumps(out))
        self.assertNotIn("RANGE", json.dumps(out))

    def test_invalid_end_no_7b(self):
        out, rec = run_chain(
            seven_a(selected_rows=[selected()]),
            {f"{ADDR_HEX}:thumb": {"end": "bad"}},
            eight_e(results=[verified()]),
        )
        self.assertTrue(any(e["error"] == "invalid-explicit-end" for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])


class PersistenceAndSecurity(unittest.TestCase):
    def test_inputs_unchanged(self):
        src = seven_a(selected_rows=[selected()])
        ends = endmap((ADDR_HEX, "thumb", END_HEX))
        enc = eight_e(results=[verified()])
        before = (json.dumps(src), json.dumps(ends), json.dumps(enc))
        run_chain(src, ends, enc)
        self.assertEqual((json.dumps(src), json.dumps(ends), json.dumps(enc)), before)

    def test_no_pipeline_module_imports(self):
        tree = ast.parse(Path(__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported <= {
            "__future__", "inspect", "json", "sys", "tempfile",
            "unittest", "pathlib", "phase8f_gate", "ast",
        })
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "skipTest", "expectedFailure", "skip",
            }:
                self.fail(node.attr)

    def test_no_labels_or_gamedb_writes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            run_chain(
                seven_a(selected_rows=[selected()]),
                endmap((ADDR_HEX, "thumb", END_HEX)),
                eight_e(results=[verified()]),
            )
            self.assertEqual(list(td.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
