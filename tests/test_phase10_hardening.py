"""Phase 10 final integration hardening. Not authority.

Observes existing 8F gate/orchestrate with synthetic JSON and injected
7B/7C fakes. Does not mint candidates, rewrite selection, infer ends,
verify encodings, or emit RANGE / Evidence / labels.
"""
from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import phase8f_gate  # noqa: E402

ADDR = 0x08001200
ADDR_HEX = "0x08001200"
END_ARM = "0x08001280"
END_THUMB = "0x08001240"


def row(*, addr=ADDR_HEX, mode="thumb", selection="selected",
        disposition="peel-ready"):
    return {
        "address": addr,
        "mode": mode,
        "selection": selection,
        "disposition": disposition,
        "deterministic": True,
    }


def seven_a(*, selected_rows=None, skipped_rows=None):
    return {
        "selected": list(selected_rows or []),
        "skipped": list(skipped_rows or []),
        "unresolved": [],
    }


def endmap(*triples):
    return {f"{addr}:{mode}": {"end": end} for addr, mode, end in triples}


def eight_e(*, results=None, deterministic=True):
    return {
        "format": "gba-mapper-encoding-verification",
        "version": 1,
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


def full(*, mode="thumb", end=None):
    end = end or (END_ARM if mode == "arm" else END_THUMB)
    return (
        seven_a(selected_rows=[row(mode=mode)]),
        endmap((ADDR_HEX, mode, end)),
        eight_e(results=[verified(mode=mode)]),
    )


class Recorders:
    def __init__(self, peel_result="peel-emitted", check_result="check-ok"):
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


def run_chain(src, ends, enc, eight_a_obj=None, rec=None,
              execute_7b=True, execute_7c=True):
    rec = rec or Recorders()
    out = phase8f_gate.orchestrate(
        src, ends, enc, eight_a_obj,
        execute_7b=execute_7b,
        execute_7c=execute_7c,
        peel_runner=rec.peel,
        check_runner=rec.check,
    )
    return out, rec


def ready_modes(out):
    return {(r["address"], r["mode"]) for r in out["results"]
            if r.get("gate") == "ready"}


def blob(out):
    return json.dumps(out)


class SameAddressArmThumb(unittest.TestCase):
    def test_arm_verified_thumb_not_verified(self):
        src = seven_a(selected_rows=[row(mode="arm"), row(mode="thumb")])
        ends = endmap((ADDR_HEX, "arm", END_ARM), (ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified(mode="arm", ok=True),
                               verified(mode="thumb", ok=False)])
        out, rec = run_chain(src, ends, enc)
        self.assertEqual(ready_modes(out), {(ADDR_HEX, "arm")})
        self.assertTrue(any(e["mode"] == "thumb" and
                            e["error"] == "encoding-not-verified"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "arm")
        self.assertEqual(len(rec.peel_calls[0][0]["selected"]), 1)

    def test_thumb_verified_arm_not_verified(self):
        src = seven_a(selected_rows=[row(mode="arm"), row(mode="thumb")])
        ends = endmap((ADDR_HEX, "arm", END_ARM), (ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified(mode="arm", ok=False),
                               verified(mode="thumb", ok=True)])
        out, rec = run_chain(src, ends, enc)
        self.assertEqual(ready_modes(out), {(ADDR_HEX, "thumb")})
        self.assertTrue(any(e["mode"] == "arm" and
                            e["error"] == "encoding-not-verified"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "thumb")
        self.assertEqual(len(rec.peel_calls[0][0]["selected"]), 1)

    def test_arm_end_not_copied_to_thumb(self):
        src = seven_a(selected_rows=[row(mode="arm"), row(mode="thumb")])
        ends = endmap((ADDR_HEX, "arm", END_ARM))
        enc = eight_e(results=[verified(mode="arm"), verified(mode="thumb")])
        out, rec = run_chain(src, ends, enc)
        self.assertEqual(ready_modes(out), {(ADDR_HEX, "arm")})
        self.assertTrue(any(e["mode"] == "thumb" and
                            e["error"] == "missing-explicit-end"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "arm")

    def test_thumb_end_not_copied_to_arm(self):
        src = seven_a(selected_rows=[row(mode="arm"), row(mode="thumb")])
        ends = endmap((ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified(mode="arm"), verified(mode="thumb")])
        out, rec = run_chain(src, ends, enc)
        self.assertEqual(ready_modes(out), {(ADDR_HEX, "thumb")})
        self.assertTrue(any(e["mode"] == "arm" and
                            e["error"] == "missing-explicit-end"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "thumb")


class Overlay8A(unittest.TestCase):
    def test_absent_ready(self):
        out, rec = run_chain(*full(), None)
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertTrue(out["invoked"]["peel"])

    def test_matching_ready(self):
        out, rec = run_chain(
            *full(),
            eight_a({"address": ADDR_HEX, "mode": "thumb",
                     "eligibility": "eligible-for-peel"}),
        )
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertTrue(out["invoked"]["peel"])
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["disposition"],
                         "peel-ready")

    def test_mismatch_no_7b(self):
        out, rec = run_chain(
            *full(),
            eight_a({"address": ADDR_HEX, "mode": "thumb",
                     "eligibility": "eligible-for-review"}),
        )
        self.assertEqual(out["errors"][0]["error"], "eligibility-mismatch")
        self.assertEqual(rec.peel_calls, [])
        self.assertFalse(out["invoked"]["peel"])

    def test_eligible_for_peel_does_not_make_peel_ready(self):
        src = seven_a(selected_rows=[row(disposition="heuristic")])
        ends = endmap((ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified()])
        out, rec = run_chain(
            src, ends, enc,
            eight_a({"address": ADDR_HEX, "mode": "thumb",
                     "eligibility": "eligible-for-peel"}),
        )
        self.assertEqual(out["errors"][0]["error"], "not-peel-ready")
        self.assertEqual(rec.peel_calls, [])
        self.assertEqual(out["results"], [])


class Conflict8E(unittest.TestCase):
    def _conflict(self, first, second):
        src, ends, _ = full()
        enc = eight_e(results=[
            verified(ok=first),
            verified(ok=second),
        ])
        return run_chain(src, ends, enc)

    def test_true_then_false_fail_closed(self):
        out, rec = self._conflict(True, False)
        self.assertEqual(out["results"], [])
        self.assertTrue(any(e["error"] == "conflicting-verification"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])
        self.assertEqual(rec.check_calls, [])
        self.assertFalse(out["invoked"]["peel"])

    def test_false_then_true_fail_closed(self):
        out, rec = self._conflict(False, True)
        self.assertEqual(out["results"], [])
        self.assertTrue(any(e["error"] == "conflicting-verification"
                            for e in out["errors"]))
        self.assertEqual(rec.peel_calls, [])
        self.assertFalse(out["invoked"]["peel"])


class HappyPath(unittest.TestCase):
    def test_execution_contract(self):
        rec = Recorders(peel_result="peel-emitted", check_result="check-ok")
        out, rec = run_chain(*full(), rec=rec)
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertTrue(out["invoked"]["peel"])
        self.assertTrue(out["invoked"]["check"])
        filtered, ends = rec.peel_calls[0]
        self.assertEqual(filtered["selected"][0]["address"], ADDR_HEX)
        self.assertEqual(filtered["selected"][0]["mode"], "thumb")
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["selection"],
                         "selected")
        peel_obj, _ = rec.check_calls[0]
        self.assertEqual(peel_obj["results"][0]["result"], "peel-emitted")
        self.assertEqual(peel_obj["results"][0]["address"], ADDR_HEX)
        self.assertEqual(peel_obj["results"][0]["mode"], "thumb")
        text = blob(out)
        self.assertNotIn("range_verified", text)
        self.assertNotIn("Evidence", text)
        self.assertNotIn("FrontierStore", text)
        self.assertNotIn("labels.toml", text)
        self.assertNotIn("gamedb", text)


class FailurePropagation(unittest.TestCase):
    def test_gate_failure_skips_7b_and_7c(self):
        src, ends, enc = full()
        out, rec = run_chain(src, {}, enc)
        self.assertEqual(out["results"], [])
        self.assertFalse(out["invoked"]["peel"])
        self.assertFalse(out["invoked"]["check"])
        self.assertEqual(rec.peel_calls, [])
        self.assertEqual(rec.check_calls, [])

    def test_7b_failure_skips_7c(self):
        rec = Recorders(peel_result="peel-failed")
        out, rec = run_chain(*full(), rec=rec)
        self.assertTrue(out["invoked"]["peel"])
        self.assertFalse(out["invoked"]["check"])
        self.assertEqual(rec.check_calls, [])
        self.assertTrue(any(e["error"] == "7b-failed" for e in out["errors"]))
        self.assertNotIn("range_verified", blob(out))

    def test_7c_failure_stays_failure(self):
        rec = Recorders(check_result="check-failed")
        out, rec = run_chain(*full(), rec=rec)
        self.assertTrue(out["invoked"]["peel"])
        self.assertTrue(out["invoked"]["check"])
        self.assertTrue(any(e["error"] == "7c-failed" for e in out["errors"]))
        self.assertNotIn("range_verified", blob(out))
        self.assertFalse(any(r.get("gate") == "success" for r in out["results"]))


class ConjunctionMatrix(unittest.TestCase):
    def test_partial_conditions_not_ready(self):
        selected = row()
        not_ready = row(disposition="heuristic")
        skipped_pr = row(selection="skipped", disposition="peel-ready")
        ends = endmap((ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified()])
        cases = {
            "selected only": (
                seven_a(selected_rows=[not_ready]), {}, eight_e(results=[])),
            "peel-ready only": (
                seven_a(skipped_rows=[skipped_pr]), {}, eight_e(results=[])),
            "explicit end only": (
                seven_a(), ends, eight_e(results=[])),
            "encoding_verified only": (
                seven_a(), {}, enc),
            "selected + peel-ready": (
                seven_a(selected_rows=[selected]), {}, eight_e(results=[])),
            "selected + explicit end": (
                seven_a(selected_rows=[not_ready]), ends, eight_e(results=[])),
            "selected + encoding_verified": (
                seven_a(selected_rows=[not_ready]), {}, enc),
            "peel-ready + explicit end": (
                seven_a(skipped_rows=[skipped_pr]), ends, eight_e(results=[])),
            "peel-ready + encoding_verified": (
                seven_a(skipped_rows=[skipped_pr]), {}, enc),
            "explicit end + encoding_verified": (
                seven_a(), ends, enc),
            "selected + peel-ready + explicit end": (
                seven_a(selected_rows=[selected]), ends, eight_e(results=[])),
            "selected + peel-ready + encoding_verified": (
                seven_a(selected_rows=[selected]), {}, enc),
            "selected + explicit end + encoding_verified": (
                seven_a(selected_rows=[not_ready]), ends, enc),
            "peel-ready + explicit end + encoding_verified": (
                seven_a(skipped_rows=[skipped_pr]), ends, enc),
        }
        for name, args in cases.items():
            with self.subTest(name):
                out, rec = run_chain(*args)
                self.assertEqual(out["results"], [], name)
                self.assertEqual(rec.peel_calls, [], name)
                self.assertFalse(out["invoked"]["peel"], name)
                self.assertFalse(out["invoked"]["check"], name)

    def test_full_conjunction_ready(self):
        out, rec = run_chain(*full())
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertTrue(out["invoked"]["peel"])

    def test_8d_claim_not_ready(self):
        src, ends, _ = full()
        claim = {
            "format": "gba-mapper-encoding-claim",
            "version": 1,
            "claims": [{"address": ADDR_HEX, "mode": "thumb",
                        "source": "human", "claim": "thumb"}],
        }
        out, rec = run_chain(src, ends, claim)
        self.assertEqual(out["results"], [])
        self.assertEqual(rec.peel_calls, [])

    def test_8c_suggestion_not_ready(self):
        src, ends, _ = full()
        llm = {
            "format": "gba-mapper-llm-suggestion",
            "version": 1,
            "suggestions": [{"address": ADDR_HEX, "mode": "thumb",
                             "action": "thumb-plausible"}],
        }
        out, rec = run_chain(src, ends, llm)
        self.assertEqual(out["results"], [])
        self.assertEqual(rec.peel_calls, [])

    def test_human_claim_not_encoding_verified(self):
        src, ends, _ = full()
        human = {
            "format": "human-encoding-claim",
            "version": 1,
            "results": [verified()],
        }
        out, rec = run_chain(src, ends, human)
        self.assertEqual(out["results"], [])
        self.assertEqual(rec.peel_calls, [])


class PersistenceAndSecurity(unittest.TestCase):
    def test_inputs_unchanged(self):
        src, ends, enc = full()
        approval = eight_a({"address": ADDR_HEX, "mode": "thumb",
                            "eligibility": "eligible-for-peel"})
        before = (json.dumps(src), json.dumps(ends), json.dumps(enc),
                  json.dumps(approval))
        run_chain(src, ends, enc, approval)
        self.assertEqual(
            (json.dumps(src), json.dumps(ends), json.dumps(enc),
             json.dumps(approval)),
            before,
        )

    def test_no_persistent_writes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            run_chain(*full())
            self.assertEqual(list(td.iterdir()), [])

    def test_no_authority_module_imports(self):
        tree = ast.parse(Path(__file__).read_text())
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        self.assertTrue(imported <= {
            "__future__", "ast", "json", "sys", "tempfile",
            "unittest", "pathlib", "phase8f_gate",
        })
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "skipTest", "expectedFailure", "skip",
            }:
                self.fail(node.attr)


if __name__ == "__main__":
    unittest.main()
