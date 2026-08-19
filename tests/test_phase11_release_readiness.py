"""Phase 11 final release-readiness validation. Not authority.

Validates the complete existing authority chain end-to-end using
synthetic JSON and injected 7B/7C fakes. Does not create, replace,
infer, promote, or rewrite any authority.
"""
from __future__ import annotations

import ast
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import phase8f_gate  # noqa: E402

ADDR = 0x08001200
ADDR_HEX = "0x08001200"
END_ARM = "0x08001280"
END_THUMB = "0x08001240"
_FORBIDDEN_FIELDS = {
    "winner", "selection", "disposition", "eligible-for-peel",
    "peel-ready", "end", "encoding_verified", "range_verified",
    "Evidence", "FrontierStore",
}


def row(*, addr=ADDR_HEX, mode="thumb", selection="selected",
        disposition="peel-ready"):
    return {"address": addr, "mode": mode, "selection": selection,
            "disposition": disposition, "deterministic": True}


def seven_a(*, selected_rows=None, skipped_rows=None):
    return {"selected": list(selected_rows or []),
            "skipped": list(skipped_rows or []),
            "unresolved": []}


def endmap(*triples):
    return {f"{addr}:{mode}": {"end": end} for addr, mode, end in triples}


def eight_e(*, results=None, deterministic=True,
            fmt="gba-mapper-encoding-verification", version=1):
    return {"format": fmt, "version": version,
            "run": {"deterministic": deterministic},
            "results": list(results or []), "errors": []}


def verified(*, addr=ADDR_HEX, mode="thumb", ok=True):
    return {"address": addr, "mode": mode, "encoding_verified": ok}


def eight_a(*items):
    return {"format": "gba-mapper-eligibility-approval",
            "version": 1, "approvals": list(items)}


class Recorder:
    def __init__(self, peel_result="peel-emitted", check_result="check-ok"):
        self.peel_calls: list = []
        self.check_calls: list = []
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


def chain(src, ends, enc, eight_a_obj=None, rec=None,
          execute_7b=True, execute_7c=True):
    rec = rec or Recorder()
    out = phase8f_gate.orchestrate(
        src, ends, enc, eight_a_obj,
        execute_7b=execute_7b, execute_7c=execute_7c,
        peel_runner=rec.peel, check_runner=rec.check,
    )
    return out, rec


def full_thumb():
    return (
        seven_a(selected_rows=[row(mode="thumb")]),
        endmap((ADDR_HEX, "thumb", END_THUMB)),
        eight_e(results=[verified(mode="thumb")]),
    )


# ── TEST A: end-to-end synthetic chain ────────────────────────────────────────

class EndToEndChain(unittest.TestCase):
    def test_full_authority_chain(self):
        src, ends, enc = full_thumb()
        rec = Recorder(peel_result="peel-emitted", check_result="check-ok")
        out, rec = chain(src, ends, enc, rec=rec)

        # gate ready
        self.assertEqual(len(out["results"]), 1)
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertEqual(out["results"][0]["mode"], "thumb")

        # 7B invoked with correct CandidateKey
        self.assertTrue(out["invoked"]["peel"])
        self.assertEqual(len(rec.peel_calls), 1)
        filtered = rec.peel_calls[0][0]
        self.assertEqual(len(filtered["selected"]), 1)
        self.assertEqual(filtered["selected"][0]["address"], ADDR_HEX)
        self.assertEqual(filtered["selected"][0]["mode"], "thumb")
        self.assertEqual(filtered["selected"][0]["selection"], "selected")

        # fake 7B returned peel-emitted
        peel_obj = rec.peel_calls[0][0]  # what was passed to check
        # check was invoked only after peel-emitted
        self.assertTrue(out["invoked"]["check"])
        self.assertEqual(len(rec.check_calls), 1)
        peel_result_obj, _ = rec.check_calls[0]
        self.assertEqual(peel_result_obj["results"][0]["result"], "peel-emitted")

        # output invariants — no forbidden authority fields
        text = json.dumps(out)
        for field in _FORBIDDEN_FIELDS:
            self.assertNotIn(f'"{field}"', text, field)


# ── TEST B: eligible-for-peel only (direct, no skipped-row indirection) ──────

class EligibleForPeelOnly(unittest.TestCase):
    def test_eligible_for_peel_not_peel_ready(self):
        # selected=selected but disposition=heuristic (NOT peel-ready)
        src = seven_a(selected_rows=[row(disposition="heuristic")])
        ends = endmap((ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified()])
        eligible = eight_a({"address": ADDR_HEX, "mode": "thumb",
                            "eligibility": "eligible-for-peel"})
        out, rec = chain(src, ends, enc, eligible)

        self.assertEqual(out["results"], [])
        self.assertFalse(out["invoked"]["peel"])
        self.assertFalse(out["invoked"]["check"])
        self.assertEqual(rec.peel_calls, [])
        self.assertEqual(rec.check_calls, [])
        self.assertTrue(any(e["error"] == "not-peel-ready"
                            for e in out["errors"]))


# ── TEST C: peel-ready direct — selection required ────────────────────────────

class PeelReadyRequiresSelection(unittest.TestCase):
    def test_peel_ready_without_selection_not_ready(self):
        # row is NOT selected; disposition is peel-ready; end + enc present
        src = seven_a(selected_rows=[
            row(selection="skipped", disposition="peel-ready"),
        ])
        ends = endmap((ADDR_HEX, "thumb", END_THUMB))
        enc = eight_e(results=[verified()])
        out, rec = chain(src, ends, enc)

        self.assertEqual(out["results"], [])
        self.assertFalse(out["invoked"]["peel"])
        self.assertTrue(any(e["error"] == "not-selected"
                            for e in out["errors"]))

    def test_peel_ready_with_selection_ready(self):
        src, ends, enc = full_thumb()
        out, rec = chain(src, ends, enc)
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertTrue(out["invoked"]["peel"])


# ── TEST D: cross-mode isolation ──────────────────────────────────────────────

class CrossModeIsolation(unittest.TestCase):
    def test_arm_ready_thumb_missing_end(self):
        src = seven_a(selected_rows=[row(mode="arm"), row(mode="thumb")])
        ends = endmap((ADDR_HEX, "arm", END_ARM))          # ARM only
        enc = eight_e(results=[verified(mode="arm"), verified(mode="thumb")])
        out, rec = chain(src, ends, enc)

        ready = {r["mode"] for r in out["results"] if r.get("gate") == "ready"}
        self.assertEqual(ready, {"arm"})
        self.assertTrue(any(e["mode"] == "thumb" and
                            e["error"] == "missing-explicit-end"
                            for e in out["errors"]))
        self.assertEqual(len(rec.peel_calls[0][0]["selected"]), 1)
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "arm")

    def test_thumb_ready_arm_missing_end(self):
        src = seven_a(selected_rows=[row(mode="arm"), row(mode="thumb")])
        ends = endmap((ADDR_HEX, "thumb", END_THUMB))      # Thumb only
        enc = eight_e(results=[verified(mode="arm"), verified(mode="thumb")])
        out, rec = chain(src, ends, enc)

        ready = {r["mode"] for r in out["results"] if r.get("gate") == "ready"}
        self.assertEqual(ready, {"thumb"})
        self.assertTrue(any(e["mode"] == "arm" and
                            e["error"] == "missing-explicit-end"
                            for e in out["errors"]))
        self.assertEqual(len(rec.peel_calls[0][0]["selected"]), 1)
        self.assertEqual(rec.peel_calls[0][0]["selected"][0]["mode"], "thumb")


# ── TEST E: 8E format / version / determinism matrix ─────────────────────────

class EightEArtifactMatrix(unittest.TestCase):
    def _bad_enc(self, enc):
        src, ends, _ = full_thumb()
        out, rec = chain(src, ends, enc)
        self.assertEqual(out["results"], [])
        self.assertFalse(out["invoked"]["peel"])
        self.assertFalse(out["invoked"]["check"])
        self.assertTrue(any(e["error"] == "invalid-encoding-verification"
                            for e in out["errors"]))

    def test_wrong_format(self):
        self._bad_enc(eight_e(results=[verified()], fmt="wrong-format"))

    def test_wrong_version(self):
        self._bad_enc(eight_e(results=[verified()], version=2))

    def test_deterministic_false(self):
        self._bad_enc(eight_e(results=[verified()], deterministic=False))


# ── TEST F: output invariants ─────────────────────────────────────────────────

class OutputInvariants(unittest.TestCase):
    def test_forbidden_fields_absent_from_ready_output(self):
        src, ends, enc = full_thumb()
        out, _ = chain(src, ends, enc)
        text = json.dumps(out)
        for field in _FORBIDDEN_FIELDS:
            self.assertNotIn(f'"{field}"', text, f'found "{field}" in output')

    def test_forbidden_fields_absent_from_gate_only_output(self):
        src, ends, enc = full_thumb()
        out = phase8f_gate.gate(src, ends, enc)
        text = json.dumps(out)
        for field in _FORBIDDEN_FIELDS:
            self.assertNotIn(f'"{field}"', text, f'found "{field}" in output')


# ── TEST G: input immutability ────────────────────────────────────────────────

class InputImmutability(unittest.TestCase):
    def test_inputs_byte_equivalent_after_chain(self):
        src, ends, enc = full_thumb()
        approval = eight_a({"address": ADDR_HEX, "mode": "thumb",
                            "eligibility": "eligible-for-peel"})
        snapshots = tuple(json.dumps(x) for x in (src, ends, enc, approval))
        chain(src, ends, enc, approval)
        self.assertEqual(
            tuple(json.dumps(x) for x in (src, ends, enc, approval)),
            snapshots,
        )


# ── TEST H: security / import invariants ──────────────────────────────────────

class SecurityAndImports(unittest.TestCase):
    def test_import_whitelist(self):
        tree = ast.parse(Path(__file__).read_text())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        allowed = {
            "__future__", "ast", "json", "sys", "unittest",
            "pathlib", "phase8f_gate",
        }
        self.assertTrue(imported <= allowed,
                        f"unexpected imports: {imported - allowed}")

    def test_no_skip_or_xfail(self):
        tree = ast.parse(Path(__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {
                "skipTest", "expectedFailure", "skip",
            }:
                self.fail(f"found disallowed attribute: {node.attr}")


if __name__ == "__main__":
    unittest.main()
