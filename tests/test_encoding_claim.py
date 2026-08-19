"""Phase 8D encoding-claim writer: advisory only. Not verification."""
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

import encoding_claim  # noqa: E402

CLI = TOOLS / "encoding_claim.py"
ADDR = 0x08001200
ADDR_HEX = "0x08001200"
ARM_ADDR = "0x08001400"


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


def claim_input(*items):
    return {
        "format": "gba-mapper-encoding-claim-input",
        "version": 1,
        "claims": list(items),
    }


def claim_entry(*, addr=ADDR_HEX, mode="thumb", source="human", claim=None, **kw):
    d = {
        "address": addr,
        "mode": mode,
        "source": source,
        "claim": claim if claim is not None else mode,
    }
    d.update(kw)
    return d


def llm_suggestion(*items):
    return {
        "format": "gba-mapper-llm-suggestion",
        "version": 1,
        "run": {"provider": "fake", "deterministic": False},
        "suggestions": list(items),
        "errors": [],
    }


def llm_item(*, addr=ADDR_HEX, mode="thumb", action="thumb-plausible", **kw):
    d = {
        "address": addr,
        "mode": mode,
        "action": action,
        "rationale": "fixture",
        "provider": "fake",
        "model": "fixture",
        "prompt_version": "7db-v1",
        "input_hash": "abc",
        "deterministic": False,
    }
    d.update(kw)
    return d


class ValidClaims(unittest.TestCase):
    def test_arm_and_thumb_accepted(self):
        rows = [
            skipped(addr=ARM_ADDR, mode="arm", disposition="conflicted"),
            skipped(disposition="heuristic"),
        ]
        inp = claim_input(
            claim_entry(addr=ARM_ADDR, mode="arm", source="human", claim="arm"),
            claim_entry(source="ghidra", claim="thumb"),
        )
        out = encoding_claim.build_claims(doc(skipped=rows), inp)
        self.assertEqual(len(out["claims"]), 2)
        by_key = {(c["address"], c["mode"], c["source"]) for c in out["claims"]}
        self.assertIn((ARM_ADDR, "arm", "human"), by_key)
        self.assertIn((ADDR_HEX, "thumb", "ghidra"), by_key)
        self.assertFalse(out["run"]["deterministic"])
        self.assertNotIn("encoding_verified", json.dumps(out))

    def test_arm_thumb_independent(self):
        rows = [skipped(addr=ARM_ADDR, mode="arm", disposition="conflicted"), skipped()]
        inp = claim_input(
            claim_entry(addr=ARM_ADDR, mode="arm", claim="arm"),
            claim_entry(source="human", claim="thumb"),
        )
        out = encoding_claim.build_claims(doc(skipped=rows), inp)
        self.assertEqual(len(out["claims"]), 2)
        self.assertNotIn("winner", json.dumps(out))


class InvalidClaims(unittest.TestCase):
    def _one(self, entry, *, rows=None):
        rows = rows or [skipped()]
        return encoding_claim.build_claims(doc(skipped=rows), claim_input(entry))

    def test_address_only_rejected(self):
        out = self._one({"address": ADDR_HEX, "source": "human", "claim": "thumb"})
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "address-only")

    def test_invalid_mode_rejected(self):
        out = self._one(claim_entry(mode="invalid", claim="invalid"))
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "invalid-claim-key")

    def test_mode_mismatch_rejected(self):
        out = self._one(claim_entry(mode="thumb", claim="arm"))
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "mode-mismatch")

    def test_unresolved_rejected(self):
        inp = claim_input(claim_entry())
        out = encoding_claim.build_claims(
            doc(unresolved=[{"type": "indirect-branch", "from_addr": "0x08000f00"}]),
            inp,
        )
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "unknown-candidate")

    def test_deterministic_true_rejected(self):
        out = self._one(claim_entry(deterministic=True))
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "deterministic-rejected")


class ForbiddenFields(unittest.TestCase):
    def _forbidden(self, field, value):
        entry = claim_entry(**{field: value})
        out = encoding_claim.build_claims(doc(skipped=[skipped()]), claim_input(entry))
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "forbidden-field")
        self.assertNotIn(field, json.dumps(out["claims"]))

    def test_encoding_verified_rejected(self):
        self._forbidden("encoding_verified", True)

    def test_verified_rejected(self):
        self._forbidden("verified", True)

    def test_winner_rejected(self):
        self._forbidden("winner", "thumb")

    def test_selection_rejected(self):
        self._forbidden("selection", "selected")

    def test_end_rejected(self):
        self._forbidden("end", "0x08001240")

    def test_suggested_end_rejected(self):
        self._forbidden("suggested_end", "0x08001240")

    def test_eligible_for_peel_rejected(self):
        self._forbidden("eligible-for-peel", True)


class SourceSemantics(unittest.TestCase):
    def test_human_claim_non_verified(self):
        out = encoding_claim.build_claims(
            doc(skipped=[skipped()]),
            claim_input(claim_entry(source="human")),
        )
        c = out["claims"][0]
        self.assertEqual(c["source"], "human")
        self.assertNotIn("encoding_verified", c)
        self.assertNotIn("verified", c)

    def test_ghidra_claim_advisory(self):
        out = encoding_claim.build_claims(
            doc(skipped=[skipped()]),
            claim_input(claim_entry(source="ghidra")),
        )
        self.assertEqual(out["claims"][0]["source"], "ghidra")
        self.assertNotIn("encoding_verified", json.dumps(out))

    def test_llm_claim_advisory_from_8c_json(self):
        rows = [
            skipped(addr=ARM_ADDR, mode="arm", disposition="conflicted"),
            skipped(),
        ]
        llm = llm_suggestion(
            llm_item(addr=ARM_ADDR, mode="arm", action="arm-plausible"),
            llm_item(action="thumb-plausible"),
            llm_item(action="possible-data"),
        )
        out = encoding_claim.build_claims(doc(skipped=rows), llm_input=llm)
        self.assertEqual(len(out["claims"]), 2)
        sources = {c["source"] for c in out["claims"]}
        self.assertEqual(sources, {"llm"})
        self.assertNotIn("encoding_verified", json.dumps(out))

    def test_llm_mode_mismatch_rejected(self):
        llm = llm_suggestion(llm_item(mode="thumb", action="arm-plausible"))
        out = encoding_claim.build_claims(doc(skipped=[skipped()]), llm_input=llm)
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "mode-mismatch")


class Immutability(unittest.TestCase):
    def test_disposition_not_rewritten(self):
        row = skipped(disposition="heuristic")
        src = doc(skipped=[row])
        before = json.dumps(src)
        encoding_claim.build_claims(src, claim_input(claim_entry()))
        self.assertEqual(json.dumps(src), before)
        self.assertEqual(src["skipped"][0]["disposition"], "heuristic")
        self.assertEqual(src["skipped"][0]["selection"], "skipped")

    def test_no_candidate_mint_or_winner(self):
        inp = claim_input(claim_entry(addr="0x08009999", mode="arm", claim="arm"))
        out = encoding_claim.build_claims(doc(skipped=[skipped()]), inp)
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "unknown-candidate")
        self.assertNotIn("winner", json.dumps(out))


class MalformedAndCli(unittest.TestCase):
    def test_malformed_claims_fail_closed(self):
        out = encoding_claim.build_claims(doc(skipped=[skipped()]), {"bad": True})
        self.assertEqual(out["claims"], [])
        self.assertEqual(out["errors"][0]["error"], "malformed-claims")

    def test_cli_output_and_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            claims = td / "claims.json"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            claims.write_text(json.dumps(claim_input(claim_entry())))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--claims", str(claims)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["format"], "gba-mapper-encoding-claim")
            self.assertFalse(result["run"]["deterministic"])
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("gamedb*")), [])
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            original = json.loads(src.read_text())
            self.assertEqual(original["skipped"][0]["selection"], "skipped")
            out = td / "out.json"
            subprocess.run(
                [sys.executable, str(CLI), str(src), "--claims", str(claims),
                 "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertTrue(out.is_file())
            self.assertEqual(json.loads(src.read_text()), original)


class Boundary(unittest.TestCase):
    def test_source_has_no_pipeline_or_external_tools(self):
        src = inspect.getsource(encoding_claim)
        for token in (
            "run_peel", "run_check", "record_range", "promote_encoding",
            "wire", "llm_suggest", "llm_providers", "ends_approve",
            "eligibility_approve", "review_select", "frontier", "evidence",
            "subprocess", "urllib", "openai",
        ):
            self.assertNotIn(token, src)
        for token in ("import ghidra", "subprocess"):
            self.assertNotIn(token, src)

    def test_no_rom_paths_in_tool(self):
        src = inspect.getsource(encoding_claim)
        self.assertNotIn("baserom", src)
        self.assertNotIn("GBA_ROM", src)


if __name__ == "__main__":
    unittest.main()
