"""Phase 8F gate: orchestration only. Not authority."""
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

import phase8f_gate  # noqa: E402

CLI = TOOLS / "phase8f_gate.py"
ADDR = 0x08001200
ADDR_HEX = "0x08001200"
END_HEX = "0x08001240"
ARM_MODE = "arm"
THUMB_MODE = "thumb"


def selected_row(*, addr=ADDR_HEX, mode=THUMB_MODE, selection="selected",
                 disposition="peel-ready", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "selection": selection,
        "disposition": disposition,
        "deterministic": True,
        "sources": ["modeflow"],
        "classes": ["control-flow"],
    }
    if extra:
        row.update(extra)
    return row


def skipped_row(*, addr=ADDR_HEX, mode=THUMB_MODE, disposition="heuristic", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "selection": "skipped",
        "disposition": disposition,
        "deterministic": False,
    }
    if extra:
        row.update(extra)
    return row


def phase7a(*, selected=None, skipped=None, unresolved=None):
    return {
        "selected": list(selected or []),
        "skipped": list(skipped or []),
        "unresolved": list(unresolved or []),
    }


def ends_map(*pairs):
    out = {}
    for addr, mode, end in pairs:
        out[f"{addr}:{mode}"] = {"end": end}
    return out


def encoding(*, results=None, deterministic=True, extra_run=None):
    run = {"deterministic": deterministic, "decoder_version": "8e-v1"}
    if extra_run:
        run.update(extra_run)
    return {
        "format": "gba-mapper-encoding-verification",
        "version": 1,
        "run": run,
        "results": list(results or []),
        "errors": [],
    }


def enc_ok(*, addr=ADDR_HEX, mode=THUMB_MODE):
    return {"address": addr, "mode": mode, "encoding_verified": True}


def eight_a(*items):
    return {
        "format": "gba-mapper-eligibility-approval",
        "version": 1,
        "run": {"deterministic": False},
        "approvals": list(items),
        "errors": [],
    }


def approval(*, addr=ADDR_HEX, mode=THUMB_MODE, eligibility="eligible-for-peel"):
    return {"address": addr, "mode": mode, "eligibility": eligibility}


class HappyPath(unittest.TestCase):
    def test_all_gates_ready(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
        )
        self.assertEqual(out["format"], "gba-mapper-phase8f-result")
        self.assertEqual(out["version"], 1)
        self.assertTrue(out["run"]["deterministic"])
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertEqual(out["results"][0]["mode"], THUMB_MODE)
        self.assertFalse(out["invoked"]["peel"])
        self.assertNotIn("encoding_verified", out["results"][0])
        self.assertNotIn("end", out["results"][0])
        self.assertNotIn("range_verified", json.dumps(out))
        blob = json.dumps(out)
        for field in ("winner", "selection", "disposition", "eligible-for-peel"):
            self.assertNotIn(f'"{field}"', blob)

    def test_ready_does_not_imply_7b_success(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
        )
        self.assertEqual(out["results"][0]["gate"], "ready")
        self.assertFalse(out["invoked"]["peel"])
        self.assertFalse(out["invoked"]["check"])


class GateFailures(unittest.TestCase):
    def test_not_peel_ready(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row(disposition="heuristic")]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
        )
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"][0]["error"], "not-peel-ready")

    def test_not_selected(self):
        out = phase8f_gate.gate(
            phase7a(skipped=[skipped_row(disposition="peel-ready")]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
        )
        self.assertEqual([r for r in out["results"] if r.get("gate") == "ready"], [])
        self.assertIn("not-selected", {e["error"] for e in out["errors"]})

    def test_eligible_for_peel_only_no_7b(self):
        calls = []
        out = phase8f_gate.orchestrate(
            phase7a(skipped=[skipped_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            eight_a(approval()),
            execute_7b=True,
            peel_runner=lambda *a, **k: calls.append(a) or {"results": []},
        )
        self.assertEqual(calls, [])
        self.assertFalse(out["invoked"]["peel"])
        self.assertEqual(out["results"], [])

    def test_missing_explicit_end(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            {},
            encoding(results=[enc_ok()]),
        )
        self.assertEqual(out["errors"][0]["error"], "missing-explicit-end")

    def test_malformed_end(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            {f"{ADDR_HEX}:{THUMB_MODE}": {"end": "nope"}},
            encoding(results=[enc_ok()]),
        )
        self.assertTrue(any(e["error"] == "invalid-explicit-end" for e in out["errors"]))
        self.assertEqual(out["results"], [])

    def test_missing_encoding(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            None,
        )
        self.assertEqual(out["errors"][0]["error"], "missing-encoding-verification")

    def test_deterministic_false(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()], deterministic=False),
        )
        self.assertTrue(any(e["error"] == "invalid-encoding-verification" for e in out["errors"]))
        self.assertEqual(out["results"], [])

    def test_key_mismatch(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok(addr="0x08009999")]),
        )
        self.assertEqual(out["errors"][0]["error"], "encoding-not-verified")

    def test_encoding_false(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[{"address": ADDR_HEX, "mode": THUMB_MODE,
                               "encoding_verified": False}]),
        )
        self.assertEqual(out["errors"][0]["error"], "encoding-not-verified")

    def test_conflicting_8e(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[
                enc_ok(),
                {"address": ADDR_HEX, "mode": THUMB_MODE, "encoding_verified": False},
            ]),
        )
        self.assertTrue(any(e["error"] == "conflicting-verification" for e in out["errors"]))
        self.assertEqual(out["results"], [])

    def test_address_only(self):
        out = phase8f_gate.gate(
            phase7a(selected=[{"address": ADDR_HEX, "selection": "selected",
                               "disposition": "peel-ready"}]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
        )
        self.assertEqual(out["errors"][0]["error"], "address-only")

    def test_invalid_mode(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row(mode="invalid")]),
            ends_map((ADDR_HEX, "invalid", END_HEX)),
            encoding(results=[enc_ok(mode="invalid")]),
        )
        self.assertEqual(out["errors"][0]["error"], "invalid-key")


class Independence(unittest.TestCase):
    def test_same_address_arm_thumb_independent(self):
        out = phase8f_gate.gate(
            phase7a(selected=[
                selected_row(mode=THUMB_MODE),
                selected_row(mode=ARM_MODE),
            ]),
            ends_map(
                (ADDR_HEX, THUMB_MODE, END_HEX),
            ),
            encoding(results=[enc_ok(mode=THUMB_MODE), enc_ok(mode=ARM_MODE)]),
        )
        ready = {(r["address"], r["mode"]) for r in out["results"]}
        self.assertIn((ADDR_HEX, THUMB_MODE), ready)
        self.assertNotIn((ADDR_HEX, ARM_MODE), ready)
        self.assertTrue(any(
            e["mode"] == ARM_MODE and e["error"] == "missing-explicit-end"
            for e in out["errors"]
        ))


class EightA(unittest.TestCase):
    def test_8a_absent_still_passes(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            None,
        )
        self.assertEqual(out["results"][0]["gate"], "ready")

    def test_8a_mismatch(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            eight_a(approval(eligibility="eligible-for-review")),
        )
        self.assertEqual(out["results"], [])
        self.assertEqual(out["errors"][0]["error"], "eligibility-mismatch")

    def test_eligible_for_peel_is_not_peel_ready(self):
        out = phase8f_gate.gate(
            phase7a(selected=[selected_row(disposition="heuristic")]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            eight_a(approval()),
        )
        self.assertEqual(out["errors"][0]["error"], "not-peel-ready")
        self.assertEqual(out["results"], [])


class Immutability(unittest.TestCase):
    def test_inputs_unchanged(self):
        src = phase7a(selected=[selected_row()])
        ends = ends_map((ADDR_HEX, THUMB_MODE, END_HEX))
        enc = encoding(results=[enc_ok()])
        before = (json.dumps(src), json.dumps(ends), json.dumps(enc))
        phase8f_gate.gate(src, ends, enc)
        self.assertEqual((json.dumps(src), json.dumps(ends), json.dumps(enc)), before)
        self.assertEqual(src["selected"][0]["selection"], "selected")
        self.assertEqual(src["selected"][0]["disposition"], "peel-ready")


class Invocation(unittest.TestCase):
    def test_7b_only_after_ready_and_no_write_labels(self):
        calls = []

        def fake_peel(filtered, ends):
            calls.append((filtered, ends))
            return {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "peel-emitted",
            }]}

        out = phase8f_gate.orchestrate(
            phase7a(selected=[
                selected_row(),
                selected_row(addr="0x08001300", disposition="heuristic"),
            ]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX), ("0x08001300", THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok(), enc_ok(addr="0x08001300")]),
            execute_7b=True,
            peel_runner=fake_peel,
        )
        self.assertTrue(out["invoked"]["peel"])
        self.assertEqual(len(calls[0][0]["selected"]), 1)
        self.assertEqual(calls[0][0]["selected"][0]["address"], ADDR_HEX)

    def test_7b_failure_propagates(self):
        def fake_peel(filtered, ends):
            return {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "peel-failed",
            }]}

        out = phase8f_gate.orchestrate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            execute_7b=True,
            peel_runner=fake_peel,
        )
        self.assertTrue(any(e["error"] == "7b-failed" for e in out["errors"]))
        self.assertFalse(out["invoked"]["check"])

    def test_7c_only_after_peel_emitted(self):
        checks = []

        def fake_peel(filtered, ends):
            return {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "peel-emitted",
            }]}

        def fake_check(peel_obj, ends):
            checks.append(peel_obj)
            return {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "range-recorded",
            }]}

        out = phase8f_gate.orchestrate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            execute_7b=True,
            execute_7c=True,
            peel_runner=fake_peel,
            check_runner=fake_check,
        )
        self.assertEqual(len(checks), 1)
        self.assertTrue(out["invoked"]["check"])
        self.assertNotIn("range_verified", json.dumps(out))

    def test_7c_not_invoked_if_7b_fails(self):
        checks = []
        out = phase8f_gate.orchestrate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            execute_7b=True,
            execute_7c=True,
            peel_runner=lambda *a, **k: {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "peel-failed",
            }]},
            check_runner=lambda *a, **k: checks.append(1) or {"results": []},
        )
        self.assertEqual(checks, [])
        self.assertTrue(any(e["error"] == "7c-gate-failed" for e in out["errors"]))

    def test_7c_failure_propagates(self):
        out = phase8f_gate.orchestrate(
            phase7a(selected=[selected_row()]),
            ends_map((ADDR_HEX, THUMB_MODE, END_HEX)),
            encoding(results=[enc_ok()]),
            execute_7b=True,
            execute_7c=True,
            peel_runner=lambda *a, **k: {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "peel-emitted",
            }]},
            check_runner=lambda *a, **k: {"results": [{
                "address": ADDR_HEX, "mode": THUMB_MODE, "result": "check-failed",
            }]},
        )
        self.assertTrue(any(e["error"] == "7c-failed" for e in out["errors"]))


class CliAndSecurity(unittest.TestCase):
    def test_cli_gate_only_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            ends = td / "ends.json"
            enc = td / "enc.json"
            src.write_text(json.dumps(phase7a(selected=[selected_row()])))
            ends.write_text(json.dumps(ends_map((ADDR_HEX, THUMB_MODE, END_HEX))))
            enc.write_text(json.dumps(encoding(results=[enc_ok()])))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--ends", str(ends),
                 "--encoding", str(enc)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["results"][0]["gate"], "ready")
            self.assertFalse(result["invoked"]["peel"])
            self.assertFalse((td / "labels.toml").exists())
            original = json.loads(src.read_text())
            self.assertEqual(original["selected"][0]["selection"], "selected")

    def test_malformed_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            bad = td / "bad.json"
            ends = td / "ends.json"
            enc = td / "enc.json"
            bad.write_text("{")
            ends.write_text("{}")
            enc.write_text("{}")
            proc = subprocess.run(
                [sys.executable, str(CLI), str(bad), "--ends", str(ends),
                 "--encoding", str(enc)],
                cwd=td, capture_output=True, text=True,
            )
            self.assertNotEqual(proc.returncode, 0)

    def test_production_boundaries(self):
        src = inspect.getsource(phase8f_gate)
        for token in (
            "llm_suggest", "llm_providers", "encoding_decoder",
            "openai", "urllib", "socket", "requests",
            "Ghidra", "import ghidra", "baserom", "GBA_ROM",
            "record_range", "FrontierStore", "write_labels=True",
            "--force-boundary", "shell=True",
        ):
            self.assertNotIn(token, src)


if __name__ == "__main__":
    unittest.main()
