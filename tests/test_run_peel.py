"""PeelRunner: explicit-end adapter only. Not peel internals or verification."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import run_peel  # noqa: E402

CLI = TOOLS / "run_peel.py"
ADDR = 0x08001200
ADDR_HEX = "0x08001200"
END_HEX = "0x08001240"
FAKE_PEEL = r"""
import json, os, sys
from pathlib import Path
log = Path(os.environ["PEEL_LOG"])
rows = json.loads(log.read_text()) if log.exists() else []
rows.append(sys.argv[1:])
log.write_text(json.dumps(rows))
sys.exit(int(os.environ.get("PEEL_EXIT", "0")))
"""


def selected_row(*, addr=ADDR_HEX, mode="thumb", disposition="peel-ready",
                 selection="selected", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "selection": selection,
        "disposition": disposition,
        "evidence_items": [{"type": "bl-target", "source": "modeflow"}],
        "classes": ["control-flow"],
        "sources": ["modeflow"],
        "deterministic": True,
    }
    if extra:
        row.update(extra)
    return row


def selection_doc(selected=None, skipped=None, unresolved=None):
    return {
        "selected": list(selected or []),
        "skipped": list(skipped or []),
        "unresolved": list(unresolved or []),
    }


def ends_for(addr=ADDR_HEX, mode="thumb", end=END_HEX):
    return {f"{addr}:{mode}": {"end": end}}


class FakePeel(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        self.peel = self.td / "fake_peel.py"
        self.peel.write_text(FAKE_PEEL)
        self.log = self.td / "peel.log"
        self.env_peel_exit = "0"

    def tearDown(self):
        self._td.cleanup()

    def runner(self, **kwargs):
        return run_peel.PeelRunner(self.peel, **kwargs)

    def run_sel(self, doc, ends, **kwargs):
        env = os_environ_patch({"PEEL_LOG": str(self.log), "PEEL_EXIT": self.env_peel_exit})
        with env:
            r = self.runner(**kwargs)
            out = r.run(doc, ends)
        return r, out

    def peel_argv(self):
        if not self.log.exists():
            return []
        return json.loads(self.log.read_text())


class os_environ_patch:
    def __init__(self, updates):
        self.updates = updates
        self.old = {}

    def __enter__(self):
        import os
        for k, v in self.updates.items():
            self.old[k] = os.environ.get(k)
            os.environ[k] = v
        return os.environ

    def __exit__(self, *exc):
        import os
        for k, prev in self.old.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


class Selection(FakePeel):
    def test_selected_peel_ready_executed(self):
        _, out = self.run_sel(
            selection_doc([selected_row()]),
            ends_for(),
        )
        self.assertEqual(len(out["results"]), 1)
        self.assertEqual(out["results"][0]["result"], "peel-emitted")
        self.assertEqual(out["results"][0]["exit_code"], 0)
        self.assertEqual(len(self.peel_argv()), 1)

    def test_skipped_never_executed(self):
        doc = selection_doc(
            skipped=[selected_row(disposition="heuristic", selection="skipped")],
        )
        _, out = self.run_sel(doc, ends_for())
        self.assertEqual(out["results"], [])
        self.assertEqual(self.peel_argv(), [])

    def test_unresolved_never_executed(self):
        unresolved = [{
            "type": "indirect-branch",
            "source": "modeflow",
            "from_addr": "0x08001000",
        }]
        _, out = self.run_sel(
            selection_doc(unresolved=unresolved),
            ends_for(),
        )
        self.assertEqual(out["unresolved"], unresolved)
        self.assertNotIn("selection", out["unresolved"][0])
        self.assertEqual(self.peel_argv(), [])

    def test_conflicted_never_executed(self):
        row = selected_row(disposition="conflicted")
        _, out = self.run_sel(selection_doc([row]), ends_for())
        self.assertEqual(out["results"], [])
        self.assertEqual(out["skipped"][0]["result"], "not-executed")
        self.assertEqual(out["skipped"][0]["reason"], "invalid-selection")
        self.assertEqual(self.peel_argv(), [])

    def test_non_peel_ready_selected_rejected(self):
        row = selected_row(disposition="agreed-seed")
        _, out = self.run_sel(selection_doc([row]), ends_for())
        self.assertEqual(out["skipped"][0]["reason"], "invalid-selection")
        self.assertEqual(self.peel_argv(), [])


class End(FakePeel):
    def test_explicit_end_passed_unchanged(self):
        _, out = self.run_sel(selection_doc([selected_row()]), ends_for())
        argv = self.peel_argv()[0]
        self.assertEqual(argv[argv.index("--end") + 1], END_HEX)
        self.assertEqual(out["results"][0]["end"], END_HEX)

    def test_missing_end_not_executed(self):
        _, out = self.run_sel(selection_doc([selected_row()]), {})
        self.assertEqual(out["results"], [])
        self.assertEqual(out["skipped"][0]["reason"], "missing-explicit-end")
        self.assertEqual(self.peel_argv(), [])

    def test_malformed_end_not_executed(self):
        for bad in (None, "not-hex", "-1", "0xZZ"):
            with self.subTest(bad=bad):
                self.log.unlink(missing_ok=True)
                _, out = self.run_sel(
                    selection_doc([selected_row()]),
                    {f"{ADDR_HEX}:thumb": {"end": bad}},
                )
                self.assertEqual(out["skipped"][0]["result"], "not-executed")
                self.assertEqual(out["skipped"][0]["reason"], "malformed-end")
                self.assertEqual(self.peel_argv(), [])

    def test_end_le_start_not_executed(self):
        _, out = self.run_sel(
            selection_doc([selected_row()]),
            ends_for(end=ADDR_HEX),
        )
        self.assertEqual(out["skipped"][0]["reason"], "malformed-end")
        self.assertEqual(self.peel_argv(), [])

    def test_arm_thumb_independent_ends(self):
        doc = selection_doc([
            selected_row(mode="arm"),
            selected_row(mode="thumb"),
        ])
        ends = {
            f"{ADDR_HEX}:arm": {"end": "0x08001280"},
            f"{ADDR_HEX}:thumb": {"end": "0x08001240"},
        }
        _, out = self.run_sel(doc, ends)
        self.assertEqual(len(out["results"]), 2)
        modes = {(r["mode"], r["end"]) for r in out["results"]}
        self.assertEqual(modes, {("arm", "0x08001280"), ("thumb", "0x08001240")})
        self.assertEqual(len(self.peel_argv()), 2)

    def test_address_only_end_not_applied(self):
        _, out = self.run_sel(
            selection_doc([selected_row()]),
            {ADDR_HEX: {"end": END_HEX}},
        )
        self.assertEqual(out["skipped"][0]["reason"], "address-only-end-mapping")
        self.assertEqual(self.peel_argv(), [])

    def test_no_end_from_ghidra_size(self):
        row = selected_row(extra={"size": 64, "ghidra_size": 64})
        _, out = self.run_sel(selection_doc([row]), {})
        self.assertEqual(out["skipped"][0]["reason"], "missing-explicit-end")
        self.assertEqual(self.peel_argv(), [])

    def test_no_end_from_next_candidate(self):
        nxt = "0x08001300"
        doc = selection_doc([
            selected_row(),
            selected_row(addr=nxt, extra={"evidence_items": [{"type": "gap"}]}),
        ])
        ends = ends_for(addr=nxt, end="0x08001340")
        _, out = self.run_sel(doc, ends)
        reasons = {r["address"]: r.get("reason") for r in out["skipped"]}
        self.assertEqual(reasons[ADDR_HEX], "missing-explicit-end")
        self.assertTrue(any(r["address"] == nxt for r in out["results"]))
        self.assertEqual(len(self.peel_argv()), 1)

    def test_no_end_from_gap_or_recommended(self):
        row = selected_row(extra={
            "recommendedEnd": "0x08001400",
            "end": "0x08001400",
            "gap": True,
        })
        _, out = self.run_sel(selection_doc([row]), {})
        self.assertEqual(out["skipped"][0]["reason"], "missing-explicit-end")
        self.assertEqual(self.peel_argv(), [])

    def test_candidate_end_field_ignored_when_mapping_present(self):
        row = selected_row(extra={"end": "0x0800FFFF", "size": 8})
        _, out = self.run_sel(selection_doc([row]), ends_for())
        self.assertEqual(out["results"][0]["end"], END_HEX)
        argv = self.peel_argv()[0]
        self.assertEqual(argv[argv.index("--end") + 1], END_HEX)


class Invocation(FakePeel):
    def test_start_end_mode_and_no_labels_default(self):
        _, _ = self.run_sel(selection_doc([selected_row()]), ends_for())
        argv = self.peel_argv()[0]
        self.assertEqual(argv[argv.index("--start") + 1], ADDR_HEX)
        self.assertEqual(argv[argv.index("--end") + 1], END_HEX)
        self.assertEqual(argv[argv.index("--mode") + 1], "thumb")
        self.assertIn("--no-labels", argv)
        self.assertNotIn("--force-boundary", argv)

    def test_force_boundary_only_when_requested(self):
        _, _ = self.run_sel(
            selection_doc([selected_row()]), ends_for(), force_boundary=True,
        )
        argv = self.peel_argv()[0]
        self.assertIn("--force-boundary", argv)
        self.assertIn("--no-labels", argv)

    def test_write_labels_omits_no_labels(self):
        _, _ = self.run_sel(
            selection_doc([selected_row()]), ends_for(), write_labels=True,
        )
        argv = self.peel_argv()[0]
        self.assertNotIn("--no-labels", argv)


class Failure(FakePeel):
    def test_exit_1_peel_failed(self):
        self.env_peel_exit = "1"
        _, out = self.run_sel(selection_doc([selected_row()]), ends_for())
        self.assertEqual(out["results"][0]["result"], "peel-failed")
        self.assertEqual(out["results"][0]["exit_code"], 1)
        self.assertEqual(out["unresolved"], [])

    def test_exit_2_peel_failed(self):
        self.env_peel_exit = "2"
        _, out = self.run_sel(selection_doc([selected_row()]), ends_for())
        self.assertEqual(out["results"][0]["result"], "peel-failed")
        self.assertEqual(out["results"][0]["exit_code"], 2)

    def test_failure_does_not_delete_or_verify(self):
        self.env_peel_exit = "1"
        row = selected_row()
        items = list(row["evidence_items"])
        _, out = self.run_sel(selection_doc([row]), ends_for())
        self.assertEqual(row["evidence_items"], items)
        self.assertEqual(row["disposition"], "peel-ready")
        self.assertNotIn("status", out)
        self.assertNotIn("winner", out["results"][0])
        self.assertEqual(len(out["results"]), 1)


class Boundary(FakePeel):
    def test_no_verification_fields_or_peel_attempt(self):
        _, out = self.run_sel(selection_doc([selected_row()]), ends_for())
        blob = json.dumps(out)
        for forbidden in (
            "range_verified", "encoding_verified", "RANGE_VERIFIED",
            "ENCODING_VERIFIED", "winner", "confidence", "score",
            "peel-attempt", "record_range", "promote_encoding",
        ):
            self.assertNotIn(forbidden, blob)
        self.assertNotIn("status", out)
        self.assertNotIn("status", out["results"][0])

    def test_evidence_not_mutated(self):
        row = selected_row()
        original = json.loads(json.dumps(row))
        self.run_sel(selection_doc([row]), ends_for())
        self.assertEqual(row, original)

    def test_same_address_arm_thumb_stay_separate(self):
        doc = selection_doc([
            selected_row(mode="arm"),
            selected_row(mode="thumb"),
        ])
        _, out = self.run_sel(doc, {
            f"{ADDR_HEX}:thumb": {"end": END_HEX},
        })
        self.assertEqual(len(out["results"]), 1)
        self.assertEqual(out["results"][0]["mode"], "thumb")
        self.assertEqual(out["skipped"][0]["mode"], "arm")
        self.assertEqual(out["skipped"][0]["reason"], "missing-explicit-end")


class FilesystemAndCli(FakePeel):
    def test_default_does_not_write_artifacts(self):
        _, _ = self.run_sel(selection_doc([selected_row()]), ends_for())
        self.assertFalse((self.td / "labels.toml").exists())
        self.assertEqual(list(self.td.glob("*.evidence.jsonl")), [])
        self.assertEqual(list(self.td.glob("gamedb*")), [])
        self.assertFalse((self.td / "asm").exists())

    def test_cli_stdout_and_output(self):
        src = self.td / "in.json"
        ends = self.td / "ends.json"
        src.write_text(json.dumps(selection_doc([selected_row()])))
        ends.write_text(json.dumps(ends_for()))
        env = os_environ_patch({"PEEL_LOG": str(self.log), "PEEL_EXIT": "0"})
        with env:
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--ends", str(ends),
                 "--peel", str(self.peel)],
                cwd=self.td, check=True, capture_output=True, text=True,
            )
        result = json.loads(proc.stdout)
        self.assertEqual(result["results"][0]["result"], "peel-emitted")
        out = self.td / "out.json"
        with env:
            proc2 = subprocess.run(
                [sys.executable, str(CLI), str(src), "--ends", str(ends),
                 "--peel", str(self.peel), "--output", str(out)],
                cwd=self.td, check=True, capture_output=True, text=True,
            )
        self.assertEqual(proc2.stdout, "")
        self.assertTrue(out.is_file())
        self.assertFalse((self.td / "labels.toml").exists())

    def test_cli_force_boundary_passthrough(self):
        src = self.td / "in.json"
        ends = self.td / "ends.json"
        src.write_text(json.dumps(selection_doc([selected_row()])))
        ends.write_text(json.dumps(ends_for()))
        env = os_environ_patch({"PEEL_LOG": str(self.log), "PEEL_EXIT": "0"})
        with env:
            subprocess.run(
                [sys.executable, str(CLI), str(src), "--ends", str(ends),
                 "--peel", str(self.peel), "--force-boundary"],
                cwd=self.td, check=True, capture_output=True, text=True,
            )
        argv = self.peel_argv()[0]
        self.assertIn("--force-boundary", argv)


class Determinism(FakePeel):
    def test_identical_inputs_same_command_sequence(self):
        doc = selection_doc([
            selected_row(addr="0x08001000"),
            selected_row(addr="0x08001200"),
        ])
        ends = {
            "0x08001000:thumb": {"end": "0x08001040"},
            "0x08001200:thumb": {"end": "0x08001240"},
        }
        r1, out1 = self.run_sel(doc, ends)
        self.log.unlink()
        r2, out2 = self.run_sel(doc, ends)
        self.assertEqual(r1.commands, r2.commands)
        self.assertEqual(out1, out2)
        addrs = [c[c.index("--start") + 1] for c in r1.commands]
        self.assertEqual(addrs, ["0x08001000", "0x08001200"])


if __name__ == "__main__":
    unittest.main()
