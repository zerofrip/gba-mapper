"""CheckRunner: wire + make check + RANGE. Mocks only; not real peel/wire/check."""
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

import run_check  # noqa: E402

CLI = TOOLS / "run_check.py"
ADDR = 0x08001200
ADDR_HEX = "0x08001200"
END_HEX = "0x08001240"
FAKE_WIRE = r"""
import json, os, sys
from pathlib import Path
log = Path(os.environ["WIRE_LOG"])
rows = json.loads(log.read_text()) if log.exists() else []
rows.append(sys.argv[1:])
log.write_text(json.dumps(rows))
sys.exit(int(os.environ.get("WIRE_EXIT", "0")))
"""


def artifact_text(start=ADDR, end=0x08001240, mode="thumb"):
    size = end - start
    return (
        "@ Auto-emitted by tools/peel.py — do not hand-edit this header.\n"
        f"@ Range:  [{start:#010x}, {end:#010x})  ({size} bytes, {mode} mode)\n"
        f"        {mode}_func_start sub_{start:08X}\n"
        f'        .incbin "baserom.gba", {start - 0x08000000:#x}, {size:#x}\n'
    )


def peel_row(*, result="peel-emitted", selection="selected",
             disposition="peel-ready", addr=ADDR_HEX, mode="thumb", extra=None):
    row = {
        "address": addr,
        "mode": mode,
        "result": result,
        "selection": selection,
        "disposition": disposition,
        "evidence_items": [{"type": "bl-target", "source": "modeflow"}],
    }
    if extra:
        row.update(extra)
    return row


def peel_doc(results=None, skipped=None, unresolved=None):
    return {
        "results": list(results or []),
        "skipped": list(skipped or []),
        "unresolved": list(unresolved or []),
    }


def ends_for(addr=ADDR_HEX, mode="thumb", end=END_HEX):
    return {f"{addr}:{mode}": {"end": end}}


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


class RunnerCase(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.td = Path(self._td.name)
        (self.td / "asm").mkdir()
        self.wire = self.td / "fake_wire.py"
        self.wire.write_text(FAKE_WIRE)
        self.log = self.td / "wire.log"
        self.records = []
        self.wire_exit = "0"
        self.check_exit = 0
        self.art = self.td / "asm" / "disasm_0x08001200.s"
        self.art.write_text(artifact_text())
        (self.td / "linker.ld").write_text(
            "SECTIONS {\n    build/asm/disasm_0x08001200.o(.text)\n}\n"
        )

    def tearDown(self):
        self._td.cleanup()

    def record(self, passed, start, mode, end):
        self.records.append((passed, start, mode, end))
        return {"ok": True} if passed else None

    def run_doc(self, doc, ends, **kwargs):
        env = os_environ_patch({
            "WIRE_LOG": str(self.log),
            "WIRE_EXIT": self.wire_exit,
        })
        with env:
            r = run_check.CheckRunner(
                self.td,
                wire=self.wire,
                make_check=lambda: self.check_exit,
                record=self.record,
                **kwargs,
            )
            out = r.run(doc, ends)
        return r, out

    def wire_argv(self):
        if not self.log.exists():
            return []
        return json.loads(self.log.read_text())


class End(RunnerCase):
    def test_explicit_end_only(self):
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["results"][0]["result"], "range-recorded")
        self.assertEqual(out["results"][0]["end"], END_HEX)
        argv = self.wire_argv()[0]
        self.assertEqual(argv[argv.index("--end") + 1], END_HEX)
        self.assertEqual(self.records, [(True, ADDR, "thumb", 0x08001240)])

    def test_missing_end(self):
        _, out = self.run_doc(peel_doc([peel_row()]), {})
        self.assertEqual(out["skipped"][0]["reason"], "missing-explicit-end")
        self.assertEqual(self.wire_argv(), [])
        self.assertEqual(self.records, [])

    def test_malformed_and_le_start(self):
        for bad in (None, "nope", ADDR_HEX):
            with self.subTest(bad=bad):
                self.log.unlink(missing_ok=True)
                self.records.clear()
                _, out = self.run_doc(
                    peel_doc([peel_row()]),
                    {f"{ADDR_HEX}:thumb": {"end": bad}},
                )
                self.assertEqual(out["skipped"][0]["reason"], "malformed-end")
                self.assertEqual(self.records, [])

    def test_rom_window_rejected(self):
        _, out = self.run_doc(
            peel_doc([peel_row()]),
            {f"{ADDR_HEX}:thumb": {"end": "0x0B000000"}},
        )
        self.assertEqual(out["skipped"][0]["reason"], "malformed-end")
        self.assertEqual(self.records, [])

    def test_no_inference_from_size_next_ghidra(self):
        row = peel_row(extra={
            "size": 64, "end": "0x0800FFFF", "recommendedEnd": "0x08001400",
            "ghidra_size": 64,
        })
        nxt = peel_row(addr="0x08001300", extra={"result": "peel-emitted"})
        doc = peel_doc([row, nxt])
        _, out = self.run_doc(doc, {})
        self.assertEqual(self.records, [])
        self.assertEqual(self.wire_argv(), [])
        reasons = {s["address"]: s["reason"] for s in out["skipped"]}
        self.assertEqual(reasons[ADDR_HEX], "missing-explicit-end")
        self.assertEqual(reasons["0x08001300"], "missing-explicit-end")

    def test_address_only_end_rejected(self):
        _, out = self.run_doc(peel_doc([peel_row()]), {ADDR_HEX: {"end": END_HEX}})
        self.assertEqual(out["skipped"][0]["reason"], "address-only-end-mapping")
        self.assertEqual(self.records, [])


class Selection(RunnerCase):
    def test_peel_failed_not_run(self):
        _, out = self.run_doc(peel_doc([peel_row(result="peel-failed")]), ends_for())
        self.assertEqual(out["skipped"][0]["reason"], "invalid-selection")
        self.assertEqual(self.wire_argv(), [])
        self.assertEqual(self.records, [])

    def test_skipped_unresolved_not_run(self):
        doc = peel_doc(
            skipped=[peel_row()],
            unresolved=[{"type": "indirect-branch", "from_addr": "0x08001000"}],
        )
        _, out = self.run_doc(doc, ends_for())
        self.assertEqual(out["results"], [])
        self.assertEqual(out["unresolved"][0]["type"], "indirect-branch")
        self.assertNotIn("result", out["unresolved"][0])
        self.assertEqual(self.wire_argv(), [])
        self.assertEqual(self.records, [])

    def test_invalid_disposition_not_run(self):
        _, out = self.run_doc(
            peel_doc([peel_row(disposition="conflicted")]), ends_for(),
        )
        self.assertEqual(out["skipped"][0]["reason"], "invalid-selection")
        self.assertEqual(self.records, [])


class Artifact(RunnerCase):
    def test_missing_artifact(self):
        self.art.unlink()
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["skipped"][0]["reason"], "missing-artifact")
        self.assertEqual(self.records, [])

    def test_end_mismatch(self):
        self.art.write_text(artifact_text(end=0x08001300))
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["skipped"][0]["reason"], "metadata-mismatch")
        self.assertEqual(self.records, [])

    def test_mode_mismatch(self):
        self.art.write_text(artifact_text(mode="arm"))
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["skipped"][0]["reason"], "metadata-mismatch")
        self.assertEqual(self.records, [])


class WireAndCheck(RunnerCase):
    def test_wire_args_no_mode(self):
        self.run_doc(peel_doc([peel_row()]), ends_for())
        argv = self.wire_argv()[0]
        self.assertEqual(argv[argv.index("--start") + 1], ADDR_HEX)
        self.assertEqual(argv[argv.index("--end") + 1], END_HEX)
        self.assertNotIn("--mode", argv)

    def test_wire_exit_3(self):
        self.wire_exit = "3"
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["results"][0]["result"], "wire-failed")
        self.assertEqual(out["results"][0]["wire_exit"], 3)
        self.assertEqual(self.records, [])

    def test_linker_missing_object(self):
        (self.td / "linker.ld").write_text("SECTIONS { build/asm/rom.o(.text) }\n")
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["skipped"][0]["reason"], "not-wired")
        self.assertEqual(self.records, [])

    def test_check_exit_1(self):
        self.check_exit = 1
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["results"][0]["result"], "check-failed")
        self.assertEqual(out["results"][0]["check_exit"], 1)
        self.assertEqual(self.records, [])

    def test_stdout_ok_ignored_when_exit_nonzero(self):
        def fake_check():
            return 1
        env = os_environ_patch({"WIRE_LOG": str(self.log), "WIRE_EXIT": "0"})
        with env:
            r = run_check.CheckRunner(
                self.td, wire=self.wire, make_check=fake_check, record=self.record,
            )
            out = r.run(peel_doc([peel_row()]), ends_for())
        self.assertEqual(out["results"][0]["result"], "check-failed")
        self.assertEqual(self.records, [])


class Boundary(RunnerCase):
    def test_source_does_not_call_direct_range_or_encoding(self):
        src = inspect.getsource(run_check)
        self.assertIn("record_range_after_check", src)
        self.assertNotIn("record_range_verified(", src)
        self.assertNotIn("promote_encoding_verified", src)
        self.assertNotIn("labels_toml", src)

    def test_no_verification_fields_in_output(self):
        _, out = self.run_doc(peel_doc([peel_row()]), ends_for())
        blob = json.dumps(out)
        for k in ("winner", "confidence", "score", "encoding_verified",
                  "range_verified", "verified"):
            self.assertNotIn(f'"{k}"', blob)
        self.assertNotIn("status", out)
        self.assertEqual(out["results"][0]["result"], "range-recorded")

    def test_failure_does_not_mutate_candidate_or_unresolved(self):
        row = peel_row()
        original = json.loads(json.dumps(row))
        unresolved = [{"type": "indirect-branch"}]
        self.check_exit = 1
        _, out = self.run_doc(peel_doc([row], unresolved=unresolved), ends_for())
        self.assertEqual(row, original)
        self.assertEqual(out["unresolved"], unresolved)
        self.assertEqual(len(out["results"]), 1)

    def test_arm_thumb_independent(self):
        arm = peel_row(mode="arm")
        thumb = peel_row(mode="thumb")
        (self.td / "asm" / "disasm_0x08001200.s").write_text(artifact_text(mode="thumb"))
        doc = peel_doc([arm, thumb])
        ends = ends_for()  # thumb only
        _, out = self.run_doc(doc, ends)
        self.assertEqual(out["skipped"][0]["mode"], "arm")
        self.assertEqual(out["skipped"][0]["reason"], "missing-explicit-end")
        self.assertEqual(out["results"][0]["mode"], "thumb")
        self.assertEqual(out["results"][0]["result"], "range-recorded")
        self.assertEqual(self.records, [(True, ADDR, "thumb", 0x08001240)])

    def test_default_does_not_write_labels(self):
        self.run_doc(peel_doc([peel_row()]), ends_for())
        self.assertFalse((self.td / "labels.toml").exists())
        self.assertEqual(list(self.td.glob("*.labels.toml")), [])
        self.assertEqual(list(self.td.glob("gamedb*")), [])


class Cli(RunnerCase):
    def test_cli_missing_end_stdout_no_side_effects(self):
        src = self.td / "in.json"
        ends = self.td / "ends.json"
        src.write_text(json.dumps(peel_doc([peel_row()])))
        ends.write_text("{}")
        proc = subprocess.run(
            [sys.executable, str(CLI), str(src), "--ends", str(ends),
             "--tree", str(self.td), "--wire", str(self.wire)],
            cwd=self.td, check=True, capture_output=True, text=True,
        )
        result = json.loads(proc.stdout)
        self.assertEqual(result["skipped"][0]["reason"], "missing-explicit-end")
        self.assertFalse((self.td / "labels.toml").exists())
        out = self.td / "out.json"
        proc2 = subprocess.run(
            [sys.executable, str(CLI), str(src), "--ends", str(ends),
             "--tree", str(self.td), "--wire", str(self.wire),
             "--output", str(out)],
            cwd=self.td, check=True, capture_output=True, text=True,
        )
        self.assertEqual(proc2.stdout, "")
        self.assertTrue(out.is_file())


if __name__ == "__main__":
    unittest.main()
