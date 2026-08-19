"""LLM suggestion layer: fake provider only. Not verification or Evidence."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import llm_suggest  # noqa: E402

CLI = TOOLS / "llm_suggest.py"
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


class TargetFilter(unittest.TestCase):
    def test_agreed_seed_heuristic_conflicted(self):
        out = llm_suggest.suggest(doc(skipped=[
            skipped(disposition="agreed-seed", extra={"sources": ["ghidra", "manual-seed"]}),
            skipped(addr="0x08001300", disposition="heuristic"),
            skipped(addr="0x08001400", mode="arm", disposition="conflicted"),
            skipped(addr="0x08001400", mode="thumb", disposition="conflicted"),
        ]))
        acts = {(s["address"], s["mode"], s["action"]) for s in out["suggestions"]}
        self.assertIn((ADDR_HEX, "thumb", "possible-control-flow"), acts)
        self.assertIn(("0x08001300", "thumb", "possible-data"), acts)
        self.assertIn(("0x08001400", "arm", "arm-plausible"), acts)
        self.assertIn(("0x08001400", "thumb", "thumb-plausible"), acts)
        self.assertNotIn("winner", json.dumps(out))

    def test_peel_ready_and_unresolved_ignored(self):
        out = llm_suggest.suggest(doc(
            selected=[selected_peel_ready()],
            skipped=[skipped(disposition="peel-ready")],
            unresolved=[{"type": "indirect-branch", "from_addr": "0x08000f00"}],
        ))
        self.assertEqual(out["suggestions"], [])
        self.assertEqual(out["errors"], [])

    def test_duplicate_first_wins(self):
        rows = [
            skipped(disposition="heuristic"),
            skipped(disposition="agreed-seed"),
        ]
        out = llm_suggest.suggest(doc(skipped=rows))
        self.assertEqual(len(out["suggestions"]), 1)
        self.assertEqual(out["suggestions"][0]["action"], "possible-data")


class SchemaAndHash(unittest.TestCase):
    def test_canonical_hash_and_no_detail(self):
        row = skipped(extra={
            "end": "0x08001240",
            "recommendedEnd": "0x08001240",
            "size": 64,
            "rom_bytes": "deadbeef",
            "review_decision": "select-for-peel",
        })
        req = llm_suggest.build_request(row)
        self.assertNotIn("detail", json.dumps(req))
        self.assertNotIn("INJECT", json.dumps(req))
        self.assertNotIn("deadbeef", json.dumps(req))
        self.assertNotIn("selection", req)
        self.assertNotIn("end", req)
        self.assertNotIn("recommendedEnd", req)
        self.assertNotIn("size", req)
        self.assertNotIn("rom_bytes", req)
        self.assertNotIn("review_decision", req)
        self.assertEqual(set(req), {
            "address", "mode", "disposition", "sources", "classes",
            "evidence_types", "deterministic",
        })
        self.assertEqual(req["evidence_types"], ["ghidra-seed"])
        expected = hashlib.sha256(
            llm_suggest.canonical_json(req).encode("utf-8")
        ).hexdigest()
        out = llm_suggest.suggest(doc(skipped=[row]))
        self.assertEqual(out["suggestions"][0]["input_hash"], expected)
        self.assertEqual(out["format"], "gba-mapper-llm-suggestion")
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["run"]["provider"], "fake")
        self.assertEqual(out["run"]["model"], "fixture")
        self.assertEqual(out["run"]["prompt_version"], "7db-v1")
        self.assertNotIn("timestamp", out)
        self.assertNotIn("timestamp", out["run"])
        self.assertFalse(out["suggestions"][0]["deterministic"])

    def test_all_allowed_actions(self):
        fake = llm_suggest.FakeProvider()
        addrs = []
        for i, action in enumerate(sorted(llm_suggest._ALLOWED_ACTIONS)):
            addr = f"0x0800{i:04x}"
            addrs.append((addr, action))
            key = (int(addr, 16), "thumb")
            fake.responses[key] = {
                "address": addr, "mode": "thumb", "action": action, "rationale": action,
            }
        rows = [skipped(addr=a, disposition="heuristic") for a, _ in addrs]
        out = llm_suggest.suggest(doc(skipped=rows), fake)
        got = {s["action"] for s in out["suggestions"]}
        self.assertEqual(got, set(llm_suggest._ALLOWED_ACTIONS))


class Validation(unittest.TestCase):
    def _one(self, raw, **fail):
        fake = llm_suggest.FakeProvider()
        key = (ADDR, "thumb")
        if raw is not None:
            fake.responses[key] = raw
        fake.failures.update(fail)
        return llm_suggest.suggest(doc(skipped=[skipped()]), fake)

    def test_unknown_and_forbidden(self):
        cases = [
            {"address": ADDR_HEX, "mode": "thumb", "action": "unknown"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "select-for-peel"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "end": "0x1"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "winner": "thumb"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "confidence": 0.9},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "status": "ok"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "range_verified": True},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "encoding_verified": True},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "verified": True},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "score": 1},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "selection": "skipped"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "disposition": "heuristic"},
            {"mode": "thumb", "action": "review"},
            {"address": ADDR_HEX, "action": "review"},
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                out = self._one(raw)
                self.assertEqual(out["suggestions"], [])
                self.assertEqual(out["errors"][0]["error"], "invalid-suggestion")

    def test_unknown_extra_fields_ignored(self):
        out = self._one({
            "address": ADDR_HEX,
            "mode": "thumb",
            "action": "review",
            "rationale": "ok",
            "comment": "ignored extra",
        })
        self.assertEqual(len(out["suggestions"]), 1)
        self.assertEqual(out["suggestions"][0]["action"], "review")
        self.assertNotIn("comment", out["suggestions"][0])

    def test_provider_failures_isolated(self):
        fake = llm_suggest.FakeProvider()
        other = "0x08001300"
        fake.failures[(ADDR, "thumb")] = "exception"
        fake.responses[(int(other, 16), "thumb")] = {
            "address": other, "mode": "thumb", "action": "review", "rationale": "ok",
        }
        out = llm_suggest.suggest(doc(skipped=[
            skipped(),
            skipped(addr=other),
        ]), fake)
        self.assertEqual(out["errors"][0]["error"], "provider-exception")
        self.assertEqual(out["suggestions"][0]["address"], other)

    def test_empty_timeout_malformed(self):
        for kind, err in (
            ("empty", "invalid-suggestion"),
            ("timeout", "timeout"),
            ("malformed", "invalid-suggestion"),
        ):
            with self.subTest(kind=kind):
                fake = llm_suggest.FakeProvider()
                fake.failures[(ADDR, "thumb")] = kind
                out = llm_suggest.suggest(doc(skipped=[skipped()]), fake)
                self.assertEqual(out["suggestions"], [])
                self.assertEqual(out["errors"][0]["error"], err)


class Boundary(unittest.TestCase):
    def test_source_has_no_pipeline_or_llm_clients(self):
        src = inspect.getsource(llm_suggest)
        self.assertNotIn("review_select", src)
        self.assertNotIn("record_range", src)
        self.assertNotIn("promote_encoding", src)
        self.assertNotIn("run_peel", src)
        self.assertNotIn("run_check", src)
        self.assertNotIn("select_peel", src)
        self.assertNotIn("adjudicate", src)
        self.assertNotIn("openai", src)
        self.assertNotIn("anthropic", src)
        self.assertNotIn("import requests", src)
        self.assertNotIn("from requests", src)
        self.assertNotIn("urllib", src)

    def test_cli_stdout_output_no_side_effects(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(doc(skipped=[skipped(disposition="heuristic")])))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--provider", "fake"],
                cwd=td, check=True, capture_output=True, text=True,
            )
            result = json.loads(proc.stdout)
            self.assertEqual(result["suggestions"][0]["action"], "possible-data")
            self.assertFalse(result["suggestions"][0]["deterministic"])
            self.assertFalse((td / "labels.toml").exists())
            self.assertEqual(list(td.glob("*.evidence.jsonl")), [])
            self.assertEqual(list(td.glob("gamedb*")), [])
            out = td / "out.json"
            proc2 = subprocess.run(
                [sys.executable, str(CLI), str(src), "--output", str(out)],
                cwd=td, check=True, capture_output=True, text=True,
            )
            self.assertEqual(proc2.stdout, "")
            self.assertTrue(out.is_file())
            self.assertEqual(json.loads(out.read_text())["format"],
                             "gba-mapper-llm-suggestion")


class Phase8CRealProvider(unittest.TestCase):
    """Cassette-based real provider tests. No live network or credentials."""

    def _cassette_fetch(self, *, url, headers, payload, request):
        self.assertTrue(url.startswith("https://"))
        self.assertNotIn("Authorization", headers)
        user_msg = payload["messages"][1]["content"]
        self.assertNotIn("INJECT", user_msg)
        self.assertNotIn("detail", user_msg)
        self.assertNotIn("deadbeef", user_msg)
        self.assertNotIn("rom", user_msg.lower())
        self.assertNotIn("/bin/", user_msg)
        self.assertEqual(set(json.loads(user_msg)), {
            "address", "mode", "disposition", "sources", "classes",
            "evidence_types", "deterministic",
        })
        content = json.dumps({
            "address": request["address"],
            "mode": request["mode"],
            "action": "possible-data",
            "rationale": "cassette-fixture",
            "provider_version": "8c-v1",
        })
        return json.dumps({"choices": [{"message": {"content": content}}]}).encode()

    def _openai_provider(self, fetch=None, api_key="test-key-not-real"):
        from llm_providers import OpenAiSuggestProvider
        return OpenAiSuggestProvider(fetch=fetch or self._cassette_fetch, api_key=api_key)

    def test_cassette_canonical_shape_and_metadata(self):
        prov = self._openai_provider()
        out = llm_suggest.suggest(doc(skipped=[skipped()]), prov)
        s = out["suggestions"][0]
        self.assertEqual(out["format"], "gba-mapper-llm-suggestion")
        self.assertEqual(out["version"], 1)
        self.assertEqual(out["run"]["provider"], "openai")
        self.assertEqual(out["run"]["model"], "gpt-4o-mini")
        self.assertEqual(out["run"]["prompt_version"], "7db-v1")
        self.assertEqual(out["run"]["provider_version"], "8c-v1")
        self.assertEqual(s["action"], "possible-data")
        self.assertFalse(s["deterministic"])
        self.assertEqual(s["provider"], "openai")
        self.assertEqual(s["provider_version"], "8c-v1")
        self.assertIn("input_hash", s)
        self.assertIn("input_hash", out["run"])

    def test_input_hash_unchanged_with_real_provider(self):
        row = skipped()
        req = llm_suggest.build_request(row)
        expected = llm_suggest.input_hash(req)
        out = llm_suggest.suggest(doc(skipped=[row]), self._openai_provider())
        self.assertEqual(out["suggestions"][0]["input_hash"], expected)

    def test_fake_provider_parity_unchanged(self):
        out = llm_suggest.suggest(doc(skipped=[skipped(disposition="heuristic")]))
        self.assertEqual(out["suggestions"][0]["action"], "possible-data")
        self.assertEqual(out["run"]["provider"], "fake")

    def test_forbidden_and_authoritative_fields_rejected(self):
        forbidden_payloads = [
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "end": "0x1"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "select-for-peel"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "selection": "skipped"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "winner": "thumb"},
            {"address": ADDR_HEX, "mode": "thumb", "action": "review", "deterministic": True},
        ]
        dropped_extra = {
            "address": ADDR_HEX, "mode": "thumb", "action": "review",
            "rationale": "ok", "eligible-for-peel": True,
        }

        def make_fetch(content_obj):
            def _fetch(**kwargs):
                return json.dumps({
                    "choices": [{"message": {"content": json.dumps(content_obj)}}],
                }).encode()
            return _fetch

        for payload in forbidden_payloads:
            with self.subTest(payload=payload):
                out = llm_suggest.suggest(
                    doc(skipped=[skipped()]),
                    self._openai_provider(fetch=make_fetch(payload)),
                )
                self.assertEqual(out["suggestions"], [])
                self.assertEqual(out["errors"][0]["error"], "invalid-suggestion")

        out = llm_suggest.suggest(
            doc(skipped=[skipped()]),
            self._openai_provider(fetch=make_fetch(dropped_extra)),
        )
        self.assertEqual(len(out["suggestions"]), 1)
        self.assertNotIn("eligible-for-peel", out["suggestions"][0])

    def test_provider_failures_mapped(self):
        cases = [
            (lambda **kw: (_ for _ in ()).throw(TimeoutError("t")), "timeout"),
            (lambda **kw: (_ for _ in ()).throw(RuntimeError("HTTP 500")), "provider-exception"),
            (lambda **kw: b"not-json", "provider-exception"),
            (lambda **kw: json.dumps({"choices": []}).encode(), "provider-exception"),
            (lambda **kw: json.dumps({
                "choices": [{"message": {"content": ""}}],
            }).encode(), "provider-exception"),
            (lambda **kw: json.dumps({
                "choices": [{"message": {"content": "{}"}}],
            }).encode(), "invalid-suggestion"),
            (lambda **kw: json.dumps({
                "choices": [{"message": {"content": json.dumps({
                    "address": ADDR_HEX, "mode": "thumb", "action": "bogus",
                })}}],
            }).encode(), "invalid-suggestion"),
        ]
        for fetch, err in cases:
            with self.subTest(err=err):
                out = llm_suggest.suggest(
                    doc(skipped=[skipped()]),
                    self._openai_provider(fetch=fetch),
                )
                self.assertEqual(out["suggestions"], [])
                self.assertEqual(out["errors"][0]["error"], err)

    def test_secret_never_emitted(self):
        secret = "sk-test-secret-must-not-leak-8c"
        prov = self._openai_provider(api_key=secret)

        def leaking_fetch(**kwargs):
            if secret in json.dumps(kwargs):
                pass
            raise RuntimeError(f"boom {secret}")

        prov_fail = self._openai_provider(fetch=leaking_fetch, api_key=secret)
        out = llm_suggest.suggest(doc(skipped=[skipped()]), prov_fail)
        blob = json.dumps(out)
        self.assertNotIn(secret, blob)
        out_ok = llm_suggest.suggest(doc(skipped=[skipped()]), prov)
        self.assertNotIn(secret, json.dumps(out_ok))

    def test_no_pipeline_modules_in_real_provider(self):
        import llm_providers as mod
        src = inspect.getsource(mod)
        for token in (
            "review_select", "eligibility_approve", "ends_approve",
            "run_peel", "run_check", "record_range", "select_peel",
            "adjudicate", "frontier",
        ):
            self.assertNotIn(token, src)
        for token in ("import evidence", "from evidence"):
            self.assertNotIn(token, src)

    def test_llm_suggest_source_still_network_free(self):
        src = inspect.getsource(llm_suggest)
        self.assertNotIn("urllib", src)
        self.assertNotIn("import requests", src)
        self.assertNotIn("run_peel", src)
        self.assertNotIn("ends_approve", src)
        self.assertNotIn("eligibility_approve", src)

    def test_cli_fake_default_and_unknown_provider(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src)],
                cwd=td, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout)["run"]["provider"], "fake")
            bad = subprocess.run(
                [sys.executable, str(CLI), str(src), "--provider", "unknown-vendor"],
                cwd=td, capture_output=True, text=True,
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("unsupported provider", bad.stderr)

    def test_cli_real_provider_missing_credential(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            src = td / "in.json"
            src.write_text(json.dumps(doc(skipped=[skipped()])))
            env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
            proc = subprocess.run(
                [sys.executable, str(CLI), str(src), "--provider", "openai"],
                cwd=td, capture_output=True, text=True, env=env,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("OPENAI_API_KEY", proc.stderr)
            self.assertNotIn("sk-", proc.stderr)


if __name__ == "__main__":
    unittest.main()
