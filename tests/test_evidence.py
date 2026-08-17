"""Evidence sidecar: serialization, status ladder, encoding gate."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import evidence  # noqa: E402
import labels_toml  # noqa: E402

SHA = "a" * 64
SHA2 = "b" * 64


def _rec(**kw) -> evidence.Record:
    base = dict(address=0x080001C8, mode="thumb", status=evidence.UNRESOLVED)
    base.update(kw)
    return evidence.Record(**base)


class Roundtrip(unittest.TestCase):
    def test_jsonl_roundtrip_hex_and_int(self):
        rec = _rec(
            status=evidence.RANGE_VERIFIED,
            end=0x08000220,
            name="AgbMain",
            evidence=[evidence.Evidence("peel-incbin", "peel", "range", from_addr=0x080000C0)],
            extra={"note": "keep-me"},
        )
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "game.evidence.jsonl"
            evidence.save(path, SHA, {rec.key(): rec})
            sha, loaded = evidence.load(path, expected_sha=SHA)
            self.assertEqual(sha, SHA)
            got = loaded[rec.key()]
            self.assertEqual(got.status, evidence.RANGE_VERIFIED)
            self.assertEqual(got.end, 0x08000220)
            self.assertEqual(got.name, "AgbMain")
            self.assertEqual(got.evidence[0].from_addr, 0x080000C0)
            self.assertEqual(got.extra.get("note"), "keep-me")
            text = path.read_text()
            self.assertIn('"0x080001c8"', text)
            # integer addresses on load
            blob = json.loads(text.splitlines()[1])
            blob["address"] = 0x080001C8
            blob["end"] = 0x08000220
            parsed = evidence.Record.from_json(blob)
            self.assertEqual(parsed.address, 0x080001C8)

    def test_unknown_evidence_type_preserved(self):
        rec = _rec(evidence=[evidence.Evidence("future-kind", "unit", "x")])
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "g.evidence.jsonl"
            evidence.save(path, SHA, {rec.key(): rec})
            _, loaded = evidence.load(path)
            self.assertEqual(loaded[rec.key()].evidence[0].type, "future-kind")

    def test_sha_mismatch(self):
        rec = _rec()
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "g.evidence.jsonl"
            evidence.save(path, SHA, {rec.key(): rec})
            with self.assertRaises(ValueError):
                evidence.load(path, expected_sha=SHA2)


class Status(unittest.TestCase):
    def test_record_range_verified(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "g.evidence.jsonl"
            evidence.record_range_verified(
                path, SHA, 0x080001C8, "thumb", 0x08000220, "AgbMain",
                evidence.Evidence("peel-incbin", "peel", "incbin"),
            )
            _, recs = evidence.load(path, SHA)
            rec = recs[(0x080001C8, "thumb")]
            self.assertEqual(rec.status, evidence.RANGE_VERIFIED)
            self.assertEqual(rec.end, 0x08000220)

    def test_unresolved_stays_until_range(self):
        rec = _rec(status=evidence.UNRESOLVED)
        self.assertEqual(rec.status, evidence.UNRESOLVED)
        self.assertNotEqual(rec.status, evidence.RANGE_VERIFIED)
        self.assertNotEqual(rec.status, evidence.ENCODING_VERIFIED)

    def test_rejected_not_encoding(self):
        rec = _rec(status=evidence.REJECTED, conflicts=["not code"])
        self.assertEqual(rec.status, evidence.REJECTED)
        self.assertEqual(list(evidence.iter_encoding_verified([rec])), [])

    def test_upsert_does_not_accept_encoding(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "g.evidence.jsonl"
            sneaky = _rec(
                status=evidence.ENCODING_VERIFIED,
                end=0x08000220,
                evidence=[evidence.Evidence("encoding-roundtrip", "test", "no")],
            )
            stored = evidence.upsert(path, SHA, sneaky)
            self.assertNotEqual(stored.status, evidence.ENCODING_VERIFIED)
            _, recs = evidence.load(path, SHA)
            self.assertEqual(recs[sneaky.key()].status, evidence.UNRESOLVED)

    def test_iter_encoding_skips_range(self):
        rows = [
            _rec(status=evidence.UNRESOLVED),
            _rec(address=0x08000200, status=evidence.RANGE_VERIFIED, end=0x08000210),
            _rec(address=0x08000300, status=evidence.ENCODING_VERIFIED, end=0x08000310),
        ]
        got = list(evidence.iter_encoding_verified(rows))
        self.assertEqual([r.address for r in got], [0x08000300])


class EncodingGate(unittest.TestCase):
    def test_refuses_without_range(self):
        rec = _rec(
            status=evidence.UNRESOLVED,
            end=0x08000220,
            evidence=[evidence.Evidence("encoding-roundtrip", "test", "asm")],
        )
        with self.assertRaises(evidence.PromotionError):
            evidence.promote_encoding_verified(rec)

    def test_refuses_without_roundtrip_evidence(self):
        rec = _rec(status=evidence.RANGE_VERIFIED, end=0x08000220)
        with self.assertRaises(evidence.PromotionError):
            evidence.promote_encoding_verified(rec)

    def test_refuses_conflicts(self):
        rec = _rec(
            status=evidence.RANGE_VERIFIED,
            end=0x08000220,
            conflicts=["interior bl"],
            evidence=[evidence.Evidence("encoding-roundtrip", "test", "asm")],
        )
        with self.assertRaises(evidence.PromotionError):
            evidence.promote_encoding_verified(rec)

    def test_refuses_missing_end(self):
        rec = _rec(
            status=evidence.RANGE_VERIFIED,
            evidence=[evidence.Evidence("encoding-roundtrip", "test", "asm")],
        )
        with self.assertRaises(evidence.PromotionError):
            evidence.promote_encoding_verified(rec)

    def test_isolated_success(self):
        rec = _rec(
            status=evidence.RANGE_VERIFIED,
            end=0x08000220,
            evidence=[evidence.Evidence("encoding-roundtrip", "test", "asm ok")],
        )
        out = evidence.promote_encoding_verified(rec)
        self.assertEqual(out.status, evidence.ENCODING_VERIFIED)
        self.assertEqual(rec.status, evidence.RANGE_VERIFIED)  # input unchanged


class LabelsCompat(unittest.TestCase):
    def test_labels_v2_has_no_status_field(self):
        with tempfile.TemporaryDirectory() as td:
            rom = Path(td) / "game.gba"
            rom.write_bytes(b"\x00" * 16)
            path = Path(td) / "game.labels.toml"
            labels_toml.save(path, SHA, {
                (0x080001C8, "thumb"): labels_toml.Fn(0x080001C8, "thumb", 0x08000220, "AgbMain"),
            })
            text = path.read_text()
            self.assertNotIn("status", text)
            self.assertNotIn("evidence", text)
            sha, fns = labels_toml.load(path)
            self.assertEqual(sha, SHA)
            fn = fns[(0x080001C8, "thumb")]
            self.assertEqual(fn.address, 0x080001C8)
            self.assertEqual(fn.mode, "thumb")
            self.assertEqual(fn.end, 0x08000220)
            self.assertEqual(fn.name, "AgbMain")
            self.assertFalse(hasattr(fn, "status"))

    def test_optional_mode_fields_roundtrip_and_old_jsonl(self):
        rec = _rec(evidence=[evidence.Evidence(
            "bl-target", "modeflow", "bl",
            from_addr=0x08001000, target_addr=0x08001200,
            source_mode="thumb", target_mode="thumb",
        )])
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "g.evidence.jsonl"
            evidence.save(path, SHA, {rec.key(): rec})
            _, loaded = evidence.load(path, SHA)
            ev = loaded[rec.key()].evidence[0]
            self.assertEqual(ev.target_addr, 0x08001200)
            self.assertEqual(ev.source_mode, "thumb")
            self.assertEqual(ev.target_mode, "thumb")
            old = {
                "address": "0x080001c8", "mode": "thumb",
                "status": "unresolved",
                "evidence": [{"type": "peel-incbin", "source": "peel", "detail": "range"}],
                "conflicts": [],
            }
            parsed = evidence.Record.from_json(old)
            self.assertIsNone(parsed.evidence[0].target_addr)
            self.assertIsNone(parsed.evidence[0].source_mode)
            self.assertIsNone(parsed.evidence[0].target_mode)


if __name__ == "__main__":
    unittest.main()

