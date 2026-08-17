"""Frontier provenance: CandidateKey, add_candidate, merge, unresolved."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import evidence  # noqa: E402
import frontier  # noqa: E402
from labels_toml import ROM_BASE  # noqa: E402

ROM_SIZE = 0x2000


def h16(x: int) -> bytes:
    return int(x).to_bytes(2, "little")


def w32(x: int) -> bytes:
    return int(x).to_bytes(4, "little")


def thumb_bl(src: int, tgt: int) -> bytes:
    off = tgt - src - 4
    hi = (off >> 12) & 0x7FF
    lo = (off >> 1) & 0x7FF
    return h16(0xF000 | hi) + h16(0xF800 | lo)


def arm_b(src: int, tgt: int, *, link: bool = False) -> bytes:
    imm = ((tgt - src - 8) >> 2) & 0xFFFFFF
    return w32((0xEB000000 if link else 0xEA000000) | imm)


def blank_rom(size: int = ROM_SIZE) -> bytearray:
    return bytearray(size)


def put(rom: bytearray, addr: int, data: bytes) -> None:
    off = addr - ROM_BASE
    rom[off:off + len(data)] = data


def items_of(result: dict, addr: int, mode: str) -> list[dict]:
    for c in result["candidates"]:
        if int(c["address"], 16) == addr and c["mode"] == mode:
            return c["evidence_items"]
    return []


class StoreRules(unittest.TestCase):
    def test_empty_evidence_is_rejected(self):
        store = frontier.FrontierStore()
        store.add_candidate(0x08001234, "thumb", [])
        store.add_candidate(0x08001234, "thumb", None)
        self.assertEqual(store.to_json_list(), [])

    def test_manual_seed_accepted(self):
        store = frontier.FrontierStore()
        ev = evidence.Evidence(
            "manual-seed", "unit", "hand",
            target_addr=0x08001234, target_mode="thumb",
        )
        store.add_candidate(0x08001234, "thumb", ev)
        rows = store.to_json_list()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_items"][0]["type"], "manual-seed")
        self.assertFalse(rows[0]["deterministic"])

    def test_same_key_two_sources_merge(self):
        store = frontier.FrontierStore()
        a = evidence.Evidence(
            "bl-target", "modeflow", "bl",
            from_addr=0x08001000, target_addr=0x08001234,
            source_mode="thumb", target_mode="thumb", insn="bl",
        )
        b = evidence.Evidence(
            "gap", "gap", "gap [0x08001200, 0x08001280) after mapped [0x08001000, 0x08001200)",
            from_addr=0x08001200, target_addr=0x08001234,
            source_mode="thumb", target_mode="thumb",
        )
        store.add_candidate(0x08001234, "thumb", a)
        store.add_candidate(0x08001234, "thumb", b)
        rows = store.to_json_list()
        self.assertEqual(len(rows), 1)
        types = [e["type"] for e in rows[0]["evidence_items"]]
        self.assertEqual(types, ["bl-target", "gap"])

    def test_identical_evidence_deduplicated(self):
        store = frontier.FrontierStore()
        ev = evidence.Evidence(
            "bl-target", "modeflow", "bl",
            from_addr=0x08001000, target_addr=0x08001234,
            source_mode="thumb", target_mode="thumb",
        )
        store.add_candidate(0x08001234, "thumb", ev)
        store.add_candidate(0x08001234, "thumb", ev)
        self.assertEqual(len(store.to_json_list()[0]["evidence_items"]), 1)

    def test_same_address_arm_thumb_are_two_candidates(self):
        store = frontier.FrontierStore()
        store.add_candidate(0x08001234, "thumb", evidence.Evidence(
            "bl-target", "modeflow", "bl",
            from_addr=0x08001000, target_addr=0x08001234,
            source_mode="thumb", target_mode="thumb",
        ))
        store.add_candidate(0x08001234, "arm", evidence.Evidence(
            "bl-target", "modeflow", "bl",
            from_addr=0x08001008, target_addr=0x08001234,
            source_mode="arm", target_mode="arm",
        ))
        keys = {(int(c["address"], 16), c["mode"]) for c in store.to_json_list()}
        self.assertEqual(keys, {(0x08001234, "arm"), (0x08001234, "thumb")})
        for c in store.to_json_list():
            self.assertTrue(c["conflicts"])
            self.assertIn("mode conflict", c["conflicts"][0])

    def test_json_roundtrip_preserves_structured_evidence(self):
        store = frontier.FrontierStore()
        store.add_candidate(0x08001234, "thumb", evidence.Evidence(
            "bl-target", "modeflow", "bl",
            from_addr=0x08001000, target_addr=0x08001234,
            source_mode="thumb", target_mode="thumb", insn="bl",
        ))
        blob = json.dumps(store.to_json_list())
        loaded = json.loads(blob)
        ev = evidence.Evidence.from_json(loaded[0]["evidence_items"][0])
        self.assertEqual(ev.type, "bl-target")
        self.assertEqual(ev.from_addr, 0x08001000)
        self.assertEqual(ev.target_addr, 0x08001234)
        self.assertEqual(ev.source_mode, "thumb")
        self.assertEqual(ev.target_mode, "thumb")
        self.assertEqual(ev.insn, "bl")
        self.assertTrue(loaded[0]["deterministic"])


class ModeflowHarvest(unittest.TestCase):
    def test_bl_enters_with_full_provenance(self):
        rom = blank_rom()
        src, tgt = 0x080000C0, 0x08000140
        put(rom, src, thumb_bl(src, tgt))
        result = frontier.build_frontier(
            bytes(rom), [(src, src + 4, "thumb")], max_n=24,
        )
        items = items_of(result, tgt, "thumb")
        self.assertEqual(len(items), 1)
        ev = items[0]
        self.assertEqual(ev["type"], "bl-target")
        self.assertEqual(ev["source"], "modeflow")
        self.assertEqual(int(ev["from_addr"], 16), src)
        self.assertEqual(ev["source_mode"], "thumb")
        self.assertEqual(int(ev["target_addr"], 16), tgt)
        self.assertEqual(ev["target_mode"], "thumb")
        cand = next(c for c in result["candidates"] if int(c["address"], 16) == tgt)
        self.assertTrue(cand["deterministic"])

    def test_known_bx_enters_with_provenance(self):
        rom = blank_rom()
        src = 0x08000100
        ptr = 0x08001201
        put(rom, src, w32(0xE59F0000) + w32(0xE12FFF10) + w32(ptr))
        result = frontier.build_frontier(
            bytes(rom), [(src, src + 12, "arm")], max_n=24,
        )
        items = items_of(result, ptr & ~1, "thumb")
        self.assertEqual(len(items), 1)
        ev = items[0]
        self.assertEqual(ev["type"], "bx-target")
        self.assertEqual(ev["source"], "modeflow")
        self.assertEqual(int(ev["from_addr"], 16), src + 4)
        self.assertEqual(ev["source_mode"], "arm")
        self.assertEqual(ev["target_mode"], "thumb")
        self.assertTrue(next(
            c for c in result["candidates"] if c["mode"] == "thumb"
        )["deterministic"])

    def test_unknown_bx_does_not_create_candidate(self):
        rom = blank_rom()
        src = 0x080000C0
        put(rom, src, h16(0x4700))
        result = frontier.build_frontier(
            bytes(rom), [(src, src + 2, "thumb")], max_n=24,
        )
        self.assertEqual(result["candidates"], [])
        types = [u["type"] for u in result["unresolved"]]
        self.assertIn("indirect-branch", types)
        un = next(u for u in result["unresolved"] if u["type"] == "indirect-branch")
        self.assertNotIn("target_addr", un)
        self.assertNotIn("target_mode", un)

    def test_gap_has_gap_provenance(self):
        rom = blank_rom()
        rom[:] = b"\x01" * len(rom)
        lo, mid, hi = 0x080000C0, 0x080000E0, 0x08000100
        result = frontier.build_frontier(
            bytes(rom),
            [(lo, mid, "thumb"), (hi, hi + 8, "thumb")],
            max_n=24,
        )
        gaps = [c for c in result["candidates"] if c.get("evidence_type") == "gap"]
        self.assertTrue(gaps)
        ev = gaps[0]["evidence_items"][0]
        self.assertEqual(ev["type"], "gap")
        self.assertEqual(ev["source"], "gap")
        self.assertEqual(int(ev["from_addr"], 16), mid)
        self.assertEqual(ev["source_mode"], "thumb")
        self.assertEqual(ev["target_mode"], "thumb")
        self.assertIn("[0x80000e0, 0x8000100)", ev["detail"])
        self.assertIn("[0x80000c0, 0x80000e0)", ev["detail"])
        self.assertFalse(gaps[0]["deterministic"])

    def test_vector_entry_provenance(self):
        rom = blank_rom()
        stub = 0x08000100
        put(rom, ROM_BASE, arm_b(ROM_BASE, stub))
        put(rom, 0x080000C0, h16(0x4770))
        result = frontier.build_frontier(
            bytes(rom), [(0x080000C0, 0x080000C2, "thumb")], max_n=24,
        )
        items = items_of(result, stub, "arm")
        self.assertEqual(len(items), 1)
        ev = items[0]
        self.assertEqual(ev["type"], "vector-entry")
        self.assertEqual(ev["source"], "modeflow")
        self.assertEqual(int(ev["from_addr"], 16), ROM_BASE)
        self.assertEqual(ev["source_mode"], "arm")
        self.assertEqual(ev["target_mode"], "arm")
        self.assertNotIn((ROM_BASE + 4, "arm"), {
            (int(c["address"], 16), c["mode"]) for c in result["candidates"]
        })

    def test_sidecar_decomp_reference_unmapped_only(self):
        rom = blank_rom()
        put(rom, 0x080000C0, h16(0x4770))
        recs = {
            (0x08000180, "thumb"): evidence.Record(
                address=0x08000180, mode="thumb", status=evidence.UNRESOLVED,
                evidence=[evidence.Evidence(
                    "decomp-reference", "seed_from_decomp", "elf FUNC Foo",
                    target_addr=0x08000180, target_mode="thumb",
                )],
            ),
            (0x080000C0, "thumb"): evidence.Record(
                address=0x080000C0, mode="thumb", status=evidence.UNRESOLVED,
                evidence=[evidence.Evidence(
                    "decomp-reference", "seed_from_decomp", "already mapped",
                )],
            ),
        }
        result = frontier.build_frontier(
            bytes(rom), [(0x080000C0, 0x080000C2, "thumb")],
            sidecar_records=recs, max_n=24,
        )
        keys = {(int(c["address"], 16), c["mode"]) for c in result["candidates"]}
        self.assertIn((0x08000180, "thumb"), keys)
        self.assertNotIn((0x080000C0, "thumb"), keys)
        ev = items_of(result, 0x08000180, "thumb")[0]
        self.assertEqual(ev["type"], "decomp-reference")


class Phase1Compat(unittest.TestCase):
    def test_phase1_jsonl_without_optional_fields_loads(self):
        old = {
            "address": "0x080001c8", "mode": "thumb",
            "status": "unresolved",
            "evidence": [{"type": "peel-incbin", "source": "peel", "detail": "range"}],
            "conflicts": [],
        }
        rec = evidence.Record.from_json(old)
        self.assertEqual(rec.address, 0x080001C8)
        self.assertIsNone(rec.evidence[0].target_addr)
        self.assertIsNone(rec.evidence[0].source_mode)
        self.assertIsNone(rec.evidence[0].insn)


if __name__ == "__main__":
    unittest.main()
