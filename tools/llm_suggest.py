#!/usr/bin/env python3
"""LLM suggestion layer. Not verification, not Evidence.

Reads Phase 7A skipped rows (agreed-seed / heuristic / conflicted) and
emits a standalone suggestion artifact. Does not mint candidates,
change selection, or call peel/wire/RANGE.

    LLM suggestion != verification
    LLM suggestion != selection
    LLM suggestion != Evidence

Usage:
  python3 tools/llm_suggest.py INPUT [--output PATH] [--provider fake|REAL]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROMPT_VERSION = "7db-v1"
_TARGET_DISP = frozenset({"agreed-seed", "heuristic", "conflicted"})
_MODES = frozenset({"arm", "thumb"})
_ALLOWED_ACTIONS = frozenset({
    "review",
    "possible-control-flow",
    "possible-data",
    "possible-invalid",
    "insufficient-evidence",
    "arm-plausible",
    "thumb-plausible",
})
_FORBIDDEN_FIELDS = frozenset({
    "verified", "range_verified", "encoding_verified",
    "winner", "confidence", "score", "end", "status",
    "select-for-peel", "selection", "disposition",
})
_SUGGEST_KEYS = frozenset({
    "address", "mode", "action", "rationale",
    "provider", "model", "prompt_version", "input_hash", "deterministic",
})
_OPTIONAL_ADDITIVE = frozenset({
    "output_hash", "request_id", "temperature", "seed", "provider_version",
})


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def input_hash(obj) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def _parse_addr(value) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid address")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("invalid address")
        return value
    s = str(value).strip()
    if not s or s.startswith("-"):
        raise ValueError("invalid address")
    return int(s, 0)


def _key(row: dict) -> tuple[int, str] | None:
    try:
        addr = _parse_addr(row.get("address"))
    except (ValueError, TypeError):
        return None
    mode = str(row.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return None
    return (addr, mode)


def build_request(row: dict) -> dict:
    types: list[str] = []
    for item in row.get("evidence_items") or []:
        if isinstance(item, dict) and item.get("type"):
            types.append(str(item["type"]))
    return {
        "address": str(row.get("address")),
        "mode": str(row.get("mode") or "").strip().lower(),
        "disposition": row.get("disposition"),
        "sources": list(row.get("sources") or []),
        "classes": list(row.get("classes") or []),
        "evidence_types": types,
        "deterministic": row.get("deterministic"),
    }


class SuggestProvider:
    """Pure request/response. No tools, shell, ROM, or verification."""

    def suggest(self, request: dict) -> dict:
        raise NotImplementedError


class FakeProvider(SuggestProvider):
    """Fixture provider. Never calls a network LLM."""

    def __init__(self) -> None:
        self.responses: dict[tuple[int, str], dict] = {}
        self.failures: dict[tuple[int, str], str] = {}
        self.model = "fixture"
        self.name = "fake"

    def suggest(self, request: dict) -> dict:
        key = _key(request)
        if key is None:
            raise ValueError("invalid request key")
        kind = self.failures.get(key)
        if kind == "timeout":
            raise TimeoutError("fake timeout")
        if kind == "exception":
            raise RuntimeError("fake provider exception")
        if kind == "empty":
            return {}
        if kind == "malformed":
            return {"not": "a suggestion"}
        if key in self.responses:
            return dict(self.responses[key])
        disp = request.get("disposition")
        mode = request.get("mode")
        if disp == "agreed-seed":
            action = "possible-control-flow"
        elif disp == "conflicted" and mode == "arm":
            action = "arm-plausible"
        elif disp == "conflicted" and mode == "thumb":
            action = "thumb-plausible"
        elif disp == "heuristic":
            action = "possible-data"
        else:
            action = "review"
        return {
            "address": request["address"],
            "mode": mode,
            "action": action,
            "rationale": "fake-fixture",
        }


def _validate_suggestion(raw, key: tuple[int, str], req: dict, meta: dict) -> dict | None:
    if not isinstance(raw, dict) or not raw:
        return None
    if "address" not in raw or "mode" not in raw:
        return None
    for k in _FORBIDDEN_FIELDS:
        if k in raw:
            return None
    action = raw.get("action")
    if action not in _ALLOWED_ACTIONS:
        return None
    try:
        addr = _parse_addr(raw.get("address"))
    except (ValueError, TypeError):
        return None
    mode = str(raw.get("mode") or "").strip().lower()
    if mode not in _MODES:
        return None
    if (addr, mode) != key:
        return None
    if raw.get("deterministic") is True:
        return None
    out = {
        "address": req["address"],
        "mode": req["mode"],
        "action": action,
        "rationale": str(raw["rationale"]) if "rationale" in raw else "",
        "provider": meta["provider"],
        "model": meta["model"],
        "prompt_version": meta["prompt_version"],
        "input_hash": meta["input_hash"],
        "deterministic": False,
    }
    for k in _OPTIONAL_ADDITIVE:
        if k in raw and k not in _FORBIDDEN_FIELDS:
            out[k] = raw[k]
    return out


def _resolve_provider(name: str) -> SuggestProvider:
    if name == "fake":
        return FakeProvider()
    from llm_providers import MissingCredentialError, provider_for_name, real_provider_names

    if name not in real_provider_names():
        raise ValueError(f"unsupported provider: {name}")
    try:
        return provider_for_name(name)
    except MissingCredentialError as exc:
        raise ValueError(str(exc)) from exc


def suggest(phase7a: dict, provider: SuggestProvider | None = None) -> dict:
    prov = provider if provider is not None else FakeProvider()
    meta_run = {
        "provider": getattr(prov, "name", "fake"),
        "model": getattr(prov, "model", "fixture"),
        "prompt_version": PROMPT_VERSION,
    }
    pv = getattr(prov, "provider_version", None)
    if pv:
        meta_run["provider_version"] = pv
    suggestions: list[dict] = []
    errors: list[dict] = []
    requests: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for row in phase7a.get("skipped") or []:
        key = _key(row)
        if key is None:
            continue
        if key in seen:
            continue
        seen.add(key)
        disp = row.get("disposition")
        if disp not in _TARGET_DISP:
            continue
        req = build_request(row)
        req_hash = input_hash(req)
        requests.append(req)
        per = {
            **meta_run,
            "input_hash": req_hash,
        }
        addr_s, mode_s = req["address"], req["mode"]
        try:
            raw = prov.suggest(req)
        except TimeoutError:
            errors.append({"address": addr_s, "mode": mode_s, "error": "timeout"})
            continue
        except Exception:
            errors.append({"address": addr_s, "mode": mode_s, "error": "provider-exception"})
            continue
        validated = _validate_suggestion(raw, key, req, per)
        if validated is None:
            errors.append({"address": addr_s, "mode": mode_s, "error": "invalid-suggestion"})
            continue
        suggestions.append(validated)
    return {
        "format": "gba-mapper-llm-suggestion",
        "version": 1,
        "run": {
            **meta_run,
            "input_hash": input_hash({"requests": requests}),
        },
        "suggestions": suggestions,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    p.add_argument(
        "--provider",
        default="fake",
        help="suggestion provider (default: fake; see docs/phase8c-real-llm.md)",
    )
    a = p.parse_args(argv)
    try:
        provider = _resolve_provider(a.provider)
    except ValueError as exc:
        p.error(str(exc))
    phase7a = json.loads(a.input.read_text())
    result = suggest(phase7a, provider)
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
