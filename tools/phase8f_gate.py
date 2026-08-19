#!/usr/bin/env python3
"""Phase 8F explicit fail-closed gate. Not authority.

Consumes existing 7A selection, 8B EndMap, and 8E encoding verification.
Does not mint candidates, rewrite selection/disposition, generate ends,
or create encoding_verified / RANGE / Evidence.

    8F gate != selection
    8F gate != encoding_verified
    8F gate != RANGE
    eligible-for-peel != peel-ready

Usage:
  python3 tools/phase8f_gate.py INPUT --ends ENDS.json --encoding ENC.json
      [--eligibility-approval 8A.json]
      [--output PATH]
      [--execute-7b]
      [--execute-7c]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_MODES = frozenset({"arm", "thumb"})
_FORBIDDEN_OUT = frozenset({
    "winner", "selection", "disposition", "eligible-for-peel",
    "peel-ready", "end", "suggested_end", "encoding_verified",
    "range_verified", "Evidence", "rationale", "score",
})


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


def _index_7a(phase7a: dict) -> tuple[dict[tuple[int, str], dict], list[dict]]:
    rows: dict[tuple[int, str], dict] = {}
    errors: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for bucket in ("selected", "skipped"):
        for row in phase7a.get(bucket) or []:
            if not isinstance(row, dict):
                continue
            if "address" in row and not str(row.get("mode") or "").strip():
                errors.append({
                    "address": str(row.get("address")),
                    "mode": "",
                    "error": "address-only",
                })
                continue
            key = _key(row)
            if key is None:
                errors.append({
                    "address": str(row.get("address")),
                    "mode": str(row.get("mode") or ""),
                    "error": "invalid-key",
                })
                continue
            if key in seen:
                continue
            seen.add(key)
            rows[key] = row
    return rows, errors


def _index_ends(raw) -> tuple[dict[tuple[int, str], object], list[dict]]:
    out: dict[tuple[int, str], object] = {}
    errors: list[dict] = []
    if raw is None:
        return out, errors
    if not isinstance(raw, dict):
        errors.append({"error": "invalid-explicit-end"})
        return out, errors
    for k, spec in raw.items():
        if k in {"format", "version", "run", "errors"}:
            continue
        if not isinstance(k, str) or ":" not in k:
            errors.append({"error": "invalid-explicit-end"})
            continue
        addr_s, mode = k.rsplit(":", 1)
        mode = mode.strip().lower()
        if mode not in _MODES:
            errors.append({"address": addr_s, "mode": mode, "error": "invalid-explicit-end"})
            continue
        try:
            addr = _parse_addr(addr_s)
        except (ValueError, TypeError):
            errors.append({"address": addr_s, "mode": mode, "error": "invalid-explicit-end"})
            continue
        end_val = spec.get("end") if isinstance(spec, dict) else spec
        try:
            end = _parse_addr(end_val)
        except (ValueError, TypeError):
            errors.append({"address": addr_s, "mode": mode, "error": "invalid-explicit-end"})
            continue
        if end <= addr:
            errors.append({"address": addr_s, "mode": mode, "error": "invalid-explicit-end"})
            continue
        out[(addr, mode)] = spec
    return out, errors


def _index_8e(raw) -> tuple[dict[tuple[int, str], bool] | None, list[dict]]:
    errors: list[dict] = []
    if raw is None:
        return None, errors
    if not isinstance(raw, dict):
        errors.append({"error": "invalid-encoding-verification"})
        return None, errors
    if raw.get("format") != "gba-mapper-encoding-verification" or raw.get("version") != 1:
        errors.append({"error": "invalid-encoding-verification"})
        return None, errors
    run = raw.get("run") if isinstance(raw.get("run"), dict) else {}
    if run.get("deterministic") is not True:
        errors.append({"error": "invalid-encoding-verification"})
        return None, errors
    out: dict[tuple[int, str], bool] = {}
    seen: set[tuple[int, str]] = set()
    for item in raw.get("results") or []:
        if not isinstance(item, dict):
            continue
        key = _key(item)
        if key is None:
            errors.append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode") or ""),
                "error": "invalid-encoding-verification",
            })
            continue
        verified = item.get("encoding_verified") is True
        if key in seen and out.get(key) != verified:
            errors.append({
                "address": str(item.get("address")),
                "mode": key[1],
                "error": "conflicting-verification",
            })
            out[key] = False
            continue
        seen.add(key)
        out[key] = verified
    return out, errors


def _index_8a(raw) -> tuple[dict[tuple[int, str], str] | None, list[dict]]:
    if raw is None:
        return None, []
    errors: list[dict] = []
    if not isinstance(raw, dict):
        return None, [{"error": "eligibility-mismatch"}]
    if raw.get("format") != "gba-mapper-eligibility-approval" or raw.get("version") != 1:
        return None, [{"error": "eligibility-mismatch"}]
    items = raw.get("approvals")
    if items is None:
        items = raw.get("decisions")
    if not isinstance(items, list):
        return None, [{"error": "eligibility-mismatch"}]
    out: dict[tuple[int, str], str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        key = _key(item)
        if key is None:
            continue
        out[key] = str(item.get("eligibility") or "")
    return out, errors


def _evaluate(
    phase7a: dict,
    ends=None,
    encoding=None,
    eligibility_approval=None,
) -> dict:
    rows, errors = _index_7a(phase7a if isinstance(phase7a, dict) else {})
    end_map, end_errs = _index_ends(ends)
    errors.extend(end_errs)
    enc_map, enc_errs = _index_8e(encoding)
    errors.extend(enc_errs)
    eight_a, a_errs = _index_8a(eligibility_approval)
    errors.extend(a_errs)

    results: list[dict] = []
    ready_keys: set[tuple[int, str]] = set()

    for key, row in rows.items():
        addr_s = str(row.get("address"))
        mode_s = key[1]
        if row.get("selection") != "selected":
            errors.append({"address": addr_s, "mode": mode_s, "error": "not-selected"})
            continue
        if row.get("disposition") != "peel-ready":
            errors.append({"address": addr_s, "mode": mode_s, "error": "not-peel-ready"})
            continue
        if eight_a is not None and eight_a.get(key) != "eligible-for-peel":
            errors.append({"address": addr_s, "mode": mode_s, "error": "eligibility-mismatch"})
            continue
        if key not in end_map:
            errors.append({"address": addr_s, "mode": mode_s, "error": "missing-explicit-end"})
            continue
        if enc_map is None:
            if encoding is None:
                errors.append({
                    "address": addr_s, "mode": mode_s,
                    "error": "missing-encoding-verification",
                })
            continue
        if key not in enc_map:
            errors.append({
                "address": addr_s, "mode": mode_s,
                "error": "encoding-not-verified",
            })
            continue
        if enc_map[key] is not True:
            already = any(
                e.get("address") == addr_s and e.get("mode") == mode_s
                and e.get("error") == "conflicting-verification"
                for e in errors
            )
            if not already:
                errors.append({
                    "address": addr_s, "mode": mode_s,
                    "error": "encoding-not-verified",
                })
            continue
        ready_keys.add(key)
        results.append({
            "address": addr_s,
            "mode": mode_s,
            "gate": "ready",
        })

    if eight_a is not None:
        for key, elig in eight_a.items():
            if key in rows:
                continue
            if elig == "eligible-for-peel":
                errors.append({
                    "address": f"{key[0]:#x}",
                    "mode": key[1],
                    "error": "not-selected",
                })

    out = {
        "format": "gba-mapper-phase8f-result",
        "version": 1,
        "run": {"deterministic": True},
        "results": results,
        "errors": errors,
        "invoked": {"peel": False, "check": False},
    }
    for k in _FORBIDDEN_OUT:
        out.pop(k, None)
    out["_ready_keys"] = ready_keys
    out["_rows"] = rows
    return out


def gate(
    phase7a: dict,
    ends=None,
    encoding=None,
    eligibility_approval=None,
) -> dict:
    artifact = _evaluate(phase7a, ends, encoding, eligibility_approval)
    artifact.pop("_ready_keys", None)
    artifact.pop("_rows", None)
    return _public(artifact)


def _public(artifact: dict) -> dict:
    out = {
        "format": artifact["format"],
        "version": artifact["version"],
        "run": artifact["run"],
        "results": artifact["results"],
        "errors": artifact["errors"],
        "invoked": artifact["invoked"],
    }
    for k in _FORBIDDEN_OUT:
        out.pop(k, None)
    return out


def _filtered_7a(phase7a: dict, ready: set[tuple[int, str]], rows: dict) -> dict:
    selected = []
    for key in ready:
        row = dict(rows[key])
        selected.append(row)
    return {
        "selected": selected,
        "skipped": [],
        "unresolved": list(phase7a.get("unresolved") or []),
    }


def _default_peel(phase7a: dict, ends: dict) -> dict:
    from run_peel import PeelRunner
    return PeelRunner(write_labels=False, force_boundary=False).run(phase7a, ends)


def _default_check(peel_obj: dict, ends: dict) -> dict:
    from run_check import CheckRunner
    return CheckRunner(Path(".")).run(peel_obj, ends)


def orchestrate(
    phase7a: dict,
    ends=None,
    encoding=None,
    eligibility_approval=None,
    *,
    execute_7b: bool = False,
    execute_7c: bool = False,
    peel_runner=None,
    check_runner=None,
) -> dict:
    artifact = _evaluate(phase7a, ends, encoding, eligibility_approval)
    ready = artifact.pop("_ready_keys")
    rows = artifact.pop("_rows")
    if not execute_7b or not ready:
        return _public(artifact)
    filtered = _filtered_7a(phase7a, ready, rows)
    peel_fn = peel_runner or _default_peel
    peel_obj = peel_fn(filtered, ends)
    artifact["invoked"]["peel"] = True
    peel_ok = False
    for item in (peel_obj or {}).get("results") or []:
        if item.get("result") == "peel-emitted":
            peel_ok = True
        elif item.get("result") == "peel-failed":
            artifact["errors"].append({
                "address": str(item.get("address")),
                "mode": str(item.get("mode") or ""),
                "error": "7b-failed",
            })
    if execute_7c and peel_ok:
        check_fn = check_runner or _default_check
        check_obj = check_fn(peel_obj, ends)
        artifact["invoked"]["check"] = True
        for item in (check_obj or {}).get("results") or []:
            if item.get("result") in ("wire-failed", "check-failed"):
                artifact["errors"].append({
                    "address": str(item.get("address")),
                    "mode": str(item.get("mode") or ""),
                    "error": "7c-failed",
                })
    elif execute_7c and not peel_ok:
        artifact["errors"].append({"error": "7c-gate-failed"})
    return _public(artifact)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("input", type=Path, help="Phase 7A selection JSON")
    p.add_argument("--ends", type=Path, required=True, help="8B EndMap JSON")
    p.add_argument("--encoding", type=Path, required=True,
                   help="8E encoding-verification JSON")
    p.add_argument("--eligibility-approval", type=Path,
                   help="optional Phase 8A approval JSON")
    p.add_argument("--output", type=Path, help="write JSON here (default: stdout)")
    p.add_argument("--execute-7b", action="store_true",
                   help="invoke existing run_peel.py after gate (labels stay disabled)")
    p.add_argument("--execute-7c", action="store_true",
                   help="invoke existing run_check.py after peel-emitted")
    a = p.parse_args(argv)
    phase7a = json.loads(a.input.read_text())
    ends = json.loads(a.ends.read_text())
    encoding = json.loads(a.encoding.read_text())
    eight_a = json.loads(a.eligibility_approval.read_text()) if a.eligibility_approval else None
    result = orchestrate(
        phase7a, ends, encoding, eight_a,
        execute_7b=a.execute_7b,
        execute_7c=a.execute_7c,
    )
    blob = json.dumps(result, indent=2)
    if a.output is not None:
        a.output.write_text(blob + "\n")
    else:
        sys.stdout.write(blob + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
