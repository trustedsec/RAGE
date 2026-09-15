#!/usr/bin/env python3
"""Reference validator for the RAGE format.

    python3 rage_validate.py graph.rage.ndjson

Each record is validated against its `../schemas/<kind>.schema.json` using **full JSON Schema**
(the `jsonschema` library — `pip install -r requirements.txt`): enums, const, types, required,
`allOf`/`if-then` (e.g. derived⇒evidence), and formats. If `jsonschema` is absent it falls back to
a stdlib const/enum/type/required subset and prints a loud DEGRADED warning to stderr — so
enforcement is never silently reduced. Beyond the schema it checks referential integrity (edge
source/target and finding/surface resource_id point at real nodes; path.edge_ids reference real
edges; edge_id unique), taxonomy endpoint conformance, and the manifest-first/NDJSON rules.
Exit 0 = valid, 1 = problems (each with its line number).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"

try:
    from jsonschema import Draft202012Validator, FormatChecker
    _FULL_JSONSCHEMA = True
except ImportError:
    _FULL_JSONSCHEMA = False

_JSON_TYPES = {
    "string": str, "number": (int, float), "integer": int,
    "object": dict, "array": list, "boolean": bool,
}


def _schema_for(kind: str) -> dict:
    f = SCHEMAS / f"{kind}.schema.json"
    return json.loads(f.read_text()) if f.exists() else {}


def _schema_errors(rec: dict, schema: dict, _cache: dict = {}) -> list[str]:
    """Validate a record against its schema — full JSON Schema via `jsonschema` when available,
    else the stdlib subset below."""
    if not schema:
        return []
    if _FULL_JSONSCHEMA:
        key = schema.get("$id") or id(schema)
        v = _cache.get(key)
        if v is None:
            v = Draft202012Validator(schema, format_checker=FormatChecker())
            _cache[key] = v
        return [e.message for e in v.iter_errors(rec)]
    return _check_against_schema(rec, schema)


def _check_against_schema(rec: dict, schema: dict) -> list[str]:
    """Stdlib fallback: the const/enum/type/required subset (used only when `jsonschema` is absent)."""
    out: list[str] = []
    if not schema:
        return out
    for field in schema.get("required", []):
        if field not in rec:
            out.append(f"missing required field '{field}'")
    for name, spec in schema.get("properties", {}).items():
        if name not in rec or not isinstance(spec, dict):
            continue
        v = rec[name]
        if "const" in spec and v != spec["const"]:
            out.append(f"field '{name}'={v!r} must be {spec['const']!r}")
        if "enum" in spec and v not in spec["enum"]:
            out.append(f"field '{name}'={v!r} not in {spec['enum']}")
        t = spec.get("type")
        if t and t in _JSON_TYPES and not isinstance(v, _JSON_TYPES[t]):
            # bool is a subclass of int — don't let it satisfy "number"/"integer"
            if not (t in ("number", "integer") and isinstance(v, bool)):
                out.append(f"field '{name}' should be {t}")
    return out


def _vocab():
    """Load the node/edge registries for taxonomy-aware endpoint checks. Returns
    (node_type->class, edge_type->{'source':set,'target':set}); empty if absent."""
    try:
        nt = json.loads((ROOT / "vocab" / "node-types.json").read_text())
        et = json.loads((ROOT / "vocab" / "edge-types.json").read_text())
    except FileNotFoundError:
        return {}, {}
    cls = {n: v.get("class") for n, v in nt["node_types"].items()}
    edges = {n: {"source": set(e.get("source", [])), "target": set(e.get("target", []))}
             for n, e in et["edge_types"].items()}
    return cls, edges


def _required(kind: str) -> list[str]:
    f = SCHEMAS / f"{kind}.schema.json"
    if not f.exists():
        return []
    return json.loads(f.read_text()).get("required", [])


def validate(path: Path) -> list[str]:
    errs: list[str] = []
    records: list[tuple[int, dict]] = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as e:
            errs.append(f"line {n}: not valid JSON ({e.msg})")
            continue
        if not isinstance(rec, dict) or "kind" not in rec:
            errs.append(f"line {n}: record has no 'kind'")
            continue
        records.append((n, rec))

    if not records:
        return ["empty file: no records"]
    if records[0][1].get("kind") != "manifest":
        errs.append(f"line {records[0][0]}: first record must be kind=manifest")

    node_type_of: dict[str, str] = {}
    evidence_ids: set[str] = set()
    edge_ids: dict[str, int] = {}
    schemas = {k: _schema_for(k) for k in
               ("manifest", "node", "edge", "fact", "evidence", "finding", "surface", "path")}
    for n, rec in records:
        kind = rec.get("kind", "")
        for problem in _schema_errors(rec, schemas.get(kind, {})):
            errs.append(f"line {n}: {kind} {problem}")
        if kind == "node":
            node_type_of[str(rec.get("node_id"))] = str(rec.get("node_type"))
        elif kind == "evidence":
            evidence_ids.add(str(rec.get("evidence_id")))
        elif kind == "edge" and rec.get("edge_id") is not None:
            eid = str(rec["edge_id"])
            if eid in edge_ids:
                errs.append(f"line {n}: duplicate edge_id '{eid}' (also line {edge_ids[eid]})")
            edge_ids[eid] = n
    node_ids = set(node_type_of)
    cls, edge_vocab = _vocab()

    def endpoint_ok(allowed: set[str], nt: str) -> bool:
        # open registry: only judged when the type is registered; '*' or class match passes
        if not allowed or "*" in allowed or nt not in cls:
            return True
        return nt in allowed or cls.get(nt) in allowed

    for n, rec in records:
        kind = rec.get("kind", "")
        if kind == "edge":
            etype = rec.get("type")
            for end in ("source", "target"):
                v = rec.get(end)
                if v is not None and v not in node_ids:
                    errs.append(f"line {n}: edge {end} points at unknown node '{v}'")
                elif v is not None and etype in edge_vocab and v in node_type_of:
                    if not endpoint_ok(edge_vocab[etype][end], node_type_of[v]):
                        errs.append(f"line {n}: edge {etype} {end} node is {node_type_of[v]!r}, "
                                    f"not an allowed {end} type {sorted(edge_vocab[etype][end])}")
            if rec.get("nature") == "derived" and not rec.get("evidence"):
                errs.append(f"line {n}: derived edge is missing evidence")
        elif kind == "finding":
            v = rec.get("resource_id")
            if v is not None and v not in node_ids:
                errs.append(f"line {n}: finding resource_id points at unknown node '{v}'")
        elif kind == "surface":
            # surfaces may sit on a sub-resource probe site rather than a graph node; only enforce
            # node membership when the resource_id is written as a node_id (the provider|...|native grammar).
            v = rec.get("resource_id")
            if v is not None and "|" in str(v) and v not in node_ids:
                errs.append(f"line {n}: surface resource_id looks like a node_id but is unknown '{v}'")
        elif kind == "path":
            for eid in (rec.get("edge_ids") or []):
                if str(eid) not in edge_ids:
                    errs.append(f"line {n}: path references unknown edge_id '{eid}'")
    return errs


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: rage_validate.py <graph.rage.ndjson>", file=sys.stderr)
        return 2
    if not _FULL_JSONSCHEMA:
        print("WARNING: `jsonschema` not installed — DEGRADED validation (stdlib subset only). "
              "Install it for full JSON Schema enforcement: pip install -r requirements.txt",
              file=sys.stderr)
    path = Path(argv[1])
    if not path.exists():
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    errs = validate(path)
    if not errs:
        print(f"VALID — {path}")
        return 0
    print(f"INVALID — {len(errs)} problem(s) in {path}:")
    for e in errs:
        print(f"  {e}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
