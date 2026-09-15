#!/usr/bin/env python3
"""Referential-integrity checker for the RAGE registries. Zero-dependency (stdlib only).

Verifies the corpus is internally consistent:
  - every provider mapping's node_type exists in the node-type registry
  - every derivation rule names an edge in the edge-type registry (and vice versa)
  - every edge's source/target names a known node type, class, or the wildcard '*'
  - every resource's `service` appears in that provider's services index

Usage:  python3 validate/check_registries.py        # exits non-zero on any error
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def load(p): return json.load(open(os.path.join(ROOT, p)))

errors, warnings = [], []
def err(m): errors.append(m)
def warn(m): warnings.append(m)

nt = load("vocab/node-types.json")
et = load("vocab/edge-types.json")
dv = load("rules/derivation.json")

node_types = set(nt["node_types"])
classes = set(nt["classes"])
edge_types = set(et["edge_types"])
categories = set(et["categories"])
valid_ref = node_types | classes | {"*"}

# 1. edge source/target reference known node types/classes; category is known;
#    and the edge's relationship_kind is one its category declares.
for name, e in et["edge_types"].items():
    cat = e.get("category")
    if cat not in categories:
        err(f"edge {name}: unknown category {cat!r}")
    else:
        declared = set(et["categories"][cat].get("relationship_kinds", []))
        if e.get("relationship_kind") not in declared:
            err(f"edge {name}: relationship_kind {e.get('relationship_kind')!r} "
                f"not in category {cat!r} kinds {sorted(declared)}")
    for side in ("source", "target"):
        for ref in e.get(side, []):
            if ref not in valid_ref:
                err(f"edge {name}: {side} references unknown type/class {ref!r}")

# 1b. every service's generic_types is registered AND (for services with resources) equals the
#     union of its resources' node types — this is what caught the stale-generic_types drift (F1.2/F3.3).
for prov in ("aws", "gcp", "azure"):
    reg = load(f"providers/{prov}.json")
    res_types = {}
    for rt, m in reg["resources"].items():
        res_types.setdefault(m.get("service"), set()).add(m.get("node_type"))
    for svc, s in reg.get("services", {}).items():
        declared = set(s.get("generic_types", []))
        for g in declared:
            if g not in node_types:
                err(f"{prov} service {svc}: generic_type {g!r} not in node-type registry")
        actual = res_types.get(svc)
        if actual and declared != actual:
            err(f"{prov} service {svc}: generic_types {sorted(declared)} != its resources' "
                f"node types {sorted(actual)}")
        if not actual and not s.get("collected", True) is False:
            warn(f"{prov} service {svc}: no resources and not marked collected:false")

# 2. derivation rules <-> edge types are 1:1
for name in dv["rules"]:
    if name not in edge_types:
        err(f"rule {name}: no matching edge type in vocab/edge-types.json")
for name in edge_types:
    if name not in dv["rules"]:
        warn(f"edge {name}: no derivation rule in rules/derivation.json")

# 2b. condition tokens are documented in the (open) conditions registry
try:
    cond_reg = set(load("vocab/conditions.json")["conditions"])
    for name, r in dv["rules"].items():
        for c in r.get("conditions", []):
            if c not in cond_reg:
                warn(f"rule {name}: condition {c!r} not in vocab/conditions.json (open registry)")
except FileNotFoundError:
    warn("vocab/conditions.json missing")

# 3. provider mappings + recipes reference known node types and services
for prov in ("aws", "gcp", "azure"):
    reg = load(f"providers/{prov}.json")
    services = set(reg.get("services", {}))
    for rt, m in reg["resources"].items():
        if m.get("node_type") not in node_types:
            err(f"{prov} {rt}: node_type {m.get('node_type')!r} not in node-type registry")
        svc = m.get("service")
        if svc and svc not in services:
            warn(f"{prov} {rt}: service {svc!r} not in services index")
        if not (m.get("enumerate") or {}).get("operation"):
            warn(f"{prov} {rt}: no enumerate.operation (collection recipe incomplete)")

# 4. fact-collection recipes: each has an operation + permissions, and every `backs` edge is real.
n_facts = 0
for prov in ("aws", "gcp", "azure"):
    reg = load(f"providers/{prov}.json")
    for f in reg.get("facts", []):
        n_facts += 1
        kind = f.get("kind", "?")
        if not (f.get("collect") or {}).get("operation"):
            err(f"{prov} fact {kind}: no collect.operation")
        if not f.get("required_permissions"):
            err(f"{prov} fact {kind}: no required_permissions")
        for e in f.get("backs", []):
            if e not in edge_types:
                err(f"{prov} fact {kind}: backs unknown edge type {e!r}")

for w in warnings: print(f"WARN  {w}")
for e in errors: print(f"ERROR {e}")
n_res = sum(len(load(f"providers/{p}.json")["resources"]) for p in ("aws", "gcp", "azure"))
print(f"\nchecked: {len(node_types)} node types, {len(edge_types)} edges, "
      f"{len(dv['rules'])} rules, {n_res} resources, {n_facts} fact recipes · "
      f"{len(errors)} errors, {len(warnings)} warnings")
sys.exit(1 if errors else 0)
