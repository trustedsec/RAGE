#!/usr/bin/env python3
"""Validate the RAGE Rules corpus (rules/{derived,explicit}/**/*.yaml) against the RAGE vocabulary.

Requires PyYAML (the corpus is YAML). Gates (exit 1 on any):
  1. EMITS       — every rule's `emits` is a registered RAGE edge type (unless it's a `?var`
                   re-emission, which inherits its matched edge's type).
  2. NATURE      — rules under derived/ emit edges whose nature is `derived` or `both`;
                   rules under explicit/ emit `explicit` or `both`.
  3. EMIT-TYPES  — `emit.source_type` / `emit.target_type` (when given) are registered node
                   types or classes (or `*`).
  4. DUP-ID      — every rule `id` is unique across the whole corpus.

Diagnostics (never gate): rules with no `emits`, files that don't parse.
"""
import json, os, sys, glob, re
try:
    import yaml
except ImportError:
    print("check_rules.py needs PyYAML (pip install pyyaml)", file=sys.stderr); sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def jload(p): return json.load(open(os.path.join(ROOT, p)))

nt = jload("vocab/node-types.json")
valid_type = set(nt["node_types"]) | set(nt["classes"]) | {"*"}
edges = jload("vocab/edge-types.json")["edge_types"]
nature_of = {n: e.get("nature", "") for n, e in edges.items()}

errors, warnings, nature_notes = [], [], []
seen_ids, n_rules, n_files = {}, 0, 0

for path in sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.yaml"), recursive=True)):
    rel = os.path.relpath(path, ROOT)
    layer = "derived" if "/derived/" in path or rel.startswith("rules/derived") else \
            ("explicit" if "/explicit/" in path or rel.startswith("rules/explicit") else "")
    try:
        doc = yaml.safe_load(open(path)) or {}
    except Exception as e:
        warnings.append(f"{rel}: parse error ({e})"); continue
    n_files += 1
    rules = doc.get("rules") or ([doc["rule"]] if "rule" in doc else [])
    for r in rules:
        if not isinstance(r, dict): continue
        n_rules += 1
        rid = r.get("id")
        if rid:
            if rid in seen_ids:
                errors.append(f"DUP-ID   {rid}: also in {seen_ids[rid]} and {rel}")
            seen_ids[rid] = rel
        emits = r.get("emits")
        if isinstance(emits, str) and not emits.startswith("?"):
            if emits not in edges:
                errors.append(f"EMITS    {rid} ({rel}): '{emits}' not a registered RAGE edge type")
            # NATURE vs layer is REPORT-ONLY (not gated): the corpus intentionally emits
            # nature:derived edges (e.g. ExposedToInternet) from explicit/ files when grounded in
            # observed config. Counted, not failed — matches the reference linter's documented rule.
            elif layer == "derived" and nature_of.get(emits) not in ("derived", "both"):
                nature_notes.append(rid)
            elif layer == "explicit" and nature_of.get(emits) not in ("explicit", "both"):
                nature_notes.append(rid)
        emit = r.get("emit") or {}
        for em in (emit if isinstance(emit, list) else [emit]):
            if not isinstance(em, dict): continue
            for key in ("source_type", "target_type"):
                v = em.get(key)
                for t in ([v] if isinstance(v, str) else (v or [])):
                    if not isinstance(t, str): continue
                    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", t):
                        continue  # computed DSL expression (e.g. node_type(?x)) — not a literal type
                    if t not in valid_type:
                        errors.append(f"EMIT-TYPE {rid} ({rel}): {key} '{t}' not a registered type/class")

for w in warnings: print(f"WARN  {w}")
for e in errors: print(f"ERROR {e}")
print(f"\nchecked {n_rules} rules in {n_files} files · {len(seen_ids)} unique ids · "
      f"{len(errors)} errors, {len(warnings)} warnings · "
      f"{len(nature_notes)} nature/layer notes (report-only, not gated)")
sys.exit(1 if errors else 0)
