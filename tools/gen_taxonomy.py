#!/usr/bin/env python3
"""Generate TAXONOMY.md from RAGE's own registries. Reads only RAGE files — RAGE is the
source of truth. Re-run after editing any registry:  python3 tools/gen_taxonomy.py"""
import json, os
from collections import defaultdict

RAGE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def r(p): return json.load(open(os.path.join(RAGE, p)))
def esc(s): return str(s).replace("|", "\\|").replace("\n", " ").strip()

nt = r("vocab/node-types.json")
et = r("vocab/edge-types.json")
dv = r("rules/derivation.json")["rules"]
provs = {p: r(f"providers/{p}.json") for p in ("aws", "gcp", "azure")}
PT = {"aws": "AWS", "gcp": "GCP", "azure": "Azure"}

# reverse index: node_type -> {provider: [resource_types]}
reverse = defaultdict(lambda: defaultdict(list))
for p, reg in provs.items():
    for rt, m in reg["resources"].items():
        reverse[m["node_type"]][p].append(rt)

L = []
def w(s=""): L.append(s)

nclasses, ntypes = len(nt["classes"]), len(nt["node_types"])
nedges, ncats = len(et["edge_types"]), len(et["categories"])
counts = {p: len(provs[p]["resources"]) for p in provs}
n_facts = sum(len(provs[p].get("facts", [])) for p in provs)
# exposure-db (optional registry)
import collections as _c
_expo = {}
_expo_vocab = None
try:
    _expo_vocab = json.load(open(os.path.join(RAGE, "exposure-db", "vocabulary.json")))
    for _p in ("aws", "gcp", "azure"):
        _expo[_p] = json.load(open(os.path.join(RAGE, "exposure-db", f"{_p}.json")))
except FileNotFoundError:
    _expo = {}
n_expo = sum(len(s["sites"]) for reg in _expo.values() for s in reg["services"].values()) if _expo else 0

w("# RAGE Taxonomy Corpus")
w()
w("The complete corpus behind the **Relational Attack Graph Exchange** — the provider-independent")
w("node & edge vocabularies, the concrete **AWS / GCP / Azure** resource mappings, the collection")
w("recipes that produce them, and the derivation rules that infer edges.")
w()
w("This document is **generated from RAGE's own registries** (`vocab/`, `rules/`, `providers/`) —")
w("RAGE is the source of truth. Regenerate with `python3 tools/gen_taxonomy.py`; do not hand-edit.")
w()
w("Both registries are **open**: an unknown `node_type` or edge `type` is legal — map it to the")
w("nearest generic type and keep the native string verbatim. Everything below is the grounded")
w("baseline every conforming producer and consumer can rely on.")
w()
w(f"**At a glance:** {nclasses} node classes · {ntypes} generic node types · {nedges} edge types in "
  f"{ncats} categories · {counts['aws']} AWS + {counts['gcp']} GCP + {counts['azure']} Azure "
  f"concrete resource types · {n_facts} fact/relationship recipes · {len(dv)} derivation rules"
  + (f" · {n_expo} exposure sites." if n_expo else "."))
w()
w("## Contents")
w("1. [Node taxonomy](#1-node-taxonomy)")
w("2. [Provider resource corpus & collection recipes](#2-provider-resource-corpus--collection-recipes)")
w("3. [Generic type → concrete resources](#3-generic-type--concrete-resources)")
w("4. [Service coverage](#4-service-coverage)")
w("5. [Edge taxonomy & derivation rules](#5-edge-taxonomy--derivation-rules)")
if n_expo:
    w("6. [Exposure DB](#6-exposure-db)")
w()
w("---")
w()

# ============ 1. NODES ============
w("## 1. Node taxonomy")
w()
w("A concrete resource carries **both** a generic `node_type` (its security role) and its verbatim")
w("`provider_type`. Rules prefer the generic type. `vocab/node-types.json` is the registry.")
w()
w("### 1.1 Classes")
w()
w("| Class | Description |")
w("|---|---|")
# preserve class order as it appears in node_types
class_order = list(nt["classes"].keys())
for c in class_order:
    w(f"| **{c}** | {esc(nt['classes'][c]['doc'])} |")
w()
w("### 1.2 Generic node types")
w()
by_class = defaultdict(list)
for name, t in nt["node_types"].items():
    by_class[t["class"]].append((name, t))
for c in class_order:
    items = by_class.get(c, [])
    w(f"#### {c} ({len(items)})")
    w()
    w("| Type | Description |")
    w("|---|---|")
    for name, t in items:
        w(f"| `{name}` | {esc(t['doc'])} |")
    w()
w("---")
w()

# ============ 2. PROVIDER CORPUS ============
w("## 2. Provider resource corpus & collection recipes")
w()
w("Every native resource type each provider defines, the RAGE node type it maps to, and the recipe a")
w("conforming **RAGE Collector** uses to enumerate it. `providers/{aws,gcp,azure}.json` are the registries.")
w()
for i, p in enumerate(("aws", "gcp", "azure"), 1):
    res = provs[p]["resources"]
    w(f"### 2.{i} {PT[p]} ({len(res)} resource types)")
    w()
    w("| Resource type | Node type | Scope | Enumerate | Required permissions |")
    w("|---|---|---|---|---|")
    for rt, m in res.items():
        op = (m.get("enumerate") or {}).get("operation", "")
        perms = ", ".join(f"`{x}`" for x in m.get("required_permissions", [])) or "—"
        detail = ""
        if m.get("detail"):
            detail = f" +{len(m['detail'])} detail"
        w(f"| `{rt}` | `{m['node_type']}` | {esc(m.get('scope',''))} | `{esc(op)}`{detail} | {perms} |")
    w()
w("> `+N detail` marks resources with an N-step enrichment chain (e.g. list → get → download) in the")
w("> registry's `detail` field. See `providers/*.json` for the full recipe (bind/capture per step).")
w()
w("### 2.4 Fact / relationship recipes")
w()
w("Node recipes yield inventory; **fact recipes** collect the policies, bindings, trust, memberships,")
w("network rules, and credentials that back *edges*. Guardrail facts (SCPs, deny assignments) have an")
w("empty `backs` — they constrain edges to BLOCKED. `providers/*.json` `facts[]` are the registries.")
w()
for p in ("aws", "gcp", "azure"):
    facts = provs[p].get("facts", [])
    if not facts:
        continue
    w(f"**{PT[p]}** ({len(facts)} fact recipes)")
    w()
    w("| Fact kind | Collect | Backs edges | Required permissions |")
    w("|---|---|---|---|")
    for f in facts:
        op = (f.get("collect") or {}).get("operation", "")
        backs = ", ".join(f"`{e}`" for e in f.get("backs", [])) or "_(guardrail — blocks)_"
        perms = ", ".join(f"`{x}`" for x in f.get("required_permissions", [])) or "—"
        w(f"| `{f.get('kind','')}` | `{esc(op)}` | {backs} | {perms} |")
    w()
w("---")
w()

# ============ 3. REVERSE ============
w("## 3. Generic type → concrete resources")
w()
w("The corpus inverted — which real resources realize each generic type across clouds. The completeness")
w("view: what is backed by collection everywhere vs. what is derivation-only.")
w()
ordered = list(nt["node_types"].keys())
for t in ordered:
    if t not in reverse: continue
    w(f"#### `{t}`")
    for p in ("aws", "gcp", "azure"):
        if reverse[t].get(p):
            w(f"- **{PT[p]}:** " + ", ".join(f"`{x}`" for x in sorted(reverse[t][p])))
    w()
unbacked = [t for t in ordered if t not in reverse]
if unbacked:
    w("### 3.x Derivation-only / abstract types")
    w()
    w("Generic types with no directly-collected resource — they arise from derivation, identity")
    w("expansion, or as class-level fallbacks:")
    w()
    w(", ".join(f"`{t}`" for t in unbacked))
    w()
w("---")
w()

# ============ 4. SERVICES ============
w("## 4. Service coverage")
w()
w("Provider services and the generic types they contribute. `attack_relevance` is the curated risk")
w("rating; `collected: false` marks a real service RAGE recognizes but doesn't yet enumerate as nodes.")
w()
for i, p in enumerate(("aws", "gcp", "azure"), 1):
    svcs = provs[p]["services"]
    w(f"### 4.{i} {PT[p]} ({len(svcs)} services)")
    w()
    w("| Service | Name | Generic types | Relevance | Collected |")
    w("|---|---|---|---|---|")
    for key, s in svcs.items():
        gt = ", ".join(f"`{g}`" for g in s.get("generic_types", []))
        collected = "no" if s.get("collected") is False else "yes"
        w(f"| `{key}` | {esc(s.get('name',''))} | {gt} | {esc(s.get('attack_relevance',''))} | {collected} |")
    w()
w("---")
w()

# ============ 5. EDGES + RULES ============
w("## 5. Edge taxonomy & derivation rules")
w()
w("Directed capability/relationship edges. Each declares its category, `relationship_kind`, `nature`")
w("(explicit = observed, derived = synthesized, both), the node types it connects, whether it is")
w("**walkable** (attacker-traversable) and **high-value**. The **derivation rule** (`rules/derivation.json`)")
w("gives the conditions and the concrete per-cloud permissions/triggers that realize it.")
w()
w("### 5.1 Categories")
w()
w("| Category | Relationship kinds | Description |")
w("|---|---|---|")
for c, cv in et["categories"].items():
    rks = ", ".join(f"`{k}`" for k in cv.get("relationship_kinds", []))
    w(f"| `{c}` | {rks} | {esc(cv['doc'])} |")
w()
w("### 5.2 Edge states")
w()
w("| State | Meaning |")
w("|---|---|")
for s, d in et["edge_states"].items():
    w(f"| `{s}` | {esc(d)} |")
w()
w("### 5.3 Edge types")
w()
cat_order = list(et["categories"].keys())
by_cat = defaultdict(list)
for name, e in et["edge_types"].items():
    by_cat[e["category"]].append((name, e))
for cat in cat_order + [c for c in by_cat if c not in cat_order]:
    if cat not in by_cat: continue
    w(f"#### {cat}")
    w()
    for name, e in by_cat[cat]:
        walk = "walkable" if e["walkable"] else "non-walkable"
        bw = e.get("base_weight")
        hv = " · **high-value**" if e["high_value"] else ""
        meta = f"{e['relationship_kind']} · {e['nature']} · {walk}"
        if bw is not None: meta += f" (w={bw})"
        meta += hv
        src = ", ".join(f"`{x}`" for x in e["source"]) or "`*`"
        tgt = ", ".join(f"`{x}`" for x in e["target"]) or "`*`"
        w(f"##### `{name}`")
        w(f"*{meta}*")
        w()
        w(f"{src} → {tgt}")
        w()
        if e["doc"]: w(esc(e["doc"]))
        rule = dv.get(name, {})
        w()
        w(f"**Derivation rule** — nature `{rule.get('nature', e['nature'])}`"
          + ("; conditions: " + ", ".join(f"`{c}`" for c in rule["conditions"]) if rule.get("conditions") else "")
          + ("" if rule.get("providers") else "; realized directly (no per-cloud specialization)"))
        if rule.get("providers"):
            w()
            for p in ("aws", "gcp", "azure"):
                pv = rule["providers"].get(p)
                if pv is None: continue
                bits = []
                if pv.get("permissions"): bits.append(", ".join(f"`{x}`" for x in pv["permissions"]))
                if pv.get("trigger"):
                    tr = pv["trigger"]
                    bits.append("; ".join(tr) if isinstance(tr, list) else str(tr))
                line = f"- **{PT[p]}:** " + (" — ".join(bits) if bits else "")
                if pv.get("note"): line += (" — " if bits else "") + esc(pv["note"])
                w(line.rstrip())
        w()
w("---")
w()

# ============ 6. EXPOSURE DB ============
if n_expo:
    w("## 6. Exposure DB")
    w()
    w("Every place a customer-controlled **credential/secret can leak**, mapped to the RAGE edge it")
    w("emits, its collection recipe, where it sits, and what leaks. `exposure-db/*.json` are the")
    w("registries; `exposure-db/vocabulary.json` is the controlled vocabulary.")
    w()
    # distributions
    emits_ct, sev_ct, dk_ct = _c.Counter(), _c.Counter(), _c.Counter()
    for reg in _expo.values():
        for s in reg["services"].values():
            for site in s["sites"]:
                emits_ct[site.get("emits")] += 1
                sev_ct[site.get("severity")] += 1
                for dk in site.get("data_kinds", []):
                    dk_ct[dk] += 1
    w(f"**{n_expo} exposure sites** across {sum(len(r['services']) for r in _expo.values())} service "
      f"catalogs — "
      + ", ".join(f"{len(_expo[p]['services'])} {PT[p]} services / "
                  f"{sum(len(s['sites']) for s in _expo[p]['services'].values())} sites" for p in ('aws','gcp','azure')) + ".")
    w()
    w("| Emits (RAGE edge) | Sites |")
    w("|---|---|")
    for e, n in emits_ct.most_common():
        w(f"| `{e}` | {n} |")
    w()
    w("**By severity:** " + " · ".join(f"{k} {sev_ct[k]}" for k in ("critical","high","medium","low") if sev_ct.get(k)))
    w()
    w("**Top data kinds:** " + ", ".join(f"`{k}` ({n})" for k, n in dk_ct.most_common(12)))
    w()
    w("**Vocabulary** — `location_kind` (" + str(len(_expo_vocab["location_kind"])) + "), `data_kinds` ("
      + str(len(_expo_vocab["data_kinds"])) + "), `access_mode` (" + ", ".join(f"`{a}`" for a in _expo_vocab["access_mode"]) + ").")
    w()
    w("---")
    w()

w(f"*{nclasses} classes · {ntypes} node types · {nedges} edges · {len(dv)} derivation rules · "
  f"{counts['aws']}+{counts['gcp']}+{counts['azure']} resource types"
  + (f" · {n_expo} exposure sites" if n_expo else "") + ". "
  f"Generated from RAGE registries by `tools/gen_taxonomy.py`.*")

out = os.path.join(RAGE, "TAXONOMY.md")
open(out, "w").write("\n".join(L) + "\n")
print(f"wrote TAXONOMY.md: {len(L)} lines, {os.path.getsize(out)} bytes")
