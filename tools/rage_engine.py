#!/usr/bin/env python3
"""RAGE reference rule engine — actually EXECUTES the derived-rule corpus.

Loads rules/derived/**/*.yaml, matches each rule's `match` graph-pattern against a RAGE graph's
edges, evaluates its `where` predicates via the spec/rules.md function catalog, and emits new
`nature: derived` edges to a fixpoint (RULE-FORMAT.md semantics: monotonic, dedup on
type|source|target|scope, weakest-contributor state). This is the reference executor the format
lacked — proof the YAML corpus runs, not just lint-validates.

Scope (honest): it executes rules whose `emit.source`/`emit.target` are bound variables (~604/1059).
Rules whose emit refs are English prose, or whose `where` needs policy data the graph doesn't carry
(`effective_action_on`, `privilege_level`), are reported, not silently dropped — unresolved `where`
clauses downgrade the emitted edge to CONDITIONAL rather than fabricating certainty.

    python3 tools/rage_engine.py graph.rage.ndjson [--out augmented.rage.ndjson]

Needs PyYAML (pip install -r requirements.txt).
"""
from __future__ import annotations
import json, os, re, sys, glob, hashlib
try:
    import yaml
except ImportError:
    print("rage_engine needs PyYAML (pip install -r requirements.txt)", file=sys.stderr); sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATE_RANK = {"BLOCKED": 0, "UNKNOWN": 1, "CONDITIONAL": 2, "POTENTIAL": 2, "ACTIVE": 3}


# ----------------------------------------------------------------------------- rule loading
def _tok(x):
    """A match-clause token: {'v': None} -> '?v'; a string -> itself (edge type or '?v');
    anything else (empty/complex YAML key) -> None so the rule is skipped as unparseable."""
    if isinstance(x, dict) and len(x) == 1:
        k = next(iter(x))
        return ("?" + k) if isinstance(k, str) and k else None
    return x if isinstance(x, str) else None


def load_rules(root=ROOT):
    rules = []
    for f in sorted(glob.glob(os.path.join(root, "rules", "derived", "**", "*.yaml"), recursive=True)):
        doc = yaml.safe_load(open(f)) or {}
        rel = os.path.relpath(f, root)
        # provider scope: a rule's own applies_to, else the file's top-level applies_to, else the
        # provider directory it lives in (rules/derived/<provider>/…), else any.
        file_applies = doc.get("applies_to")
        parts = rel.split(os.sep)
        path_prov = parts[2] if len(parts) > 3 and parts[2] in ("aws", "gcp", "azure") else None
        for r in (doc.get("rules") or []):
            if not r.get("match") or not r.get("emit"):
                continue
            clauses = [[_tok(c[0]), _tok(c[1]), _tok(c[2])]
                       for c in r["match"] if isinstance(c, list) and len(c) == 3]
            if not clauses or any(None in c for c in clauses):
                continue  # unparseable match pattern
            r = dict(r)
            r["_match"] = clauses
            r["_file"] = rel
            r["applies_to"] = (r.get("applies_to") or file_applies
                               or ([path_prov] if path_prov else None) or ["*"])
            rules.append(r)
    return rules


# ----------------------------------------------------------------------------- graph
class Graph:
    def __init__(self):
        self.node_type = {}   # node_id -> node_type
        self.node_class = {}  # node_id -> class
        self.edges = []       # list of dicts
        self._key = set()     # dedup keys (type|source|target|scope)

    @classmethod
    def from_ndjson(cls, path, classes):
        g = cls()
        for line in open(path, encoding="utf-8"):
            if not line.strip():
                continue
            r = json.loads(line)
            k = r.get("kind")
            if k == "node":
                g.node_type[r["node_id"]] = r.get("node_type")
                g.node_class[r["node_id"]] = classes.get(r.get("node_type"))
            elif k == "edge":
                g._add_raw(r)
        return g

    def _add_raw(self, e):
        key = f'{e.get("type")}|{e.get("source")}|{e.get("target")}|{e.get("scope","")}'
        if key in self._key:
            return False
        self._key.add(key)
        self.edges.append(e)
        return True


def edge_id(etype, src, tgt, scope=""):
    h = hashlib.sha256(f"{etype}|{src}|{tgt}|{scope}".encode()).hexdigest()
    return "e_" + h[:16]


# ----------------------------------------------------------------------------- where evaluator
_LIST_RE = re.compile(r"^\[(.*)\]$")
_FN_RE = re.compile(r"^(\w+)\((.*)\)$")


def _split_args(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "[(":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _parse_list(t):
    inner = _LIST_RE.match(t).group(1)
    return [x.strip().strip("'\"") for x in _split_args(inner)] if inner.strip() else []


class Eval:
    """Evaluates a single `where` clause under a binding. Returns True/False, or None if a needed
    function couldn't be resolved from the graph (unresolved -> caller downgrades to CONDITIONAL)."""
    def __init__(self, graph, binding):
        self.g, self.b = graph, binding
        self.unresolved = False

    def clause(self, expr):
        expr = expr.split("#", 1)[0].strip()
        if not expr:
            return True
        for op in (" intersects ", " != ", " == ", " >= ", " <= ", " in ", " > ", " < "):
            i = self._top_split(expr, op)
            if i is not None:
                lv = self.term(expr[:i]); rv = self.term(expr[i + len(op):])
                if lv is self._UNRES or rv is self._UNRES:
                    self.unresolved = True; return None
                return self._apply(op.strip(), lv, rv)
        v = self.term(expr)                      # bare predicate (function returning bool)
        if v is self._UNRES:
            self.unresolved = True; return None
        return bool(v)

    def _top_split(self, s, op):
        depth = 0
        for i, ch in enumerate(s):
            if ch in "[(":
                depth += 1
            elif ch in ")]":
                depth -= 1
            elif depth == 0 and s.startswith(op, i):
                return i
        return None

    _UNRES = object()

    def term(self, t):
        t = t.strip()
        if not t:
            return None
        if _LIST_RE.match(t):
            return _parse_list(t)
        if t[0] in "'\"":
            return t.strip("'\"")
        m = _FN_RE.match(t)
        if m:
            return self._fn(m.group(1), _split_args(m.group(2)))
        if t.startswith("?") and "." in t:
            var, attr = t.split(".", 1)
            return self._attr(self.b.get(var), attr)
        if t.startswith("?"):
            return self.b.get(t)
        if re.fullmatch(r"-?\d+(\.\d+)?", t):
            return float(t)
        return t                                  # bare identifier -> string constant

    def _attr(self, node, attr):
        if node is None:
            return self._UNRES
        if attr == "node_type":
            return self.g.node_type.get(node)
        if attr in ("provider_type", "privilege_level"):
            return self._UNRES                    # needs data the graph doesn't carry
        return self._UNRES

    def _fn(self, name, args):
        a = [self.term(x) for x in args]
        if name == "node_type":
            return self.g.node_type.get(a[0]) if a and a[0] else self._UNRES
        if name == "node_class":
            return self.g.node_class.get(a[0]) if a and a[0] else self._UNRES
        if name in ("scope", "account"):
            nid = a[0] or ""
            parts = str(nid).split("|")
            return parts[1] if (name == "account" and len(parts) > 1) else self._UNRES
        if name == "effective_action_on":
            # approximation: the union of `permissions` on edges from a[0] to a[1] in this graph.
            if len(a) < 2 or not a[0] or not a[1]:
                return self._UNRES
            perms, seen = [], False
            for e in self.g.edges:
                if e.get("source") == a[0] and e.get("target") == a[1]:
                    seen = True
                    perms += e.get("permissions") or []
            return set(perms) if seen else self._UNRES
        if name == "trigger_exists":
            tgt = a[0] if a else None
            for e in self.g.edges:
                if e.get("target") == tgt and e.get("type") in ("CanInvoke", "CanTrigger", "CanExecuteCommand"):
                    return True
            return self._UNRES
        return self._UNRES                        # privilege_level, identity(), role(), ... : unresolved

    def _apply(self, op, lv, rv):
        try:
            if op == "in":
                return lv in (rv or [])
            if op == "intersects":
                return bool(set(lv if isinstance(lv, (set, list)) else [lv]) &
                            set(rv if isinstance(rv, (set, list)) else [rv]))
            if op == "==":
                return lv == rv
            if op == "!=":
                return lv != rv
            if op in (">=", "<=", ">", "<"):
                lv, rv = float(lv), float(rv)
                return {">=": lv >= rv, "<=": lv <= rv, ">": lv > rv, "<": lv < rv}[op]
        except (TypeError, ValueError):
            return False
        return False


# ----------------------------------------------------------------------------- matching
def _bind(binding, var, val):
    """Extend a binding: '?x' binds/checks; a literal must equal val. None = conflict."""
    if isinstance(var, str) and var.startswith("?"):
        if var in binding and binding[var] != val:
            return None
        nb = dict(binding); nb[var] = val; return nb
    return binding if var == val else None


def _provider(e):
    """The cloud an edge belongs to (for applies_to scoping)."""
    if e.get("provider"):
        return e["provider"]
    src = str(e.get("source", ""))
    return src.split("|", 1)[0] if "|" in src else None


def match(rule, graph):
    clauses = rule["_match"]
    provs = set(rule.get("applies_to") or ["*"])
    any_prov = "*" in provs
    by_type = {}
    for e in graph.edges:
        by_type.setdefault(e.get("type"), []).append(e)

    def rec(i, binding, used):
        if i == len(clauses):
            yield dict(binding), list(used); return
        a, et, b = clauses[i]
        candidates = graph.edges if (isinstance(et, str) and et.startswith("?")) else by_type.get(et, [])
        for e in candidates:
            if not any_prov and _provider(e) not in provs:
                continue  # respect the rule's applies_to (provider scope)
            nb = _bind(binding, a, e.get("source"))
            if nb is None:
                continue
            nb = _bind(nb, b, e.get("target"))
            if nb is None:
                continue
            if isinstance(et, str) and et.startswith("?"):
                nb = _bind(nb, et, e.get("type"))
                if nb is None:
                    continue
            yield from rec(i + 1, nb, used + [e])
    yield from rec(0, {}, [])


# ----------------------------------------------------------------------------- emit + fixpoint
def _emits_type(rule, binding):
    em = rule["emits"]
    return binding.get(em) if isinstance(em, str) and em.startswith("?") else em


def executable(rule):
    """True if emit.source/target are bound variables (this engine can emit a concrete edge)."""
    emit = rule["emit"]
    emit = emit[0] if isinstance(emit, list) else emit
    s, t = str(emit.get("source", "")), str(emit.get("target", ""))
    return s.startswith("?") and " " not in s and t.startswith("?") and " " not in t


def run(graph, rules, max_rounds=8):
    stats = {"rules_total": len(rules), "rules_fired": set(), "derived": 0,
             "conditional_unresolved": 0, "skipped_prose_emit": 0, "rounds": 0}
    for _ in range(max_rounds):
        stats["rounds"] += 1
        new_edges = []
        for rule in rules:
            if not executable(rule):
                continue  # prose/complex emit ref — not executable by the reference engine
            emit = rule["emit"]
            emit = emit[0] if isinstance(emit, list) else emit
            src_ref, tgt_ref = str(emit.get("source")), str(emit.get("target"))
            for binding, used in match(rule, graph):
                ev = Eval(graph, binding)
                ok = all(ev.clause(w) is not False for w in (rule.get("where") or []))
                if not ok:
                    continue
                etype = _emits_type(rule, binding)
                src, tgt = binding.get(src_ref), binding.get(tgt_ref)
                if not (etype and src and tgt):
                    stats["skipped_prose_emit"] += 1
                    continue
                scope = used[0].get("scope", "") if used else ""
                eid = edge_id(etype, src, tgt, scope)
                key = f"{etype}|{src}|{tgt}|{scope}"
                if key in graph._key:
                    continue
                states = [u.get("state", "ACTIVE") for u in used]
                st = min(states, key=lambda s: _STATE_RANK.get(s, 3)) if states else "ACTIVE"
                if ev.unresolved:
                    st = "CONDITIONAL" if _STATE_RANK.get(st, 3) > 2 else st
                    stats["conditional_unresolved"] += 1
                evid = []
                for u in used:
                    evid += u.get("evidence") if isinstance(u.get("evidence"), list) else ([u["evidence"]] if u.get("evidence") else [])
                edge = {"kind": "edge", "edge_id": eid, "type": etype, "source": src, "target": tgt,
                        "nature": "derived", "state": st, "rule_id": rule.get("id"),
                        "derived_from": [u.get("edge_id") for u in used if u.get("edge_id")],
                        "evidence": sorted(set(evid)) or [f"derived:{rule.get('id')}"], "scope": scope}
                new_edges.append(edge)
                stats["rules_fired"].add(rule.get("id"))
        added = 0
        for e in new_edges:
            if graph._add_raw(e):
                added += 1; stats["derived"] += 1
        if added == 0:
            break
    stats["rules_fired"] = len(stats["rules_fired"])
    return stats


def main(argv):
    if not argv:
        print("usage: rage_engine.py <graph.rage.ndjson> [--out <path>]", file=sys.stderr)
        return 2
    path = argv[0]
    out = argv[argv.index("--out") + 1] if "--out" in argv else None
    classes = {n: v.get("class") for n, v in
               json.load(open(os.path.join(ROOT, "vocab", "node-types.json")))["node_types"].items()}
    rules = load_rules()
    g = Graph.from_ndjson(path, classes)
    base = len(g.edges)
    st = run(g, rules)
    execu = sum(1 for r in rules if executable(r))
    print(f"loaded {st['rules_total']} derived rules (match+emit); "
          f"{execu} executable by this engine (variable emit refs)")
    print(f"graph: {len(g.node_type)} nodes, {base} explicit edges")
    print(f"executed to fixpoint in {st['rounds']} rounds:")
    print(f"  {st['rules_fired']} distinct rules fired -> {st['derived']} derived edges "
          f"({len(g.edges)} total)")
    print(f"  {st['conditional_unresolved']} edges downgraded to CONDITIONAL (unresolved where-clause)")
    if out:
        with open(out, "w") as fh:
            for nid, nt in g.node_type.items():
                fh.write(json.dumps({"kind": "node", "node_id": nid, "node_type": nt}) + "\n")
            for e in g.edges:
                fh.write(json.dumps(e) + "\n")
        print(f"  wrote augmented graph -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
