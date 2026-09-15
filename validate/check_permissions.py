#!/usr/bin/env python3
"""Permission-string validator for the RAGE corpus.

Checks every native permission string asserted anywhere in the corpus against the
vendored ground-truth catalogs (validate/catalogs/, refreshed by
tools/refresh_catalogs.py from iann0036/iam-dataset).

Two modes:
  python3 validate/check_permissions.py            # gate mode: exits non-zero on errors
  python3 validate/check_permissions.py --report   # audit mode: classify + write
                                                   #   permission-audit.json, never fails

Sources walked (all four): providers/*.json (resources, detail steps, facts),
exposure-db/*.json (sites), rules/derivation.json (per-cloud), rules/**/*.yaml
(emit.permissions + match_effective_permission.action).

Zero deps beyond PyYAML (already in requirements.txt).
"""
import json, os, sys, glob, re, difflib
from collections import defaultdict

try:
    import yaml
except ImportError:
    print("ERROR PyYAML required (pip install -r requirements.txt)")
    sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAT = os.path.join(ROOT, "validate", "catalogs")


def load(p):
    with open(os.path.join(ROOT, p), encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------- catalogs
def load_catalogs():
    aws = load("validate/catalogs/aws-actions.json")["actions"]           # {prefix:[actions]}
    aws_prefixes = set(aws)
    aws_action_index = defaultdict(set)                                   # action(lower) -> {prefixes}
    for pfx, acts in aws.items():
        for a in acts:
            aws_action_index[a.lower()].add(pfx)
    gcp = set(load("validate/catalogs/gcp-permissions.json")["permissions"])
    az = load("validate/catalogs/azure-arm-operations.json")
    az_canon = set(az["canonical"])
    az_lower = az["lower_to_canonical"]                                   # {lower: canonical}
    graph = set(load("validate/catalogs/azure-graph-scopes.json")["scopes"])
    return {
        "aws": aws, "aws_prefixes": aws_prefixes, "aws_action_index": aws_action_index,
        "gcp": gcp, "az_canon": az_canon, "az_lower": az_lower, "graph": graph,
    }


def load_allowlist():
    p = os.path.join(ROOT, "validate", "permission-allowlist.json")
    if os.path.exists(p):
        return json.load(open(p, encoding="utf-8"))
    return {}


# ---------------------------------------------------------------- source walker
def walk_sources():
    """Yield (perm, kind, relfile, path) for every asserted permission string."""
    for cloud in ("aws", "gcp", "azure"):
        rel = f"providers/{cloud}.json"
        d = load(rel)
        for rk, r in (d.get("resources") or {}).items():
            for p in r.get("required_permissions", []) or []:
                yield p, "resource", rel, f"resources.{rk}"
            for i, step in enumerate(r.get("detail", []) or []):
                for p in step.get("required_permissions", []) or []:
                    yield p, "resource_detail", rel, f"resources.{rk}.detail[{i}]"
        for f in d.get("facts", []) or []:
            fid = f.get("kind") or f.get("id") or "?"
            for p in f.get("required_permissions", []) or []:
                yield p, "fact", rel, f"facts.{fid}"

        rel = f"exposure-db/{cloud}.json"
        d = load(rel)
        for sk, sv in (d.get("services") or {}).items():
            for site in sv.get("sites", []) or []:
                sid = site.get("id", "?")
                for p in site.get("required_permissions", []) or []:
                    yield p, "exposure", rel, f"services.{sk}.sites.{sid}"

    d = load("rules/derivation.json")
    for edge, body in (d.get("rules") or {}).items():
        if not isinstance(body, dict):
            continue
        for cloud, pb in (body.get("providers") or {}).items():
            if isinstance(pb, dict):
                for p in pb.get("permissions", []) or []:
                    yield p, "derivation", "rules/derivation.json", f"rules.{edge}.providers.{cloud}"

    for f in sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.yaml"), recursive=True)):
        rel = os.path.relpath(f, ROOT)
        try:
            doc = yaml.safe_load(open(f, encoding="utf-8")) or {}
        except Exception as e:
            print(f"WARN  {rel}: YAML parse error ({e})")
            continue
        for i, rule in enumerate(doc.get("rules", []) or []):
            if not isinstance(rule, dict):
                continue
            rid = rule.get("id", f"[{i}]")
            mep = rule.get("match_effective_permission")
            if isinstance(mep, dict) and mep.get("action") is not None:
                act = mep["action"]
                for a in (act if isinstance(act, list) else [act]):
                    yield a, "rule_match", rel, f"{rid}.match_effective_permission.action"
            emit = rule.get("emit")
            if isinstance(emit, dict):
                for p in emit.get("permissions", []) or []:
                    yield p, "rule_emit", rel, f"{rid}.emit.permissions"


# ---------------------------------------------------------------- classification
def detect_cloud(p):
    if ":" in p and "/" not in p:
        return "aws"
    if "/" in p:
        return "azure_arm"
    if "." in p:
        # Both GCP perms and MS Graph scopes are dotted. GCP is service.resource.verb
        # with a lowercase-first service (verbs may be camelCase, e.g. setIamPolicy);
        # Graph scopes are PascalCase-first (Group.Read.All).
        return "azure_graph" if p[:1].isupper() else "gcp"
    return "unknown"


AWS_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9]+$")
GCP_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-zA-Z][a-zA-Z0-9]*)+$")

# Non-cloud-IAM permission namespaces present in the corpus (legit content, but not
# validatable against the AWS/GCP/Azure IAM catalogs — allowlist candidates).
NONIAM_PREFIX = ("vso.", "FabricClient:")
NONIAM_EXACT = {"AcrPush", "AcrPull", "AcrDelete", "Contribute"}


def looks_literal(p):
    """True if p is shaped like a single native permission token, not prose/placeholder."""
    if not p or len(p) > 60:
        return False
    if any(c in p for c in "<>|()?= "):
        return False
    if "http" in p or "://" in p:
        return False
    return True


# disposition: how a maintainer should act on it
#   auto      -> mechanical fix, proposed_fix is high-confidence
#   review    -> a fix is needed but the target should be confirmed
#   policy    -> not a bug per se; needs a decision (allowlist / schema / scope)
#   catalog   -> can't assert; ground-truth catalog is known-incomplete here
def classify(p, cat):
    """Return (disposition, tier, proposed_fix); disposition 'ok' means valid."""
    if not looks_literal(p):
        return "policy", "non-literal-placeholder", None
    if "*" in p:
        return "policy", "wildcard", None
    if p in NONIAM_EXACT or p.startswith(NONIAM_PREFIX):
        return "policy", "non-iam-namespace", None

    cloud = detect_cloud(p)

    if cloud == "aws":
        if not AWS_RE.match(p):
            return "policy", "non-iam-namespace", None
        pfx, action = p.split(":", 1)
        if pfx not in cat["aws_prefixes"]:
            owners = sorted(cat["aws_action_index"].get(action.lower(), []))
            if len(owners) == 1:
                return "auto", "tier1-bogus-prefix", f"{owners[0]}:{action}"
            if len(owners) > 1:
                return "review", "tier1-bogus-prefix", [f"{o}:{action}" for o in owners]
            return "review", "tier1-bogus-prefix", None
        if action not in cat["aws"][pfx]:
            ci = [a for a in cat["aws"][pfx] if a.lower() == action.lower()]
            if ci:
                return "auto", "tier2-aws-casing", f"{pfx}:{ci[0]}"
            near = difflib.get_close_matches(action, cat["aws"][pfx], n=1, cutoff=0.8)
            return "review", "tier2-aws-action", (f"{pfx}:{near[0]}" if near else None)
        return "ok", None, None

    if cloud == "gcp":
        if not GCP_RE.match(p):
            return "policy", "non-iam-namespace", None
        if p in cat["gcp"]:
            return "ok", None, None
        # GCP catalog (iam-dataset permissions.json) is role-derived and incomplete;
        # absence is not proof of error.
        return "catalog", "gcp-not-in-catalog", None

    if cloud == "azure_arm":
        # ARM matches case-insensitively, and the ground-truth catalog is itself
        # casing-inconsistent (some RPs register ops in lowercase). So existence is
        # checked case-insensitively; per-string casing is not an error. Corpus casing
        # *consistency* is reported separately as an aggregate.
        if p.lower() in cat["az_lower"]:
            return "ok", None, None
        # Not in snapshot. The Azure catalog has demonstrable gaps (data-plane /
        # managed-HSM ops), so absence is not proof of error — flag, don't assert.
        return "catalog", "azure-op-not-in-catalog", None

    if cloud == "azure_graph":
        if p in cat["graph"]:
            return "ok", None, None
        near = difflib.get_close_matches(p, cat["graph"], n=1, cutoff=0.9)
        return "review", "graph-scope-nonexistent", (near[0] if near else None)

    return "policy", "unroutable", None


# ---------------------------------------------------------------- main
def main():
    report = "--report" in sys.argv
    cat = load_catalogs()
    allow = load_allowlist()

    # distinct string -> {tier, cloud, fix, locations:[(kind,file,path)]}
    seen = {}
    total_refs = 0
    malformed = []
    for p, kind, rel, path in walk_sources():
        total_refs += 1
        if not isinstance(p, str):
            malformed.append((repr(p), kind, rel, path))
            continue
        if p in seen:
            seen[p]["locations"].append((kind, rel, path))
            continue
        disp, tier, fix = classify(p, cat)
        seen[p] = {"disp": disp, "tier": tier, "cloud": detect_cloud(p),
                   "fix": fix, "locations": [(kind, rel, path)]}

    # group by disposition (auto/review = real fixable bugs; policy/catalog = decisions)
    buckets = defaultdict(list)   # disp -> [(p, info)]
    allowed = []
    for p, info in seen.items():
        if info["disp"] == "ok":
            continue
        if p in allow:
            allowed.append(p)
            continue
        buckets[info["disp"]].append((p, info))

    fixable = buckets["auto"] + buckets["review"]
    decisions = buckets["policy"] + buckets["catalog"]

    # Azure casing consistency: valid ARM ops the corpus writes in >1 casing (dedup bug).
    az_casings = defaultdict(set)
    for p, info in seen.items():
        if info["cloud"] == "azure_arm" and p.lower() in cat["az_lower"]:
            az_casings[p.lower()].add(p)
    az_inconsistent = {lk: sorted(v) for lk, v in az_casings.items() if len(v) > 1}

    by_tier = defaultdict(int)
    for p, info in fixable + decisions:
        by_tier[info["tier"]] += 1

    if report:
        def dump(rows):
            return [
                {"string": p, "cloud": i["cloud"], "tier": i["tier"], "disposition": i["disp"],
                 "proposed_fix": i["fix"], "occurrences": len(i["locations"]),
                 "locations": [{"kind": k, "file": f, "path": pa} for k, f, pa in i["locations"]]}
                for p, i in sorted(rows, key=lambda x: (x[1]["tier"], x[0]))
            ]
        out = {
            "total_refs": total_refs, "distinct": len(seen),
            "counts": {d: len(buckets[d]) for d in ("auto", "review", "policy", "catalog")},
            "allowlisted": len(allowed), "malformed_nonstring": len(malformed),
            "azure_casing_inconsistent_ops": az_inconsistent,
            "by_tier": dict(sorted(by_tier.items())),
            "fixable": dump(fixable), "decisions": dump(decisions),
        }
        outp = os.path.join(ROOT, "permission-audit.json")
        with open(outp, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print("=== permission audit (report mode) ===")
        print(f"{total_refs} refs · {len(seen)} distinct strings · {len(allowed)} allowlisted\n")
        print(f"FIXABLE BUGS:   {len(fixable):4}  (auto={len(buckets['auto'])} review={len(buckets['review'])})")
        print(f"DECISIONS:      {len(decisions):4}  (policy={len(buckets['policy'])} catalog-gap={len(buckets['catalog'])})")
        print()
        print(f"{'tier':28} {'disp':8} count")
        rows = defaultdict(lambda: [None, 0])
        for p, i in fixable + decisions:
            rows[i["tier"]][0] = i["disp"]; rows[i["tier"]][1] += 1
        for tier, (disp, n) in sorted(rows.items(), key=lambda x: (x[1][0], -x[1][1])):
            print(f"{tier:28} {disp:8} {n}")
        auto_fixes = sum(1 for p, i in fixable if i["disp"] == "auto")
        print(f"\nauto-fix proposed for {auto_fixes}/{len(fixable)} fixable bugs")
        print(f"azure ARM ops written in >1 casing (dedup cleanup): {len(az_inconsistent)}")
        print(f"wrote {outp}")
        sys.exit(0)

    # gate mode: fixable bugs fail; decisions warn until allowlisted/resolved
    for p in sorted(allowed):
        print(f"WARN  allowlisted {p} ({allow[p]})")
    for p, info in sorted(decisions, key=lambda x: (x[1]["tier"], x[0])):
        print(f"WARN  [{info['tier']}] {p}")
    for p, info in sorted(fixable, key=lambda x: (x[1]["tier"], x[0])):
        loc = info["locations"][0]
        fix = f"  -> {info['fix']}" if info["fix"] else ""
        print(f"ERROR [{info['tier']}] {p} ({loc[1]}:{loc[2]}){fix}")
    print(f"\nchecked: {total_refs} refs, {len(seen)} distinct · "
          f"{len(fixable)} bugs, {len(decisions)} decisions, {len(allowed)} allowlisted")
    sys.exit(1 if fixable else 0)


if __name__ == "__main__":
    main()
