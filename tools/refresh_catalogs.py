#!/usr/bin/env python3
"""Refresh the vendored permission catalogs from iann0036/iam-dataset.

Downloads the upstream ground-truth files, distills each to the compact string set
the permission validator needs, and writes them under validate/catalogs/. The full
upstream files are ~33 MB combined; the distilled catalogs are ~1-2 MB.

Ground truth (single dataset, all three clouds):
  https://github.com/iann0036/iam-dataset

Usage:  python3 tools/refresh_catalogs.py        # pulls upstream, rewrites catalogs
Zero external deps (stdlib urllib only). Requires network; run it deliberately, not in CI.
CI consumes the vendored output; it does not refresh.
"""
import json, os, sys, urllib.request, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "validate", "catalogs")
RAW = "https://raw.githubusercontent.com/iann0036/iam-dataset/main"
API_COMMIT = "https://api.github.com/repos/iann0036/iam-dataset/commits/main"
# Microsoft Graph scopes are a separate namespace, not in iam-dataset. Official source
# is the Graph Explorer / DevX content repo published by Microsoft.
GRAPH_URL = ("https://raw.githubusercontent.com/microsoftgraph/"
             "microsoft-graph-devx-content/dev/permissions/permissions-descriptions.json")

SOURCES = {
    "aws": f"{RAW}/aws/iam_definition.json",
    "gcp": f"{RAW}/gcp/permissions.json",
    "azure": f"{RAW}/azure/provider-operations.json",
    "graph": GRAPH_URL,
}


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "rage-refresh-catalogs"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def upstream_sha():
    try:
        return fetch_json(API_COMMIT).get("sha", "unknown")[:12]
    except Exception:
        return "unknown"


def distill_aws(raw):
    # raw: [ {prefix, privileges:[{privilege, access_level, ...}], ...}, ... ]
    actions = {}
    for svc in raw:
        prefix = svc.get("prefix")
        if not prefix:
            continue
        privs = sorted({p["privilege"] for p in svc.get("privileges", []) if p.get("privilege")})
        actions[prefix] = privs
    return {"actions": actions}  # prefixes are the keys


def distill_gcp(raw):
    # raw: { "service.resource.verb": [roles...], ... }
    return {"permissions": sorted(raw.keys())}


def distill_azure(raw):
    # raw: [ {name, operations:[{name, isDataAction}], resourceTypes:[{operations:[...]}]}, ... ]
    canonical = set()
    for prov in raw:
        for op in prov.get("operations") or []:
            if op.get("name"):
                canonical.add(op["name"])
        for rt in prov.get("resourceTypes") or []:
            for op in rt.get("operations") or []:
                if op.get("name"):
                    canonical.add(op["name"])
    lower_to_canonical = {}
    collisions = 0
    for name in canonical:
        lk = name.lower()
        if lk in lower_to_canonical and lower_to_canonical[lk] != name:
            collisions += 1
        lower_to_canonical[lk] = name
    if collisions:
        print(f"  note: {collisions} ARM ops collide on lowercase (case-only variants)")
    return {"canonical": sorted(canonical), "lower_to_canonical": lower_to_canonical}


def distill_graph(raw):
    # raw: {delegatedScopesList:[{value,...}], applicationScopesList:[{value,...}]}
    scopes = set()
    for key in ("delegatedScopesList", "applicationScopesList"):
        for e in raw.get(key, []):
            v = e.get("value") or e.get("name")
            if v:
                scopes.add(v)
    return {"scopes": sorted(scopes)}


DISTILLERS = {"aws": distill_aws, "gcp": distill_gcp, "azure": distill_azure, "graph": distill_graph}
FILES = {
    "aws": "aws-actions.json",
    "gcp": "gcp-permissions.json",
    "azure": "azure-arm-operations.json",
    "graph": "azure-graph-scopes.json",
}


def main():
    os.makedirs(OUT, exist_ok=True)
    sha = upstream_sha()
    summary = []
    for cloud, url in SOURCES.items():
        print(f"fetching {cloud}: {url}")
        raw = fetch_json(url)
        distilled = DISTILLERS[cloud](raw)
        path = os.path.join(OUT, FILES[cloud])
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(distilled, fh, indent=0, sort_keys=True)
            fh.write("\n")
        size_kb = os.path.getsize(path) // 1024
        if cloud == "aws":
            n = sum(len(v) for v in distilled["actions"].values())
            summary.append(f"aws: {len(distilled['actions'])} services, {n} actions ({size_kb} KB)")
        elif cloud == "gcp":
            summary.append(f"gcp: {len(distilled['permissions'])} permissions ({size_kb} KB)")
        elif cloud == "graph":
            summary.append(f"graph: {len(distilled['scopes'])} MS Graph scopes ({size_kb} KB)")
        else:
            summary.append(f"azure: {len(distilled['canonical'])} ARM operations ({size_kb} KB)")

    today = datetime.date.today().isoformat()
    snap = os.path.join(OUT, "SNAPSHOT.md")
    with open(snap, "w", encoding="utf-8") as fh:
        fh.write("# Permission catalog snapshot\n\n")
        fh.write("Vendored ground truth for `validate/check_permissions.py`. Do not hand-edit.\n\n")
        fh.write(f"- Source (aws/gcp/azure): https://github.com/iann0036/iam-dataset @ `{sha}`\n")
        fh.write("- Source (graph): https://github.com/microsoftgraph/microsoft-graph-devx-content"
                 " (permissions/permissions-descriptions.json)\n")
        fh.write(f"- Pulled: {today}\n")
        fh.write("- Refresh: `python3 tools/refresh_catalogs.py`\n\n")
        fh.write("## Contents\n\n")
        for line in summary:
            fh.write(f"- {line}\n")
    print("\n" + "\n".join(summary))
    print(f"wrote catalogs to {OUT} (source @ {sha})")


if __name__ == "__main__":
    main()
