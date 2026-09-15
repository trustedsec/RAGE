#!/usr/bin/env python3
"""Referential-integrity checker for the RAGE exposure-db (zero-dependency, stdlib only).

Verifies every exposure site is strongly mapped:
  - `emits` is a registered RAGE edge type (vocab/edge-types.json)
  - `location_kind`, `data_kinds`, `access_mode` are in exposure-db/vocabulary.json
  - `severity` is low|medium|high|critical
  - `id` and `emits` are present

Usage:  python3 validate/check_exposure_db.py    # exits non-zero on any error
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def load(p): return json.load(open(os.path.join(ROOT, p)))

edge_types = set(load("vocab/edge-types.json")["edge_types"])
vocab = load("exposure-db/vocabulary.json")
loc_kinds = set(vocab["location_kind"])
data_kinds = set(vocab["data_kinds"])
access_modes = set(vocab["access_mode"])
SEV = {"low", "medium", "high", "critical"}

errors, warnings = [], []
n_sites = n_services = 0
for prov in ("aws", "gcp", "azure"):
    reg = load(f"exposure-db/{prov}.json")
    for svc, s in reg["services"].items():
        n_services += 1
        for site in s.get("sites", []):
            n_sites += 1
            sid = site.get("id") or "?"
            if not site.get("id"):
                errors.append(f"{prov} {svc}: a site has no id")
            e = site.get("emits")
            if not e:
                errors.append(f"{prov} {sid}: no emits edge")
            elif e not in edge_types:
                errors.append(f"{prov} {sid}: emits {e!r} not a registered RAGE edge type")
            if site.get("severity") not in SEV:
                errors.append(f"{prov} {sid}: severity {site.get('severity')!r} not in {sorted(SEV)}")
            if site.get("location_kind") and site["location_kind"] not in loc_kinds:
                errors.append(f"{prov} {sid}: location_kind {site['location_kind']!r} not in vocabulary")
            for dk in site.get("data_kinds", []):
                if dk not in data_kinds:
                    errors.append(f"{prov} {sid}: data_kind {dk!r} not in vocabulary")
            am = (site.get("read") or {}).get("access_mode")
            if am and am not in access_modes:
                errors.append(f"{prov} {sid}: access_mode {am!r} not in vocabulary")
            if not (site.get("read") or {}).get("operation"):
                errors.append(f"{prov} {sid}: read recipe has no operation")
            if am == "read_api" and not site.get("required_permissions"):
                warnings.append(f"{prov} {sid}: read_api site has no required_permissions")

for w in warnings[:20]: print(f"WARN  {w}")
if len(warnings) > 20: print(f"WARN  … +{len(warnings)-20} more")
for e in errors: print(f"ERROR {e}")
print(f"\nchecked {n_sites} exposure sites across {n_services} service catalogs · "
      f"{len(errors)} errors, {len(warnings)} warnings")
sys.exit(1 if errors else 0)
