#!/usr/bin/env python3
"""Apply auto-fix permission-string corrections from a permission audit.

Reads permission-audit.json (produced by `validate/check_permissions.py --report`)
and applies the high-confidence `auto` fixes across all four corpus sources by exact
token replacement. YAML rule files carry extensive comments, so this does careful
text substitution (never a parse/dump round-trip that would drop them).

Safety: each replacement uses lookarounds so a fix can only match a *whole* permission
token, never a substring of a longer one.

Usage:
  python3 tools/apply_permission_fixes.py            # dry-run: show what would change
  python3 tools/apply_permission_fixes.py --write    # apply and rewrite files
"""
import json, os, re, sys, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONT = r"[A-Za-z0-9:._/*-]"   # permission-token continuation characters


def sources():
    files = []
    for c in ("aws", "gcp", "azure"):
        files += [f"providers/{c}.json", f"exposure-db/{c}.json"]
    files.append("rules/derivation.json")
    files += [os.path.relpath(p, ROOT) for p in
              sorted(glob.glob(os.path.join(ROOT, "rules", "**", "*.yaml"), recursive=True))]
    return files


def main():
    write = "--write" in sys.argv
    fixes = {}
    # audit auto-fixes (may be empty once already applied)
    apath = os.path.join(ROOT, "permission-audit.json")
    if os.path.exists(apath):
        audit = json.load(open(apath, encoding="utf-8"))
        fixes.update({x["string"]: x["proposed_fix"] for x in audit["fixable"]
                      if x["disposition"] == "auto" and isinstance(x["proposed_fix"], str)})
    # manual remaps: {wrong: right}
    if "--manual" in sys.argv:
        mpath = sys.argv[sys.argv.index("--manual") + 1]
        fixes.update(json.load(open(mpath, encoding="utf-8")))
    if not fixes:
        print("no fixes to apply")
        return
    patterns = {w: re.compile(rf"(?<!{CONT}){re.escape(w)}(?!{CONT})") for w in fixes}

    per_fix = {w: 0 for w in fixes}
    changed_files = 0
    for rel in sources():
        path = os.path.join(ROOT, rel)
        text = open(path, encoding="utf-8").read()
        new = text
        hits_here = {}
        for w, r in fixes.items():
            new2, n = patterns[w].subn(r, new)
            if n:
                hits_here[w] = n
                per_fix[w] += n
                new = new2
        if hits_here:
            changed_files += 1
            tag = "WRITE" if write else "DRY  "
            print(f"{tag} {rel}: " + ", ".join(f"{w}->{fixes[w]} x{n}" for w, n in hits_here.items()))
            if write:
                open(path, "w", encoding="utf-8").write(new)

    print(f"\n{len(fixes)} auto fixes · {sum(per_fix.values())} replacements · {changed_files} files")
    missed = [w for w, n in per_fix.items() if n == 0]
    if missed:
        print("WARN not found in any source (already fixed?): " + ", ".join(missed))
    if not write:
        print("\n(dry-run — re-run with --write to apply)")


if __name__ == "__main__":
    main()
