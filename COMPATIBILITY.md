# RAGE Compatibility

RAGE is the source of truth. Its **`spec_version`** is the single number that pins the
tools to a RAGE release. There is nothing else to reconcile.

Answer "what version of Thunderstorm / Blaze pairs with what version of RAGE?" here —
one row per RAGE `spec_version`.

| RAGE `spec_version` | Thunderstorm | Blaze / Blaze Lite |
|---------------------|--------------|--------------------|
| 0.1                 | 0.1.x        | 0.1.x              |

## How it stays in sync (no hand-bumping, no drift)

- **RAGE declares it.** Every registry file carries `spec_version` (e.g.
  `providers/*.json`, `vocab/*.json`, `exposure-db/*.json`).
- **Thunderstorm reads it — never hardcodes it.** `make RAGE_ROOT=/path/to/RAGE`
  vendors a RAGE snapshot; the collector reads that snapshot's `spec_version`
  (`thunderstorm version` prints `RAGE <v>`) and stamps it into the manifest of every
  `.rage.ndjson` it emits.
- **The viewers verify it.** Blaze and Blaze Lite read `spec_version` from the graph
  manifest and warn when a graph was built against a RAGE version they don't support —
  the guardrail that stops silent mis-rendering (the BloodHound/SharpHound failure mode).

When a RAGE change would affect consumers, bump `spec_version`, add a row above, and
widen the tools' supported range in the same release.
