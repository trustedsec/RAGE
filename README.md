# RAGE - Relational Attack Graph Exchange

*An attack graph you can actually hand to someone else.*

Every graph-based security product keeps your attack graph locked inside a proprietary
store. You cannot export it, diff two scans, put it in version control, or query it with
anything but the vendor's own UI. When the engagement ends, the graph leaves with it.

RAGE is a vendor-neutral **file format** for offensive security graphs, plus the open
corpus that gives it meaning: the node and edge taxonomy, the AWS/GCP/Azure mappings and
collection recipes, and the edge-derivation rules. One file. Any language. Grab and go.

**Status:** early draft (`spec_version: 0.1`). Not stable yet; feedback and pull requests
are welcome.

## The whole format in one breath

A RAGE graph is a single NDJSON file (one JSON object per line). Line 1 is the manifest;
every other line is a record tagged with `kind`.

```jsonc
{"kind":"manifest","spec_version":"0.1"}
{"kind":"node","node_id":"gcp|proj-a|gcp:iam:service-account|sa-deploy","node_type":"ServiceAccount"}
{"kind":"node","node_id":"gcp|proj-a|gcp:iam:service-account|sa-admin","node_type":"ServiceAccount"}
{"kind":"node","node_id":"gcp|proj-a|gcp:storage:bucket|bucket-crown","node_type":"ObjectStorage"}
{"kind":"edge","type":"CanImpersonate","source":"gcp|proj-a|…|sa-deploy","target":"gcp|proj-a|…|sa-admin"}
{"kind":"edge","type":"CanReadData","source":"gcp|proj-a|…|sa-admin","target":"gcp|proj-a|…|bucket-crown"}
{"kind":"finding","resource_id":"gcp|proj-a|…|bucket-crown","severity":"critical"}
```

A two-hop chain that respects the taxonomy: `sa-deploy` can impersonate `sa-admin` (an
identity to identity edge), which can read the crown-jewels bucket (identity to storage).

Read it in three lines of any language:

```python
for line in open("graph.rage.ndjson"): rec = json.loads(line)   # switch on rec["kind"]
```
```bash
jq 'select(.kind=="edge" and .type=="CanImpersonate")' graph.rage.ndjson
```

## Record kinds

| kind | required fields | purpose |
|---|---|---|
| `manifest` | `spec_version` | line 1: version + optional counts/scope/producer |
| `node` | `node_id`, `node_type` | a resource or identity |
| `edge` | `source`, `target`, `type` | a capability or relationship |
| `fact` | `fact_id` | a normalized observation the graph was built from |
| `evidence` | `evidence_id`, `content_hash` | tamper-evident receipt (an API/collection operation) |
| `finding` | `resource_id`, `severity` | an exposure |
| `surface` / `path` | - | optional extension kinds |

The provenance chain is `evidence` (API) then `fact` then `edge`/`finding`, linked by ids.
`node_type` and edge `type` come from the open registries in [`vocab/`](vocab/). Everything
else is optional enrichment. See [`spec/format.md`](spec/format.md).

## The corpus

The format is only half of RAGE. The other half is the shared corpus that gives the types
meaning, so two independent tools agree on what `CanImpersonate` is and where a credential
can leak:

- **Taxonomy** ([`vocab/`](vocab/)): 105 node types in 10 classes, 80 edge types in 9 categories.
- **Mappings and collection recipes** ([`providers/`](providers/)): 219 native resource types across AWS, GCP, and Azure, each mapped to a generic node type with the calls that enumerate it.
- **Derivation rules** ([`rules/`](rules/)): the contract in [`rules/derivation.json`](rules/derivation.json) plus 2,400+ executable `match/where/emit` rules for how edges are derived.
- **Exposure DB** ([`exposure-db/`](exposure-db/)): 1,049 mapped credential-leak sites, each tied to the RAGE edge it emits and the recipe that reads it.

The whole corpus, human-readable, is in [`TAXONOMY.md`](TAXONOMY.md).

## Implementations

RAGE is designed so anyone can produce or consume it. The format is the contract; the
tools are interchangeable, and the list is open.

**RAGE is the format, Thunderstorm produces it, Blaze explores it.**

| implementation | role | where |
|---|---|---|
| Thunderstorm | producer: read-only cloud collector + derivation engine | [github.com/ustayready/thunderstorm](https://github.com/ustayready/thunderstorm) |
| *your tool here* | producer or consumer | emit or read `.rage.ndjson` and it interoperates |

Anything that reads or writes the format speaks RAGE. Conforming producers and engines
conform to the registries in this repository; RAGE depends on none of them. See
[`COMPATIBILITY.md`](COMPATIBILITY.md) for how implementations pin to a `spec_version`.

## What's here

- `spec/format.md` - the wire format (records, `node_id` grammar, `.rage.zip`, scope).
- `spec/edges.md` - edge semantics: direction/traversal, `state`, `weight`/`walkable`, canonicalization.
- `spec/rules.md` - rule-evaluation semantics: fixpoint, state-merge, the function catalog.
- `schemas/` - JSON Schema for all 8 record kinds.
- `vocab/` - `node-types.json` + `edge-types.json` + `conditions.json`.
- `rules/derivation.json` - the edge-derivation contract (per edge: conditions + per-cloud permissions/triggers).
- `rules/{derived,explicit}/**` - the executable corpus of 2,400+ `match/where/emit` rules.
- `providers/{aws,gcp,azure}.json` - native to generic mappings + node recipes + fact recipes.
- `exposure-db/{aws,gcp,azure}.json` + `vocabulary.json` - the Exposure DB (1,049 leak sites).
- `TAXONOMY.md` - the entire corpus, human-readable (generated from the registries above).
- `tools/rage_engine.py` - the reference rule engine: runs the derived-rule corpus over a graph to a fixpoint.
- `validate/` - record (full JSON Schema), registry, permission-string, and rule-corpus validators.
- `examples/` - a minimal valid graph exercising all 8 record kinds.

## Validating

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python validate/rage_validate.py examples/minimal.rage.ndjson   # full JSON Schema + refs
./.venv/bin/python validate/check_registries.py    # registry integrity
./.venv/bin/python validate/check_rules.py         # rule corpus vs vocab
```

CI runs all of the above plus a `gen_taxonomy` no-drift gate.

## License

Apache-2.0 (see [`LICENSE`](LICENSE)).
