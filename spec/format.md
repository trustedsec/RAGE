# RAGE Format (v0.1)

## The bundle

A RAGE graph is **one NDJSON file** (`*.rage.ndjson`): one JSON object per line.

- **Line 1 MUST be the `manifest`.**
- Every other line is a record with a `kind` field.
- Order is otherwise free. Unknown `kind`s MUST be ignored (forward-compatible).

**Media type:** `application/vnd.rage.graph+ndjson`. A producer SHOULD also self-declare it in the
manifest via `media_type` so a bare file is identifiable without its extension.

**`.rage.zip` (optional packaging).** For upload-size limits or attaching raw blobs, a graph MAY be
zipped. The zip layout is normative:

- Exactly one `*.rage.ndjson` at the archive root is the graph (the canonical unit). A consumer
  reads that file and ignores the rest.
- Optional `blobs/` — raw API responses referenced by `evidence.pointer` (`blobs/<hash>`).
- No other interpretation: a `.rage.zip` is a single graph plus its optional blobs, never multiple
  graphs.

## Record kinds

### manifest (line 1)
Required: `spec_version`.
Optional: `created_at`, `scope` (providers, foothold node_id), `producer` (opaque version
strings), `counts` (nodes/edges/findings — so consumers don't scan to count).

### node
Required: `node_id`, `node_type`.

**`node_id` grammar (normative).** A `node_id` MUST be four `|`-delimited components:

```
<provider>|<account>|<native_type>|<native_id>
```

- `provider` — `aws` | `gcp` | `azure` | a producer-defined lowercase token for other systems.
- `account` — the identity/billing realm: AWS account id, GCP project id, Azure subscription id
  (or tenant id for tenant-scoped objects). This is the collision boundary, so `sa@proj-a` ≠
  `sa@proj-b`.
- `native_type` — the provider's own resource type string (e.g. `gcp:iam:service-account`,
  `aws:s3:bucket`, `Microsoft.Storage/storageAccounts`).
- `native_id` — the provider's stable identifier (ARN, resource id, self-link, or name).

**Escaping.** Any literal `|` inside a component MUST be percent-encoded as `%7C` (and `%25` for a
literal `%`). Consumers split on unescaped `|` only. This makes the id unambiguous and reversible.

**Regional/global scope** lives in the node's optional `scope` object (`region`/`location`), NOT in
the `node_id` — a resource keeps one id across regional views. Cross-scope children (a subnet in a
region) still use the account of their subscription/project as the realm.

**Merging graphs from multiple producers.** Because the realm (`provider|account`) and `native_id`
are producer-independent, two producers that both follow this grammar emit **identical** `node_id`s
for the same resource, so their graphs union by `node_id` without a reconciliation pass. Producers
that cannot follow the grammar MUST still emit a globally-unique `node_id` and SHOULD set
`x-<provider>` hints to aid matching.

- `node_type` is the generic taxonomy type (`ServiceAccount`, `ObjectStorage`, …). It SHOULD come
  from `vocab/node-types.json`, but the vocab is **open** — unknown types are allowed (map to the
  nearest type + keep the native type verbatim).
Optional: `provider`, `name`, `scope`, `observed_at`, `attributes` (free bag; provider extras
under `x-<provider>`).

### edge
Required: `source`, `target`, `type`.
- `source`/`target` are `node_id`s. `type` is the capability (`CanImpersonate`, …). It
  SHOULD come from `vocab/edge-types.json` (open registry) — each type declares its legal
  `source`/`target` node types, `walkable`, and `category`.
Recommended: `state` (default `ACTIVE`), `nature` (`explicit`|`derived`, default `explicit` —
`explicit` = observed directly from configuration, `derived` = synthesized by a rule),
`edge_id`, `facts` (array of `fact_id`s that justify this edge — the provenance link).
- **Conditional:** if `nature` is `derived`, `evidence` is REQUIRED (an `evidence_id`, or an
  array of them). This is what keeps every *derived* edge explainable.

### fact
A normalized observation the graph was built from — the middle of the provenance chain
`evidence (API) → fact → edge/finding`.
Required: `fact_id`.
Recommended: `edge_hint` (the edge type this fact suggests), `source`/`target` (node refs),
`provider`, `scope`, `captured_at`, `content_hash`, `evidence` (the `evidence_id`(s) — which
API collection produced this fact), `attributes`.

### finding (exposure)
Required: `resource_id` (the exposed `node_id`), `severity` (`low|medium|high|critical`).
Optional: `location`, `emits_hint`, `value_ref`, `evidence`.

### evidence
The tamper-evident **receipt** at the base of the chain — typically one API/collection
operation.
Required: `evidence_id`, `content_hash` (hash-addressable).
Recommended: `source` (the API/operation, e.g. `azure:role_assignment:list`), `status`
(collection outcome: `ok`/`denied`/…), `captured_at`, `scope`, `pointer` (where the raw
response lives, if retained), `detail` (opaque bag).

### surface (optional) / path (optional)
Extension kinds a producer MAY emit (attack surfaces; precomputed multi-hop paths). Not
part of the required core; consumers that don't understand them skip them.

## Rules

- **Required = the floor for any producer.** A minimal graph is `manifest + node + edge`.
- **Optional = present when the producer did that analysis.** Absence means "none," not
  "unknown." `counts` in the manifest says what's inside.
- **Extend without forking:** new provider → `x-<provider>` attributes; unknown resource →
  nearest `node_type` + keep the native type verbatim; new `kind` → old readers skip it.

## Scope

RAGE models an **identity/access attack graph**: who can reach and act on what, and how those
capabilities chain. The following are **out of scope for v0.1** — intentionally, to keep the core
focused:

- **Vulnerabilities / exploits (CVEs).** RAGE has no `vulnerability` node or exploit edge. A
  producer that also does vuln analysis MAY attach it via the open extension — e.g.
  `finding.x-vuln = {"cve": "CVE-2026-1234", "cvss": 9.8}` on the affected node's finding, or an
  `x-<producer>` edge — without forking the spec. First-class vuln modeling may be reconsidered in
  a later version.
- **Runtime/behavioral telemetry** (process trees, netflow) — RAGE is a configuration/relationship
  graph, not an EDR.

`finding` records represent **exposures** (a credential or resource an attacker can reach), not
software vulnerabilities.

## The corpus (normative companions)

The wire format above says how to *serialize* a graph. The vocabulary that gives records meaning
lives in these registries — RAGE is the source of truth for all of them:

- **`vocab/node-types.json`** — the node taxonomy: 10 classes, 105 generic `node_type`s (each a
  security role, not a product).
- **`vocab/edge-types.json`** — the edge taxonomy: 80 `type`s across 9 categories, with
  `relationship_kind`, allowed `source`/`target`, `walkable`, and `high_value`.
- **`rules/derivation.json`** — **how** each edge is derived: `nature` (explicit/derived/both),
  `conditions`, and the concrete per-cloud `permissions`/`triggers` that realize it.
- **`providers/{aws,gcp,azure}.json`** — two collection layers:
  - `resources[]` — the native→generic **mappings** + **node recipes** (enumerate operation,
    id/arn fields, detail-enrichment chain, required permissions) for every concrete resource type.
  - `facts[]` — the **fact/relationship recipes**: how to collect the policies, role
    assignments/bindings, trust policies, group memberships, network rules, and credential objects
    that back *edges*. Each fact recipe declares `kind`, `collect` (operation/over/scope), the edge
    types it `backs`, and `required_permissions`. Guardrail facts (SCPs, deny assignments) carry an
    empty `backs` — they constrain edges to `BLOCKED` rather than producing one.

### Collection coverage (v0.1)

Node recipes alone yield inventory + structural edges. The `facts[]` recipes back the **foundational**
walkable edges (`HasPermission`, `HasRole`, `MemberOf`, `CanAssume`, `CrossAccountTrust`, resource-policy
and network edges, credential edges); the **capability/derived** edges (`CanRead*`, `CanModify`,
`CanExecuteAs`, `CanEscalateTo`, `CanEnter*`, …) are composed from those foundations by the rules in
`rules/`. Together they make **all 70 walkable edge types producible** — the last four
(`CanExecuteOn`, `CanReplace`, `CanCreateKey`, `AuthenticatesTo`) are covered by the
`rules/derived/capability-completions.yaml` roll-up/derivation rules.

Aspirational, not-yet-collected areas (documented limitations, not silent omissions): **in-cluster
Kubernetes** (`KubernetesWorkload`, `ContainerTask`, pod-level `Container` — only the cluster object is
collected) and **external IdP identities** (`ExternalIdentity`/`FederatedIdentity` from
Okta/GitHub/Entra-as-IdP — the CSP side of `FederatesTo` is collected, the external side is not).

- **`vocab/conditions.json`** — the (open) vocabulary for edge/rule `conditions` (the preconditions
  that gate a `CONDITIONAL` edge).
- **`exposure-db/{aws,gcp,azure}.json`** + `exposure-db/vocabulary.json` — the **Exposure DB**: 1,049
  exposure sites (every place a credential/secret can leak), each mapped to the RAGE edge it `emits`,
  its collection recipe (`access_mode`/`operation`/`required_permissions`), where it sits
  (`location`/`location_kind`), and what leaks (`data_kinds`).

Both registries are **open**: unknown types are legal (map to the nearest generic + keep the
native string). [`../TAXONOMY.md`](../TAXONOMY.md) renders the whole corpus for humans; regenerate
it from the registries with `tools/gen_taxonomy.py`. Validate the registries' internal integrity
with `validate/check_registries.py` and the rule corpus with `validate/check_rules.py`.

**Companion specs:**
- [`edges.md`](edges.md) — edge semantics: direction/traversal, `state`, `weight`/`walkable`, and
  **canonicalization** (which of overlapping edges like `CanAssume`/`CanImpersonate` to emit).
- [`rules.md`](rules.md) — rule-evaluation semantics: the fixpoint, state-merge, and the normative
  **function catalog** (`effective_action_on`, `node_type`, …) two engines must agree on.
