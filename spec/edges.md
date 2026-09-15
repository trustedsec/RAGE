# RAGE Edge Semantics (v0.1)

The wire format (`format.md`) says how to serialize an edge; this says what an edge **means**, how
producers should choose between overlapping types, how a consumer traverses them, and what `weight`,
`walkable`, `state`, and `conditions` are for. `vocab/edge-types.json` is the registry.

## Direction & traversal

- An edge is directed from the **capable party** (`source`) to the **target** of the capability:
  "`source` can do X to/as `target`." A path-finder traverses **source → target** — an attacker who
  controls `source` gains the capability over `target`.
- `walkable: true` means the traversal is a real attacker move (identity/exec/credential/network/
  data/cross-boundary/derived edges). `walkable: false` marks **structural** edges (`Contains`,
  `LocatedIn`, `AttachedTo`) — present for context and grouping, not for path-finding.
- **Exposure edges are the one direction exception.** `ExposedToInternet` /
  `ExposedToTenant`/`ExposedToAccount` point *resource → AnonymousIdentity/boundary* to read
  naturally ("bucket is exposed to the internet"). For traversal they are **entry-point seeds**: the
  reachable principal (Internet/tenant/account) is the *start*, the resource is where the attacker
  arrives. A path-finder consumes `ExposedTo*` in reverse (target → source) to seed footholds, then
  follows normal edges forward. Producers MUST keep the `resource → principal` orientation so this
  convention holds.

## state (traversability gate)

| state | meaning for the path-finder |
|---|---|
| `ACTIVE` | all preconditions met — traverse it |
| `CONDITIONAL` | traversable **iff** the listed `conditions` hold — traverse with that caveat |
| `POTENTIAL` | the capability doesn't exist yet but `source` could create it — traverse only in "what-if" mode |
| `BLOCKED` | a guardrail (SCP / deny assignment / explicit deny) prevents it — do not traverse |
| `UNKNOWN` | insufficient collection to decide — traverse only if modeling worst-case |

Default when omitted: `ACTIVE`.

## weight & confidence (path scoring)

- `base_weight` (on the edge **type**) and `weight` (on an instance) are a **traversal cost** —
  lower is cheaper / more likely for an attacker. It is a cost, **not** a probability. A `path`'s
  `score` aggregates the weights of its edges; the cheapest path is the most attainable. Rough
  scale: `~1` = a direct, unconstrained capability; higher = more hops/conditions/effort.
- `confidence` (0–1) is the producer's certainty the *instance* exists (e.g. a conditional allow
  lowers it). It is orthogonal to `weight`.

## conditions

An edge's `conditions` list the preconditions that gate it (see `state = CONDITIONAL`). The token
vocabulary is `vocab/conditions.json` (open — rule-specific tokens are allowed). A `CONDITIONAL`
edge SHOULD list the conditions still **unmet**; an `ACTIVE` edge has none outstanding. In
`rules/derivation.json` the per-edge `conditions` are the *typical* preconditions for that edge
type; the authoritative, per-instance conditions come from the `rules/` corpus that emitted the edge.

## Canonicalization: which edge to emit

Several edge types overlap. **Producers MUST emit the most specific edge that applies** and MAY
additionally emit a summary edge. Consumers SHOULD understand the subsumption below so a graph from
one producer (specific edges) and another (summary edges) still compare.

### Subsumption table

| Summary / general edge | Specific edges that imply it | Rule of thumb |
|---|---|---|
| **CanAssume** (obtain another identity's session) | `CanImpersonate` (SA impersonation / act-as), `CanFederateAs` (OIDC/SAML/WIF federation), `CanRetrieveToken` (metadata/token mint) | emit the **mechanism** you observed; `CanAssume` is AWS role-assumption specifically and the umbrella concept |
| **CanExecuteOn** (get code running on a resource) | `CanExecuteCommand`, `CanInvoke`, `CanDeploy`, `CanModifyCode`, `CanModifyConfiguration`, `CanStart`, `CanTrigger`, `CanSchedule` | emit the specific execution primitive; `CanExecuteOn` is a computed superset |
| **CanControl** (effective control of a target) | `CanAdminister` (full admin/owner), plus sufficient sub-capabilities (`CanModifyPolicy`, `CanTakeOwnership`, `CanModify`, …) | `CanAdminister` = a single admin grant; `CanControl` = derived "admin OR enough pieces"; `Controls` = the terminal objective edge on a finished path |
| **CanGrantPermission** vs **CanModifyPolicy** | — | `CanModifyPolicy` = edit a policy **document**; `CanGrantPermission` = assign a role/permission. Emit the one matching the mechanism; both are privesc primitives |
| **CanRead/CanWrite/CanModify** (control-plane) vs **CanReadData/CanWriteData** (data-plane) | — | use the **data** edges for reads/writes of the stored data in a store; the generic ones for control-plane operations on the resource object |
| **CanReadSecret** vs **CanReadCredential** | — | `CanReadSecret` = read a secret-manager/KV secret; `CanReadCredential` = obtain a credential object (access key, SA key, token) |
| **CanCreateCredentialFor** | `CanCreateKey` (service-account-key case) | creating an SA key **is** minting a credential for that identity — emit `CanCreateCredentialFor`; `CanCreateKey` is the key-material view (also covers KMS `CreateKey`) |

`CanExecuteOn` is a **roll-up** produced by `rules/derived/capability-completions.yaml` from any
specific execution edge — producers emit the specific primitive; consumers may rely on the roll-up.

### Derived vs foundational

`nature: explicit` edges come straight from configuration (a trust policy → `CanAssume`). `nature:
derived` edges are composed by the `rules/` corpus from other edges (`CanModifyCode` + `ExecutesAs`
→ `CanExecuteAs`; a chain of capabilities → `CanEscalateTo`). A derived edge MUST carry `evidence`
and SHOULD carry `derived_from` (the edge_ids it was built from) and `rule_id`. See `rules.md`.
