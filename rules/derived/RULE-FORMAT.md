# Derived-Edge Rule Format (Version 1)  — Deliverable 10

Derived edges are produced by **rules** that match a pattern of existing edges
(explicit or already-derived) and emit a new edge with full evidence. Rules are
declarative, provider-aware, and idempotent.

A rule is machine-readable YAML with this shape:

```yaml
rule:
  id: <stable-kebab-id>            # unique; referenced by emitted edge.rule_id
  emits: <CommonEdgeType>          # must exist in edges.yaml, nature: derived|both
  description: <one line>
  applies_to: [aws, azure, gcp]    # provider scope; use ["*"] for provider-agnostic

  # MATCH: a conjunctive graph pattern. Variables (?x) bind node_ids.
  # Each clause is [ ?src, EdgeType, ?dst ] with optional constraints.
  match:
    - [ ?attacker, CanModifyCode, ?compute ]
    - [ ?compute,  ExecutesAs,    ?identity ]
  # optional additional non-edge constraints
  where:
    - ?identity.privilege_level >= ?attacker.privilege_level   # only if escalation
    - node_type(?compute) in [ServerlessFunction, Container, VirtualMachine]

  # OPTIONAL clauses that upgrade/downgrade the emitted state instead of blocking.
  optional:
    - [ ?attacker, CanInvoke, ?compute ]        # present -> ACTIVE, absent -> CONDITIONAL(trigger_exists)

  # EMIT: the new edge
  emit:
    source: ?attacker
    target: ?identity
    state_logic: |
      if matched(optional[0]) or trigger_exists(?compute): ACTIVE
      else: CONDITIONAL(trigger_exists)
    conditions_from: [ ?compute, ?identity ]     # merge unmet conditions from contributors
    confidence: min(contributing_confidences) * rule_prior
    weight: sum(contributing_weights) + emits.base_weight
    permissions: union(contributing.permissions)
    derived_from: [ <all matched edge_ids in order> ]
    evidence:
      narrative_template: >
        {attacker.name} can execute as {identity.name} because it can modify the
        code of {compute.name} (via {perm:CanModifyCode}), which executes as
        {identity.name}{if optional[0]: ", and can invoke it directly"}.
```

## Evaluation semantics
- **Fixpoint**: rules run repeatedly until no new edges are produced (derived
  edges can feed other rules — that is how multi-hop capabilities collapse).
- **Monotonic + deduped**: an edge (type,source,target,scope) is emitted once;
  re-derivation with higher confidence/lower weight updates in place.
- **State propagation**: an emitted edge is never stronger than its weakest
  contributor (a CONDITIONAL input yields at best CONDITIONAL output). A BLOCKED
  contributor blocks the derivation.
- **Provider isolation**: provider rules live in `/rules/derived/<provider>/`
  and may only match edges/nodes; they never mutate the taxonomy.
- **Explainability is mandatory**: every emitted edge MUST carry `derived_from`
  and a rendered narrative (see /docs/evidence-model.md).

## Typed emit refs (`source_type` / `target_type`) — REQUIRED for new rules
The `emit.source` / `emit.target` values are human-readable node references
(often prose, e.g. `<member Account that owns ?oaar>`). To let the conformance
linter (`scripts/lint_edges.py`) statically verify that an emit's node CLASS is
admissible for its edge, every emit SHOULD also declare the node type explicitly:

```yaml
  emit:
    source_type: Identity          # node class or subtype of emit.source
    target_type: Account           # node class or subtype of emit.target; "*" if the
                                    # edge target set is "*" (intentionally any)
    source: ?principal
    target: "<member Account that owns ?oaar>"
```

- The value must be a class or subtype from `schema/nodes.yaml`, and must be
  within the emitting edge's declared `source` / `target` set in
  `schema/edges.yaml`. The linter treats these as authoritative (falls back to
  mining the prose only when a `*_type` is absent).
- For a re-emission rule (`emits: ?cap`, a state-upgrade that re-emits the matched
  edge), omit `*_type` — conformance is inherited from the matched edge.
- Existing rules were backfilled by `scripts/backfill_emit_types.py` for the
  schema-forced and prose-unambiguous cases; emits whose edge admits several
  classes and whose prose does not name exactly one are left untyped and must be
  annotated by hand (that untyped tail is what still blocks `derived -> verified`).

## Where rules live
```
/rules/explicit/            # normalization rules: raw config -> explicit edges
/rules/derived/             # provider-agnostic derivations (this format)
/rules/derived/aws/         # provider-specific derivations
/rules/derived/azure/
/rules/derived/gcp/
```
Provider-specific rules SHOULD emit common edge types and only exist separately
when the *derivation logic* (not the concept) is provider-specific.
