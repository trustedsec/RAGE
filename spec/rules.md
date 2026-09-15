# RAGE Rule Evaluation (v0.1)

`rules/{explicit,derived}/**` is the RAGE Rules corpus; `rules/derived/RULE-FORMAT.md` defines a
rule's *shape* (`match → where → optional → emit`). This document defines its **evaluation
semantics** — enough that two independent engines run the same corpus over the same facts and
produce the **same graph**. That is the reproducibility guarantee the format depends on.

## Evaluation model

1. **Explicit pass.** `rules/explicit/**` normalize raw collected config/facts into `nature:
   explicit` edges (a trust policy → `CanAssume`, a public bucket policy → `ExposedToInternet`).
2. **Fixpoint pass.** `rules/derived/**` match a conjunctive pattern of existing edges/nodes and
   emit new edges. Repeat until no new edge is produced (a monotonic fixpoint).
3. **Dedup.** An edge is keyed by `(type, source, target, scope)`. Re-derivation with higher
   `confidence` / lower `weight` updates in place; the id is the deterministic `edge_id`
   (`format.md`).
4. **State merge.** A derived edge is never stronger than its weakest contributor: a `CONDITIONAL`
   input yields at best `CONDITIONAL`; a `BLOCKED` contributor blocks the derivation entirely.
   `conditions` on the output are the union of unmet contributor conditions.
5. **Aggregation.** `confidence = min(contributing_confidences) * rule_prior`;
   `weight = sum(contributing_weights) + emits.base_weight`; `permissions = union(...)`.
6. **Explainability (mandatory).** Every derived edge MUST carry `evidence`, and SHOULD carry
   `derived_from` (the contributor `edge_id`s) and `rule_id`.

Evaluation order within a pass MUST NOT affect the fixpoint result (rules are commutative up to the
dedup/merge rules above) — this is what makes two engines agree.

## Function catalog (normative)

`where` predicates and `emit` expressions may call only the following. An engine MUST implement them
with these meanings; a rule using anything else is non-portable.

**Node/graph accessors**
- `node_type(?x)` → the node's generic `node_type`.
- `node_class(?x)` → the node's taxonomy class (`vocab/node-types.json`).
- `scope(?x)` / `account(?x)` → the node's scope realm / account component of its `node_id`.
- `provider_type(?x)` → the node's verbatim native type.
- `[ ?a, EdgeType, ?b ]` (in `match`) → an edge of that type exists from `?a` to `?b`.

**Authorization**
- `effective_action_on(?principal, ?resource)` → the set of actions `?principal` may perform on
  `?resource` **after full policy evaluation**: identity + resource policy union, minus explicit
  deny, minus SCP/org-policy deny, intersected with any permission boundary. This is the core
  primitive; engines MUST evaluate deny precedence identically (explicit deny and guardrail deny
  win). Companion: `effective_action_on(...) intersects [<actions>]`.
- `role(?assignment)` / `identity(?x)` / `principal(?x)` → resolve an assignment's role / a node's
  identity / a policy statement's principal.
- `privilege_level(?identity)` → an ordinal rank used only to decide whether a lateral capability is
  an **escalation** (`priv(target) > priv(source)`). The ranking is provider-defined but MUST be
  monotonic (admin > power-user > scoped > read-only); engines SHOULD document their ranking.

**Predicates & aggregation**
- `trigger_exists(?resource)` → an invocation trigger/event source exists for the resource.
- `matched(optional[i])` → the i-th `optional` clause matched (drives state up/down).
- `intersects`, `in`, `==`, `>=` → set/relational tests over the above.
- `min`, `sum`, `union` → aggregation over contributing edges (see step 5).

## conditions

Unmet preconditions are attached to the emitted edge as `conditions` (from `vocab/conditions.json`,
open). They gate `state`: an edge with outstanding conditions is `CONDITIONAL`, not `ACTIVE`. See
`edges.md` for how a consumer treats each state during traversal.

## Provider rules

Provider-specific derivations live under `rules/derived/<provider>/` and MAY only match edges/nodes
— they never mutate the taxonomy. They SHOULD emit common edge types and exist separately only when
the *derivation logic* (not the concept) is provider-specific.
