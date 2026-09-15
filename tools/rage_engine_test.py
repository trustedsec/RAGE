#!/usr/bin/env python3
"""Proves the reference engine executes the corpus: a synthetic graph whose explicit edges must
compose — across a fixpoint — into the classic credential-pivot chain. Run: python3 tools/rage_engine_test.py
(or under pytest). Needs PyYAML."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rage_engine as R  # noqa: E402


def _graph():
    g = R.Graph()
    nodes = {
        "aws|acct|iam|attacker": "HumanIdentity",
        "aws|acct|iam|workload": "ServiceAccount",
        "aws|acct|sm|secret": "Secret",
        "aws|acct|iam|sa-admin": "ServiceAccount",
    }
    cls = {"HumanIdentity": "Identity", "ServiceAccount": "Identity", "Secret": "Secret"}
    for nid, nt in nodes.items():
        g.node_type[nid] = nt
        g.node_class[nid] = cls[nt]

    def E(t, s, d):
        g._add_raw({"kind": "edge", "edge_id": R.edge_id(t, s, d), "type": t, "source": s,
                    "target": d, "nature": "explicit", "state": "ACTIVE", "evidence": ["ev:x"]})
    # attacker -CanExecuteAs-> workload -CanReadSecret-> secret -CredentialsFor-> sa-admin
    E("CanExecuteAs", "aws|acct|iam|attacker", "aws|acct|iam|workload")
    E("CanReadSecret", "aws|acct|iam|workload", "aws|acct|sm|secret")
    E("CredentialsFor", "aws|acct|sm|secret", "aws|acct|iam|sa-admin")
    return g


def _has(g, t, s, d):
    return any(e["type"] == t and e["source"] == s and e["target"] == d for e in g.edges)


def test_engine_executes_credential_chain():
    g = _graph()
    st = R.run(g, R.load_rules())
    assert st["derived"] > 0, "engine derived nothing — corpus did not execute"
    # round 1: execute-then-read-secret composes CanExecuteAs+CanReadSecret -> CanReadSecret(attacker->secret)
    assert _has(g, "CanReadSecret", "aws|acct|iam|attacker", "aws|acct|sm|secret"), \
        "expected derived CanReadSecret(attacker->secret)"
    # round 2 (fixpoint): read-secret-yields-identity turns that into CanImpersonate(attacker->sa-admin)
    assert _has(g, "CanImpersonate", "aws|acct|iam|attacker", "aws|acct|iam|sa-admin"), \
        "expected derived CanImpersonate(attacker->sa-admin) via fixpoint"
    assert st["rounds"] >= 2, "expected a multi-round fixpoint"


def test_derived_edges_carry_provenance():
    g = _graph()
    R.run(g, R.load_rules())
    for e in g.edges:
        if e.get("nature") == "derived":
            assert e.get("evidence"), f"derived edge {e['type']} has no evidence"
            assert e.get("derived_from"), f"derived edge {e['type']} has no derived_from"


if __name__ == "__main__":
    test_engine_executes_credential_chain()
    test_derived_edges_carry_provenance()
    print("ok: rage_engine executes the corpus (credential chain composes across a fixpoint)")
