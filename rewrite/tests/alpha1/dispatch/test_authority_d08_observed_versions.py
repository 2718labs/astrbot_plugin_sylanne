"""D08 never derives a current conflict PASS from an unbound effect DTO."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from rewrite.tests.alpha1.dispatch.test_authority_budget_snapshot import _case
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.graph_types import GraphSnapshot, NamespaceEpoch
from sylanne3.runtime.dispatch_current_commitments import (
    read_current_d08_observed_versions,
)
from sylanne3.runtime_contracts import QueryEpoch


def test_d08_observed_versions_rejects_effect_outside_snapshot_head():
    namespace, context, witness, authority_snapshot, _ = _case()
    effect = CurrentEffectReadV2(
        context.permit.authority_id, context.permit.namespace,
        context.permit.effect_id, context.permit.generation, "unresolved",
        authority_snapshot.anchor.execution_seq,
        authority_snapshot.anchor.execution_digest,
        effect_seq=authority_snapshot.anchor.execution_seq - 1,
        append_id="append:old", append_digest="sha256:" + "1" * 64,
        mutation_id=authority_snapshot.unresolved_effects[0].mutation_id,
    )
    graph = GraphSnapshot((), (NamespaceEpoch(*namespace.as_tuple, 0),))
    with pytest.raises(ValueError, match="claimed P2 effect"):
        read_current_d08_observed_versions(
            SimpleNamespace(in_transaction=True), namespace, graph,
            QueryEpoch(namespace, "all", 0), "action:test", context, witness,
            authority_snapshot, effect)


def test_d08_observed_versions_rejects_foreign_owner_snapshot():
    namespace, context, witness, authority_snapshot, _ = _case()
    effect = CurrentEffectReadV2(
        context.permit.authority_id, context.permit.namespace,
        context.permit.effect_id, context.permit.generation, "unresolved",
        authority_snapshot.anchor.execution_seq,
        authority_snapshot.anchor.execution_digest,
        effect_seq=authority_snapshot.anchor.execution_seq,
        append_id="append:claimed",
        append_digest=authority_snapshot.anchor.execution_digest,
        mutation_id=authority_snapshot.unresolved_effects[0].mutation_id,
    )
    graph = GraphSnapshot((), (NamespaceEpoch(*namespace.as_tuple, 0),))
    with pytest.raises(RuntimeError, match="snapshot differs"):
        read_current_d08_observed_versions(
            SimpleNamespace(in_transaction=True), namespace, graph,
            QueryEpoch(namespace, "all", 0), "action:test", context,
            replace(witness, grant_id="grant:foreign"), authority_snapshot,
            effect)
