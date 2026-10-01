"""C09 rebase DTOs reject ambiguous recovery and erased-content reads."""

from dataclasses import fields, replace

import pytest

from sylanne3.runtime.c09_storage_rebase_contract_v1 import (
    GraphErasureRebaseCertificateV1, GraphRowDispositionV1,
    GraphTableDispositionManifestV1, SanitizedD02FactV4,
    SanitizedD11FactV4,
    SanitizedExecutionFactV4, SanitizedGraphReadV1,
    SanitizedRecoveryFactsV4, SanitizedUnknownFactV4,
    require_same_operation_replay_v1,
)
from sylanne3.runtime_contracts import canonical_digest
from sylanne3.runtime_journal import RecoveryConstraintFootprint


def digest(value):
    return canonical_digest(value)


def committed(kind, field_name, **values):
    names = [field.name for field in fields(kind) if field.name != field_name]
    defaults = {field.name: field.default for field in fields(kind)
                if field.default is not field.default_factory}
    body = {**defaults, **values}
    body[field_name] = digest(tuple(body[name] for name in names))
    return kind(**body)


def certificate(*, previous=None, prior_keys=(), new_key=None):
    row = GraphRowDispositionV1(digest("row"), digest("old"),
                                "payload_erased_retained_facts", digest("new"))
    manifest = committed(GraphTableDispositionManifestV1, "manifest_digest",
                         table_name="graph_history", rows=(row,))
    new_key = new_key or digest("key-1")
    cumulative = tuple(sorted(set(prior_keys) | {new_key}))
    return committed(
        GraphErasureRebaseCertificateV1, "certificate_digest",
        authority_id="authority", installation_id="installation",
        namespace="bot/persona", operation_id="delete-1" if previous is None else "delete-2",
        accepted_receipt_digest=digest("accepted"),
        barrier_receipt_digest=digest("barrier"),
        frozen_inventory_digest=digest("inventory"),
        old_incarnation="graph-old", old_revision=10,
        old_graph_epoch=10, old_access_epoch=2, old_delete_epoch=2,
        new_incarnation="graph-new" if previous is None else "graph-next",
        maintenance_generation=1 if previous is None else 2,
        table_manifests=(manifest,), source_closure_digest=digest("source"),
        derived_closure_digest=digest("derived"),
        prior_certificate_digest=previous, prior_erased_key_digests=prior_keys,
        newly_erased_key_digests=(new_key,),
        cumulative_erased_key_digests=cumulative,
        tombstone_root=digest(cumulative), new_data_root=digest("data"),
        component_hashes=(("graph.db", digest("bytes")),),
        cold_read_digest=digest("cold-read"),
    )


def recovery(*, executions=(), unknown=(), d02=()):
    return committed(
        SanitizedRecoveryFactsV4, "facts_digest",
        authority_id="authority", installation_id="installation",
        namespace="bot/persona", operation_id="delete-1",
        old_chain_head_digest="sha256:" + digest("old-head"),
        verifier_commitment=digest("verifier"),
        executions=executions, d02_facts=d02, d11_facts=(),
        unknown_facts=unknown, graph_facts=(),
    )


def test_rebase_manifest_and_cumulative_tombstone_are_committed():
    first = certificate()
    second = certificate(previous=first.certificate_digest,
                         prior_keys=first.cumulative_erased_key_digests,
                         new_key=digest("key-2"))
    assert second.cumulative_erased_key_digests == tuple(sorted((digest("key-1"), digest("key-2"))))
    with pytest.raises(ValueError, match="certificate_digest differs"):
        replace(first, new_data_root=digest("different-data"))
    with pytest.raises(ValueError, match="cumulative erased keys differ"):
        replace(second, prior_erased_key_digests=())
    with pytest.raises(ValueError, match="preserved row commitment changed"):
        GraphRowDispositionV1(digest("row"), digest("old"),
                              "preserved_exact", digest("new"))
    require_same_operation_replay_v1(first, first)
    with pytest.raises(ValueError, match="different commitment"):
        require_same_operation_replay_v1(first, certificate(new_key=digest("key-3")))


def test_recovery_unknown_requires_footprint_and_terminal_commitment():
    execution = SanitizedExecutionFactV4(
        "execution", digest("input"), None, digest("terminal"),
        digest("signature"), "unknown", True)
    footprint = RecoveryConstraintFootprint(
        "bot/persona", "activity", "effect", external_query_ref="platform-query",
        conflict_keys=("conflict",))
    fact = SanitizedUnknownFactV4(
        "execution", 2, "platform-query", 1, 5, footprint)
    assert recovery(executions=(execution,), unknown=(fact,)).unknown_facts == (fact,)
    internal = replace(fact, platform_query_ref=None, footprint=RecoveryConstraintFootprint(
        "bot/persona", "activity", "effect", conflict_keys=("conflict",)))
    assert internal.platform_query_ref is None
    with pytest.raises(ValueError, match="unknown execution constraints differ"):
        recovery(executions=(execution,))
    with pytest.raises(ValueError, match="footprint is absent"):
        replace(fact, footprint=RecoveryConstraintFootprint(
            "bot/persona", "activity", "effect"))
    with pytest.raises(ValueError, match="consumed right differs"):
        replace(execution, consumed=False)


def test_d02_cost_and_graph_read_state_are_explicit():
    fact = SanitizedD02FactV4(
        "quote", "component", "outcome", "settlement",
        digest("quote"), digest("completed"), digest("outcome"),
        digest("settlement"), 12)
    assert recovery(d02=(fact,)).d02_facts == (fact,)
    with pytest.raises(ValueError, match="fixed_cost"):
        replace(fact, fixed_cost=None)
    budget = SanitizedD11FactV4(
        "settlement", "parent-budget", "idempotency", 20, 12, 12, 0, 0)
    assert budget.actual_cost == 12
    with pytest.raises(ValueError, match="actual_cost"):
        replace(budget, actual_cost=None)
    with pytest.raises(TypeError):
        SanitizedD11FactV4(
            "settlement", "parent-budget", "idempotency", 20, 12, 12, 0, 0,
            metadata={"body": "forbidden"})
    key = digest("key")
    assert SanitizedGraphReadV1(key, "original", digest("original"), None).status == "original"
    assert SanitizedGraphReadV1(key, "erased", None, digest("certificate")).status == "erased"
    with pytest.raises(ValueError, match="erased read"):
        SanitizedGraphReadV1(key, "erased", digest("old-body"), digest("certificate"))
