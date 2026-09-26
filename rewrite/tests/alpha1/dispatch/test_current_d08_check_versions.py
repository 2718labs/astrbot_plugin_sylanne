"""Frozen D08 refs must equal observed graph/P2 versions, never test literals."""

from dataclasses import replace
import json
import sqlite3

import pytest

from rewrite.tests.alpha1.d08.test_goal_execution_domain import _intent
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.runtime.dispatch_current_commitments import (
    CurrentD08ObservedVersionsV1, _map_current_d08_check_versions,
)
from sylanne3.runtime_contracts import (
    CheckReceipt, NamespaceId, QueryEpoch, VersionedRef,
)


def _case():
    namespace = NamespaceId("bot", "sylanne")
    intent = _intent()
    criterion = AtomKey(Owner("persona", *namespace.as_tuple),
                        "d08.criteria.v1", "commitment")
    value = {"policy": "current"}
    graph = GraphSnapshot((GraphAtom(criterion, 1, value),),
                          (NamespaceEpoch(*namespace.as_tuple, 4),))
    query = QueryEpoch(namespace, "all", 4)
    cancellation = AtomKey(
        Owner("activity", *namespace.as_tuple, intent.identity.activity_id),
        "d08.action_cancellation.v1", intent.action_id)
    job = AtomKey(
        Owner("activity", *namespace.as_tuple, intent.identity.activity_id),
        "runtime.job", "job:test")
    observed = CurrentD08ObservedVersionsV1(
        query, VersionedRef(intent.goal_ref, 1),
        (VersionedRef(intent.commitment_refs[0], 1),),
        2, "sha256:" + "a" * 64, GraphVersion(cancellation, 1),
        GraphVersion(job, 1), "binding:digest", (), "snapshot:digest")
    frozen = (
        VersionedRef(criterion.token, 1),
        VersionedRef(intent.goal_ref, 1),
        VersionedRef(intent.commitment_refs[0], 1),
        VersionedRef("commitments-query:persona:sylanne", 4),
        VersionedRef(f"execution-epoch:{intent.action_id}", 2),
        VersionedRef(f"cancellation-epoch:{intent.action_id}", 1),
    )
    old_spec = next(item for item in intent.required_checks
                    if item.check_kind == "commitment_conflict")
    spec = replace(old_spec, criteria_version=criterion.token,
                   required_input_versions=frozen)
    intent = replace(intent, required_checks=tuple(
        spec if item.check_kind == "commitment_conflict" else item
        for item in intent.required_checks))
    receipt = CheckReceipt(
        spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
        frozen, "full", "pass", 20.0, spec.provider_id)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_epochs(bot TEXT, persona TEXT, revision INT)")
    db.execute("CREATE TABLE graph_atoms(token TEXT, bot TEXT, persona TEXT, "
               "revision INT, value TEXT, valid INT)")
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", (*namespace.as_tuple, 4))
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)", (
        criterion.token, *namespace.as_tuple, 1,
        json.dumps(value, separators=(",", ":")), 1))
    return db, namespace, graph, query, intent, spec, receipt, observed


def test_current_d08_version_mapping_accepts_only_exact_observed_versions():
    db, namespace, graph, query, intent, spec, receipt, observed = _case()
    try:
        assert _map_current_d08_check_versions(
            db, namespace, graph, query, intent, spec, receipt, observed,
            now_utc=5.0) == spec.required_input_versions
    finally:
        db.close()


def test_pre_p2_receipt_execution_version_is_stale():
    db, namespace, graph, query, intent, spec, receipt, observed = _case()
    try:
        old = tuple(replace(item, version=0)
                    if item.ref == f"execution-epoch:{intent.action_id}" else item
                    for item in spec.required_input_versions)
        stale_spec = replace(spec, required_input_versions=old)
        stale_intent = replace(intent, required_checks=tuple(
            stale_spec if item.check_kind == "commitment_conflict" else item
            for item in intent.required_checks))
        stale_receipt = replace(receipt, input_versions=old)
        with pytest.raises(ValueError, match="stale after P2"):
            _map_current_d08_check_versions(
                db, namespace, graph, query, stale_intent, stale_spec,
                stale_receipt, observed, now_utc=5.0)
    finally:
        db.close()


def test_legacy_self_reported_criteria_ref_has_no_graph_authority():
    db, namespace, graph, query, intent, spec, receipt, observed = _case()
    try:
        legacy = replace(spec, criteria_version="criteria:1",
                         required_input_versions=(
                             VersionedRef("criteria:1", 1),
                             *spec.required_input_versions[1:]))
        intent = replace(intent, required_checks=tuple(
            legacy if item.check_kind == "commitment_conflict" else item
            for item in intent.required_checks))
        receipt = replace(receipt, input_versions=legacy.required_input_versions)
        with pytest.raises(ValueError, match="criteria lacks a current graph address"):
            _map_current_d08_check_versions(
                db, namespace, graph, query, intent, legacy, receipt,
                observed, now_utc=5.0)
    finally:
        db.close()
