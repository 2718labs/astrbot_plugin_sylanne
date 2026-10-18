"""Finite dispatch epoch assembly; this does not issue installed material."""
from dataclasses import replace
import math

import pytest
from test_contact_deadline_v3 import envelope
from sylanne3.graph_types import GraphSnapshot, NamespaceEpoch
from sylanne3.runtime.domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOwnerGuardV1, ProductionQueryCoverageV1,
)
from sylanne3.runtime.contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
from sylanne3.runtime.contact_final_stage_v3 import _contact_dispatch_epoch_frame_v3
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch, canonical_digest


@pytest.mark.parametrize('drift', [None, 'missing', 'duplicate', 'partial', 'page_epoch', 'guard_namespace'])
def test_dispatch_epoch_keeps_all_cas_and_inventory_evidence(drift):
    env = envelope()
    ns = env.authority.namespace
    query = QueryEpoch(ns, 'namespace', 2)
    pages = tuple(ProductionQueryCoverageV1(query, kind, (), True, None) for kind in CONTACT_FINAL_QUERY_TYPES_V3)
    if drift == 'missing': pages = pages[:-1]
    if drift == 'duplicate': pages = pages[:-1] + (pages[0],)
    if drift == 'partial': pages = (replace(pages[0], complete=False, continuation_ref='continue'),) + pages[1:]
    if drift == 'page_epoch': pages = (replace(pages[0], epoch=replace(query, revision=1)),) + pages[1:]
    guarded = replace(query, namespace=NamespaceId('other', 'persona')) if drift == 'guard_namespace' else query
    if drift == 'guard_namespace':
        with pytest.raises(ValueError, match='version guard namespace differs'):
            replace(env, version_guard=replace(env.version_guard, query_epochs=(guarded,)))
        return
    env = replace(env, version_guard=replace(env.version_guard, query_epochs=(guarded,)))
    frame = CurrentOperationFrameV1(env, GraphSnapshot((), (NamespaceEpoch(*ns.as_tuple, 2),)),
        100., ProductionOwnerGuardV1('actual-grant', 1, 'a'*64, 'b'*64), 1, pages, (), ())
    if drift is None:
        actual = _contact_dispatch_epoch_frame_v3(frame)
        assert actual.envelope.version_guard.query_epochs == (QueryEpoch(ns, 'all', 2),)
        assert actual.snapshot is frame.snapshot and actual.query_coverage is frame.query_coverage
        assert actual.envelope.identity is env.identity
        assert actual.envelope.source_qualification is env.source_qualification
        assert actual.envelope.version_guard.read_versions == env.version_guard.read_versions

        # Shared constructor unit only; no installed, provider or ledger proof.
        original_envelope = actual.envelope
        original_digest = canonical_digest(original_envelope)
        deadline = original_envelope.deadline_utc
        positive = replace(actual, now_utc=math.nextafter(deadline, -math.inf))
        assert positive.envelope is original_envelope
        assert positive.snapshot is actual.snapshot
        assert positive.owner_guard is actual.owner_guard
        assert positive.query_coverage is actual.query_coverage
        assert canonical_digest(positive.envelope) == original_digest
        for controlled_now in (deadline, math.nextafter(deadline, math.inf)):
            with pytest.raises(ValueError, match='^production frame time is invalid or expired$') as denied:
                replace(positive, now_utc=controlled_now)
            current = denied.value.__traceback__
            while current is not None and current.tb_frame.f_code is not CurrentOperationFrameV1.__post_init__.__code__:
                current = current.tb_next
            assert current is not None, 'the exact production frame constructor must reject'
            refused_frame = current.tb_frame.f_locals['self']
            assert refused_frame.now_utc == controlled_now
            assert refused_frame.envelope is original_envelope
            assert canonical_digest(refused_frame.envelope) == original_digest
    else:
        with pytest.raises(ValueError, match='complete actual query coverage'):
            _contact_dispatch_epoch_frame_v3(frame)
