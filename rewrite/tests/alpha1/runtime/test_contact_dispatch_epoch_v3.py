"""Finite dispatch epoch assembly; this does not issue installed material."""
from dataclasses import replace

import pytest
from test_contact_deadline_v3 import envelope
from sylanne3.graph_types import GraphSnapshot, NamespaceEpoch
from sylanne3.runtime.domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOwnerGuardV1, ProductionQueryCoverageV1,
)
from sylanne3.runtime.contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
from sylanne3.runtime.contact_final_stage_v3 import _contact_dispatch_epoch_frame_v3
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


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
    else:
        with pytest.raises(ValueError, match='complete actual query coverage'):
            _contact_dispatch_epoch_frame_v3(frame)
