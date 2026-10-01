"""Actual issued location/fence checks on a genuinely RELEASED four-store case."""
from dataclasses import replace
from pathlib import Path
import sqlite3
from uuid import uuid4
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.runtime_contracts import canonical_digest


def assert_current_source_location_v1(maintenance,*,credential,subject,holder):
    qualifier=maintenance.current_source_location;service=qualifier._fences
    operation='location-acceptance:'+uuid4().hex
    permit=service.begin_fence(credential=credential,subject=subject,holder=holder,operation='read',operation_id=operation,
        expected_anchor=service.current_anchor(credential=credential,subject=subject))
    try:
        observed=qualifier.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
        with service.core._tx() as db:assert qualifier.require_current_in_tx_v1(db,observed) is observed
        graph=sqlite3.connect(Path(observed.graph_db_path).as_uri()+'?mode=ro',uri=True,isolation_level=None)
        try:
            graph.execute('BEGIN')
            assert qualifier.require_graph_snapshot_v1(graph,observed,graph_db_path=observed.graph_db_path) is observed
            try:qualifier.require_graph_snapshot_v1(graph,replace(observed),graph_db_path=observed.graph_db_path)
            except AuthorityUnavailable:pass
            else:raise AssertionError('copied location DTO was accepted')
        finally:graph.close()
        with service.core._tx() as db:
            changed=replace(observed,purpose='accepted_erasure')
            try:qualifier.require_current_in_tx_v1(db,changed)
            except AuthorityUnavailable:pass
            else:raise AssertionError('wrong-purpose copied location was accepted')
    finally:
        service.finish_fence(credential=credential,subject=subject,permit=permit,
            request_id='location-finish:'+uuid4().hex,request_digest='sha256:'+canonical_digest(operation))
    with service.core._tx() as db:
        try:qualifier.require_current_in_tx_v1(db,observed)
        except AuthorityUnavailable:pass
        else:raise AssertionError('finished business fence was still current')
    return observed.storage_generation
