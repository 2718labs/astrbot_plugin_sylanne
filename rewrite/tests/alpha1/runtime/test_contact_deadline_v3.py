"""Typed runtime deadline guard; clock values are finite test-local seams.

This issues no current capability. Installed staging must retain the original
monotonic bound while independently checking the advancing paired UTC bound.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.runtime import contact_final_stage_v3 as stage
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest,
)


def envelope():
    ns = NamespaceId('bot', 'persona')
    return CommandEnvelope(RUNTIME_SCHEMA,
        OperationIdentity('activity:contact', 'effect:contact', 'attempt:contact',
            'prepare', 'operation:contact', canonical_digest({'input_refs': []})),
        AuthorityContext('owner', 'd11', 'capability', ns, ('activity',),
            'expression', ('private',), 'policy', 1),
        VersionGuard((), (), 0, 0, 'catalogue', 'scheme', 'operator', 'policy', (), (), ()),
        SourceQualification((), 'reported', 1., 1., 'external_report',
            'eligible', None, 'not_applicable'),
        (), 'lease', 105., 14., 'interval', ())


@pytest.mark.parametrize('utc_deadline,local_deadline,refuses', [
    (105., 14., False), (103., 14., True), (105., 12., True),
])
def test_actual_envelope_separately_enforces_fixed_utc_and_monotonic_deadline(
        monkeypatch, utc_deadline, local_deadline, refuses):
    monkeypatch.setattr(stage.time, 'monotonic', lambda: 12.)
    typed = replace(envelope(), deadline_utc=utc_deadline,
        monotonic_deadline=local_deadline)
    material = SimpleNamespace(frame=SimpleNamespace(envelope=typed),
        clock_reading=SimpleNamespace(utc_upper_bound_seconds=101.,
            monotonic_after_seconds=10.))
    if refuses:
        with pytest.raises(ValueError, match='deadline expired'):
            stage._require_contact_deadline_v1(material)
    else:
        stage._require_contact_deadline_v1(material)
    assert typed.monotonic_deadline == local_deadline
