"""The registry binds D04 only when startup supplies an explicit scheme."""

import json
import unittest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme, FeelingState
from sylanne3.graph_types import AtomKey, GraphSnapshot, GraphWrite, Owner
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, NamespaceId,
    OperationIdentity, QueryEpoch, SourceQualification, VersionGuard,
    canonical_digest,
)
from sylanne3.graph_types import GraphVersion


def _scheme() -> AffectScheme:
    return AffectScheme(
        schema="d04.affect.scheme.v1",
        scheme_version="scheme:affect:1",
        operator_version="operator:affect:1",
        parameter_version="parameter:affect:1",
        coupling_version="coupling:affect:1",
        axes=(AffectAxis("care", "normalized", "care for another"),),
        parameter_bounds=(),
    )


def _typed_proposal(provider):
    key = AtomKey(Owner("persona", "bot", "persona"), "d04.feeling_state.v1", "affect:1")
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(
            "activity:affect:1", None, "attempt:1", "prepare", "operation:affect:1",
            canonical_digest({"input_refs": ["source:event:1"]}),
        ),
        AuthorityContext(
            "host:user", "d11", "capability:affect", namespace, ("persona",), "respond",
            ("entity:friend",), "policy:1", 1,
        ),
        VersionGuard(
            (GraphVersion(key, 0),), (QueryEpoch(namespace, "d04:affect", 0),), 0, 0,
            "catalogue:1", "scheme:affect:1", "operator:affect:1", "policy:1", (), (), (),
        ),
        SourceQualification(
            ("source:event:1",), "reported", 9.0, 10.0, "external_report", "eligible", 0.7,
            "not_applicable",
        ),
        ("source:event:1",), "budget:1", 20.0, 20.0, "clock:1", (),
    )
    feeling = FeelingState(
        process_id="affect:1", target_ref="entity:friend",
        basis_version="scheme:affect:1", operator_version="operator:affect:1",
        coordinates=(("care", 0.5),), meaning_refs=("meaning:1",),
        interpretation_refs=("interpretation:1",), active_driver_refs=("driver:1",),
        historical_source_refs=("source:event:1",),
        parameter_version="parameter:affect:1", coupling_version="coupling:affect:1",
        cursor=10.0,
    )
    return provider.proposal_for(
        envelope,
        typed_writes=(GraphWrite(key, json.loads(json.dumps(feeling.__dict__))),),
        dependencies=DependencySet(), contribution_keys=(), required_bundle_parts=(),
    )


class DomainRegistryAffectBindingTests(unittest.TestCase):
    def test_explicit_scheme_binds_real_d04_validator(self):
        scheme = _scheme()
        registry = discover_domain_registry(active_affect_scheme=scheme)
        self.assertNotIn("d04", registry.unavailable)
        provider = registry.registrations["d04"].provider
        proposal = _typed_proposal(provider)
        self.assertIs(provider.validate(proposal, snapshot=GraphSnapshot((), ())), proposal)

    def test_omitted_scheme_leaves_typed_writes_fail_closed(self):
        provider = discover_domain_registry().registrations["d04"].provider
        proposal = _typed_proposal(provider)
        with self.assertRaisesRegex(ValueError, "active D04 scheme"):
            provider.validate(proposal, snapshot=GraphSnapshot((), ()))

    def test_invalid_scheme_is_rejected_at_registry_boundary(self):
        with self.assertRaisesRegex(TypeError, "active_affect_scheme must be an AffectScheme"):
            discover_domain_registry(active_affect_scheme=object())
