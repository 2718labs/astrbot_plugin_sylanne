"""Source-gated engineering choices and explicit D04 parameter switch holds."""

from __future__ import annotations

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from sylanne3.domains.d01 import PersonaBlock, PersonaDomain, PersonaPlan
from sylanne3.domains.d02 import BodyState
from sylanne3.domains.d04 import AppraisalBundle, MeaningFacet
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
    owner_grant_key,
)
from sylanne3.native_runtime.d04_parameter_scheme import (
    POSITIVE_RATE_FLOOR, REGISTERED_RECOVERY_SCHEMES,
    propose_d04_parameter_switch, select_d04_recovery_scheme,
)
from sylanne3.runtime_contracts import NamespaceId


NAMESPACE = NamespaceId("bot", "persona")
RESOURCE_KEY = AtomKey(Owner("persona", "bot", "persona"), "d02.body_state.v1", "body")
MEANING_KEY = AtomKey(Owner("event", "bot", "persona", "event-1"),
                      "d04.appraisal_bundle.v1", "appraisal")


def _guard() -> OwnerAuthorizationGuardV1:
    return OwnerAuthorizationGuardV1(
        "authority", "installation", NAMESPACE, 1, "sha256:" + "b" * 64, 0, 0,
    )


def _grant() -> GraphAtom:
    return GraphAtom(owner_grant_key("bot", "persona"), 1, {
        "schema": "sylanne3.graph.owner_grant.v1",
        "authority_id": "authority", "installation_id": "installation",
        "grant_id": "grant", "principal": {
            "identity_provider": "local", "account_ref": "account",
            "account_incarnation": "incarnation",
        },
        "ticket_id": "ticket", "creation_operation_id": "create",
        "creation_digest": "sha256:" + "a" * 64,
        "issue_operation_id": "issue", "grant_revision": 1,
        "state": "pending_authority", "scope": "bot/persona",
        "issuer_ref": "authority:installation",
        "capabilities": ["workbench.read"], "purposes": ["workbench_view"],
        "audiences": ["owner"], "activation_generation": 1,
        "graph_incarnation": "graph-one",
    })


def _sources(*, strategy: str = "adaptive", energy: float = 0.8,
             controllability: float | None = 0.8) -> tuple[GraphSnapshot, tuple[GraphVersion, ...]]:
    plan = PersonaPlan(
        "chosen", NAMESPACE, 1,
        (PersonaBlock("identity", "semantic_identity", "authored", "read_only"),
         PersonaBlock(f"d04.recovery.{strategy}.v1", "strategy", "author choice", "authored_only")),
        (), True,
    )
    grant = _grant()
    plan_write = PersonaDomain.plan_write(plan)
    activation_write = PersonaDomain.activation_write(plan, grant, _guard())
    resource = BodyState("body", 1, energy, {"work": 0.1}, 0.1, 0.0)
    unknown = ("controllability",) if controllability is None else ()
    facet = MeaningFacet(
        "facet-1", "target", "interpretation", "value", "uncertain",
        controllability, 0.6, None, None, 0.9, unknown, ("source",),
    )
    appraisal = AppraisalBundle(
        "appraisal", "event", "target", (facet,), ("interpretation",),
        ("source",), "observed", "external_observation", "contribution", 0.0,
    )
    atoms = (
        grant,
        GraphAtom(plan_write.key, 1, plan_write.value),
        GraphAtom(activation_write.key, 1, activation_write.value),
        GraphAtom(RESOURCE_KEY, 1, asdict(resource)),
        GraphAtom(MEANING_KEY, 1, json.loads(json.dumps(asdict(appraisal)))),
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 3),))
    reads = tuple(GraphVersion(atom.key, atom.revision) for atom in atoms)
    return snapshot, reads


def _select(snapshot: GraphSnapshot, reads: tuple[GraphVersion, ...], **changes):
    args = dict(
        namespace=NAMESPACE, current_guard=_guard(), read_versions=reads,
        resource_ref=RESOURCE_KEY.token, meaning_ref=MEANING_KEY.token,
        meaning_facet_id="facet-1",
    )
    args.update(changes)
    return select_d04_recovery_scheme(snapshot, **args)


def test_source_conditioned_registry_and_explicit_switch_hold() -> None:
    assert len(REGISTERED_RECOVERY_SCHEMES) == 8
    assert all(POSITIVE_RATE_FLOOR <= rate <= 1.0
               for scheme in REGISTERED_RECOVERY_SCHEMES.values()
               for rate in scheme.rates_24d)
    baseline_snapshot, baseline_reads = _sources()
    baseline = _select(baseline_snapshot, baseline_reads)
    altered_snapshot, altered_reads = _sources(
        strategy="persistent", energy=0.2, controllability=0.2,
    )
    altered = _select(altered_snapshot, altered_reads)
    assert baseline.status == altered.status == "conditional_candidate"
    assert baseline.scheme.scheme_id == "adaptive:available:controllable"
    assert altered.scheme.scheme_id == "persistent:depleted:low_control"
    assert baseline.scheme.rates_24d != altered.scheme.rates_24d
    assert len(altered.source_versions) == 5 and altered.graph_epoch == 3

    switch = propose_d04_parameter_switch(
        switch_id="switch-1", previous_scheme_id=baseline.scheme.scheme_id,
        selection=altered, effective_role_time=12.0,
    )
    assert switch.previous_parameter_version == baseline.scheme.parameter_version
    assert switch.proposed_parameter_version == altered.scheme.parameter_version
    assert switch.source_versions == altered.source_versions
    assert switch.state_mapping is None and switch.energy_delta is None
    assert switch.status == "HOLD_REQUIRES_STATE_MAP_AND_ENERGY_LEDGER"
    with pytest.raises(ValueError, match="distinct"):
        propose_d04_parameter_switch(
            switch_id="no-change", previous_scheme_id=altered.scheme.scheme_id,
            selection=altered, effective_role_time=12.0,
        )


def test_absent_or_untrusted_sources_hold_instead_of_defaulting() -> None:
    snapshot, reads = _sources()
    assert _select(snapshot, reads, meaning_ref=None).status == "HOLD"
    assert _select(snapshot, reads[:-1]).hold_reason == "source_not_version_guarded"
    assert _select(snapshot, reads, current_guard=replace(
        _guard(), pending_revoke_operation_id="revoke",
    )).status == "HOLD"
    unknown_snapshot, unknown_reads = _sources(controllability=None)
    assert _select(unknown_snapshot, unknown_reads).hold_reason == (
        "meaning_facet_missing_or_unknown"
    )
    unregistered_snapshot, unregistered_reads = _sources(strategy="unregistered")
    assert _select(unregistered_snapshot, unregistered_reads).hold_reason == (
        "registered_persona_strategy_missing_or_ambiguous"
    )
