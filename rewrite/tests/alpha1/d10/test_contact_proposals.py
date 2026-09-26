"""D10 contact proposals carry guarded graph writes, not approval proofs."""

from dataclasses import replace

import pytest

from sylanne3.domains.d10 import (
    ContactPolicy, LifeDomain, ProactiveOpportunity, contact_policy_key, opportunity_key,
)
from sylanne3.graph_types import (
    GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key,
)
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    SourceQualification, VersionGuard, canonical_digest,
)


NS = NamespaceId("bot", "persona")
SOURCE = source_key("bot", "persona", "source-one")
ACCESS = access_key("bot", "persona", "source-one")


def _envelope(inputs, versions):
    return CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-one", None, "attempt-one", "prepare", "operation-one",
                          canonical_digest({"input_refs": list(inputs)})),
        AuthorityContext("owner:user", "d10", "cap:d10", NS, ("persona",),
                         "context", ("user",), "policy:1", 1),
        VersionGuard(versions, (), 1, 0, "catalogue:1", "scheme:1", "operator:1",
                     "policy:1", (), (), ()),
        SourceQualification((SOURCE.token,), "reported", 1.0, 2.0,
                            "external_report", "qualified", 0.6, "not_applicable"),
        inputs, "budget:1", 10.0, 10.0, "clock:1", (),
    )


def test_policy_proposal_binds_approval_and_owner_grant_version():
    domain = LifeDomain()
    policy = ContactPolicy("policy:one", NS, 1, "user:one", "private", "ordinary",
                           True, False, 1, 0.0, 24.0)
    target = contact_policy_key(NS, policy.policy_id)
    envelope = _envelope((policy.policy_id, "approval:one"), (
        GraphVersion(target, 0), GraphVersion(owner_grant_key(*NS.as_tuple), 1)))
    proposal = domain.contact_policy_proposal(
        envelope, policy, approval_ref="approval:one",
        approval_authority_id="authority", installation_id="installation")
    assert proposal.typed_writes[0].key == target
    assert proposal.dependencies.current_invalidation == (
        GraphVersion(owner_grant_key(*NS.as_tuple), 1),)
    assert domain.validate(proposal) is proposal
    with pytest.raises(ValueError, match="approval"):
        domain.validate(replace(proposal, typed_writes=(replace(
            proposal.typed_writes[0], value=dict(
                proposal.typed_writes[0].value, approval_ref="unbound")),)))


def test_opportunity_proposal_requires_guarded_d06_source_and_access():
    domain = LifeDomain()
    opportunity = ProactiveOpportunity("opportunity:one", NS, SOURCE.token,
                                        "user:one", "private", "ordinary", 0.0, 10.0)
    target = opportunity_key(NS, opportunity.opportunity_id)
    envelope = _envelope((SOURCE.token, opportunity.opportunity_id), (
        GraphVersion(target, 0), GraphVersion(SOURCE, 2), GraphVersion(ACCESS, 3)))
    proposal = domain.proactive_opportunity_proposal(envelope, opportunity)
    assert proposal.typed_writes[0].dependencies == (SOURCE, ACCESS)
    assert proposal.dependencies.historical_provenance == (GraphVersion(SOURCE, 2),)
    snapshot = GraphSnapshot((GraphAtom(SOURCE, 2, {}), GraphAtom(ACCESS, 3, {})),
                             (NamespaceEpoch("bot", "persona", 5),))
    assert domain.validate(proposal, snapshot) is proposal
    with pytest.raises(ValueError, match="access absent"):
        domain.validate(proposal, replace(snapshot, atoms=snapshot.atoms[:1]))
    with pytest.raises(ValueError, match="guarded graph version"):
        domain.proactive_opportunity_proposal(
            replace(envelope, version_guard=replace(
                envelope.version_guard, read_versions=(GraphVersion(target, 0),
                                                       GraphVersion(SOURCE, 2)))),
            opportunity)
