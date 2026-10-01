import json
from dataclasses import asdict, replace

from sylanne3.domains.d10 import (
    ContactClaim, ContactContinuation, ContactPolicy, ProactiveOpportunity,
    contact_policy_graph_write, proactive_opportunity_graph_write,
)
from sylanne3.domains.d10.current_contact import project_current_contact_v1
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch


NS = NamespaceId("bot", "persona")
SOURCE = source_key(*NS.as_tuple, "one")
ACCESS = access_key(*NS.as_tuple, "one")
POLICY = ContactPolicy("policy:one", NS, 1, "user:one", "private", "ordinary",
                       True, False, 1, 0.0, 20.0)
OPPORTUNITY = ProactiveOpportunity("opportunity:one", NS, SOURCE.token,
                                   "user:one", "private", "ordinary", 0.0, 10.0)


def snapshot(*, policy=POLICY, claim=None):
    source = SourceRecord("one", "milestone", "user:one", "reported", "reported",
                          1.0, 1.0, "family:one", ("user:one",),
                          ("context", "expression"), ())
    pwrite = contact_policy_graph_write(
        policy, owner_grant_revision=1, approval_ref="approval:one",
        approval_authority_id="authority", installation_id="installation")
    owrite = proactive_opportunity_graph_write(
        OPPORTUNITY, source_revision=1, access_revision=1)
    atoms = [
        GraphAtom(pwrite.key, policy.version, pwrite.value),
        GraphAtom(owrite.key, 1, owrite.value),
        GraphAtom(SOURCE, 1, source.to_dict()),
        GraphAtom(ACCESS, 1, {"source_id": "one", "audiences": ["user:one"],
                              "purposes": ["context", "expression"],
                              "status": "active", "recorded_at": 1.0}),
    ]
    if claim is not None:
        key = AtomKey(Owner("persona", *NS.as_tuple), "d10.contact_claim.v1",
                      claim.contact_id)
        atoms.append(GraphAtom(key, 1, asdict(claim) | {
            "segment_effects": list(claim.segment_effects),
            "observations": [list(pair) for pair in claim.observations]}))
    # Simulate persisted canonical JSON and a fresh process's decoded read.
    restored = tuple(GraphAtom(atom.key, atom.revision,
                               json.loads(json.dumps(atom.value))) for atom in atoms)
    return GraphSnapshot(restored, (NamespaceEpoch(*NS.as_tuple, 7),))


def project(graph, continuation=None):
    return project_current_contact_v1(
        graph, QueryEpoch(NS, "all", 7), namespace=NS,
        policy_id=POLICY.policy_id, opportunity_id=OPPORTUNITY.opportunity_id,
        now=2.0, continuation=continuation)


def test_current_graph_candidate_reads_policy_source_and_negative_claim_scope():
    result = project(snapshot())
    assert result.status == "policy_candidate"
    assert result.check.result == "pass"
    assert result.query_epoch == QueryEpoch(NS, "all", 7)
    assert {v.key.type_name for v in result.read_versions} == {
        "d10.contact_policy.v1", "d10.proactive_opportunity.v1",
        "memory.source", "memory.access",
    }
    assert "d10.contact_claim:subject_channel_category:all_valid" in result.negative_predicates


def test_restart_unknown_blocks_remaining_segment_and_new_contact():
    claim = ContactClaim("contact:one", "action:one", "user:one", "private",
                         "ordinary", ("effect:first", "effect:second"),
                         (("effect:first", "unknown"),), "pending_confirmation",
                         POLICY.policy_id, 1)
    restored = snapshot(claim=claim)
    continuation = ContactContinuation("contact:one", "action:one", "effect:second")
    later = project(restored, continuation)
    assert later.status == "hold"
    assert "prior_segment_unknown" in later.reasons
    assert project(restored).status == "hold"
    assert "no_response_gate" in project(restored).reasons
    assert any(v.key.type_name == "d10.contact_claim.v1" for v in later.read_versions)


def test_current_quiet_and_stale_source_hold():
    assert "quiet_hours" in project(snapshot(policy=replace(POLICY, quiet=True))).reasons
    graph = snapshot()
    stale_access = tuple(replace(atom, revision=2) if atom.key == ACCESS else atom
                         for atom in graph.atoms)
    assert project(replace(graph, atoms=stale_access)).reasons == (
        "opportunity_source_changed",)
