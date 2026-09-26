"""C02 frozen bundle codec accepts only the known canonical DTO tree."""

import json
from dataclasses import replace

import pytest

from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from sylanne3.runtime.c02_bundle_codec import (
    c02_bundle_from_wire, c02_bundle_to_wire,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, DependencySet, DomainBundle,
    DomainProposal, NamespaceId, OperationIdentity, QueryEpoch,
    SourceQualification, VersionGuard, canonical_digest, canonical_serialize,
)


def _bundle() -> DomainBundle:
    namespace = NamespaceId("bot-a", "persona-a")
    source_key = AtomKey(Owner("persona", "bot-a", "persona-a"),
                         "memory.source.v1", "source-a")
    input_refs = (source_key.token,)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity-a", None, "first-ingress-c02",
                          "first_ingress_c02", "c02-operation-a",
                          canonical_digest({"input_refs": list(input_refs)})),
        AuthorityContext("worker-a", "d06", "capability-a", namespace,
                         ("persona",), "consolidation", ("self",),
                         "provider-policy-a", 1, 2),
        VersionGuard((GraphVersion(source_key, 3),),
                     (QueryEpoch(namespace, "all", 4),), 1, 0,
                     "catalogue-a", "scheme-a", "operator-a", "policy-a",
                     (), (), ()),
        SourceQualification(input_refs, "observed", 1.0, 2.0,
                            "external_observation", "eligible", None, "actual"),
        input_refs, "budget-a", 100.0, 200.0, "character-a", ("origin-a",))
    d06_key = AtomKey(Owner("persona", "bot-a", "persona-a"),
                      "memory.episode.v1", "episode-a")
    d11_key = AtomKey(Owner("persona", "bot-a", "persona-a"),
                      "runtime.job", "job-a")
    d06 = DomainProposal(
        "d06", "d06.proposal.v1", "a" * 64, envelope,
        (GraphWrite(d06_key, {"episode_id": "episode-a",
                              "$type": "ordinary user data",
                              "nested": {"$type": "not a DTO"}}, (source_key,)),),
        DependencySet((GraphVersion(source_key, 3),), (), (), ()), (), ())
    d11 = DomainProposal(
        "d11", "d11.proposal.v1", "b" * 64, envelope,
        (GraphWrite(d11_key, {"job_id": "job-a", "phase": "completed"}),),
        DependencySet(), (), ())
    return DomainBundle(envelope, (d06, d11), (), (), (), (), (), (), ())


def test_c02_bundle_roundtrip_retains_original_canonical_bytes_and_digest():
    bundle = _bundle()
    text = c02_bundle_to_wire(bundle)
    recovered = c02_bundle_from_wire(text)
    assert text == canonical_serialize(bundle)
    assert recovered == bundle
    assert recovered.digest == bundle.digest
    assert c02_bundle_to_wire(recovered) == text
    assert recovered.proposals[0].typed_writes[0].value["$type"] == "ordinary user data"


@pytest.mark.parametrize("change", [
    lambda raw: raw.update(extra="unapproved"),
    lambda raw: raw["envelope"].update({"$type": "builtins.eval"}),
    lambda raw: raw["envelope"]["identity"].update({"phase": "other"}),
    lambda raw: raw["proposals"][0]["typed_writes"][0]["key"].update(
        {"$type": "other.AtomKey"}),
    lambda raw: raw["proposals"][0]["typed_writes"][0].update(
        {"dependencies": "not-a-list"}),
])
def test_c02_bundle_rejects_changed_fields_types_and_scope(change):
    raw = json.loads(c02_bundle_to_wire(_bundle()))
    change(raw)
    with pytest.raises((TypeError, ValueError)):
        c02_bundle_from_wire(json.dumps(
            raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def test_c02_bundle_rejects_noncanonical_text_and_other_bundle_shapes():
    bundle = _bundle()
    text = c02_bundle_to_wire(bundle)
    with pytest.raises(ValueError, match="noncanonical"):
        c02_bundle_from_wire(text + " ")
    with pytest.raises(TypeError):
        c02_bundle_from_wire(json.loads(text))
    with pytest.raises(ValueError):
        c02_bundle_to_wire(replace(bundle, choice_refs=("choice-a",)))
    with pytest.raises(ValueError):
        c02_bundle_to_wire(replace(bundle, proposals=bundle.proposals[:1]))
