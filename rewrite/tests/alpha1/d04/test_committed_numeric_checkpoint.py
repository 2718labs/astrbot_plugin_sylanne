"""The committed checkpoint has a separate, strict graph contract."""

from dataclasses import replace
import json

import pytest

from sylanne3.domains.d04 import (
    AffectProvider,
    CommittedRef,
    NumericCheckpoint,
    RootAssetBindings,
    RootBlockIdentity,
    decode_numeric_checkpoint,
    encode_numeric_checkpoint,
)
from sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DependencySet,
    NamespaceId,
    OperationIdentity,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    canonical_digest,
)


def _checkpoint(kind="feeling"):
    assets = RootAssetBindings(
        scheme_version="s1", operator_version="o1", parameter_version="p1",
        coupling_version="c1", readout_version="r1", scheme_sha256="a" * 64,
        operator_sha256="b" * 64, parameter_sha256="c" * 64,
        coupling_sha256="d" * 64, readout_sha256="e" * 64,
    )
    block = RootBlockIdentity(
        block_id="block:one", template_id="template:one", kind=kind,
        object_ref="person:one" if kind == "feeling" else None,
        meaning_ref="meaning:one" if kind == "feeling" else None,
        authored_source_id="authored:one",
    )
    graph_type = "d04.feeling_state.v1" if kind == "feeling" else "d04.mood_field.v1"
    graph_ref = AtomKey(Owner("persona", "bot:one", "alice"), graph_type, block.block_id).token
    return NumericCheckpoint(
        checkpoint_id="checkpoint:one", namespace=("bot:one", "alice"), block=block,
        assets=assets, asset_digest=assets.digest,
        axes=tuple(f"axis:{i:02d}" for i in range(24)),
        latent_state=(2.0,) * 24, certified_box=((1.9, 2.1),) * 24,
        numeric_error_bound=0.11, certificate_source="trusted_initial_box",
        certificate_digest="f" * 64, cursor=42.0,
        graph_state=CommittedRef(graph_ref, 1), readout_proof_digest="1" * 64,
        commit_operation_id="operation:adopt:one",
        predecessor_kind="none", predecessor_receipt_digest=None,
    )


@pytest.mark.parametrize("kind", ["feeling", "mood"])
def test_root_round_trip_preserves_order_and_graph_version(kind):
    checkpoint = _checkpoint(kind)
    wire = json.loads(json.dumps(encode_numeric_checkpoint(checkpoint)))
    assert decode_numeric_checkpoint(wire) == checkpoint
    assert wire["schema"] == "d04.numeric_checkpoint.v1"
    assert len(wire["axes"]) == len(wire["latent_state"]) == 24
    assert wire["graph_state"]["revision"] == 1
    assert wire["commit_operation_id"] == "operation:adopt:one"
    assert "commit_receipt_digest" not in wire
    assert "author_id" not in wire


def test_successor_requires_predecessor_receipt_and_abi2_source():
    root = _checkpoint()
    successor = replace(root, certificate_source="trusted_abi2",
                        predecessor_kind="root", predecessor_receipt_digest="2" * 64)
    assert decode_numeric_checkpoint(encode_numeric_checkpoint(successor)) == successor
    with pytest.raises(ValueError, match="predecessor_receipt_digest"):
        replace(successor, predecessor_receipt_digest=None)
    with pytest.raises(ValueError, match="trusted_abi2"):
        replace(root, predecessor_kind="root", predecessor_receipt_digest="2" * 64)
    with pytest.raises(ValueError, match="initial box"):
        replace(root, certificate_source="trusted_abi2")


def test_malformed_shapes_error_certificate_and_graph_mismatch_rejected():
    root = _checkpoint()
    with pytest.raises(ValueError, match="asset_digest"):
        replace(root, asset_digest="0" * 64)
    with pytest.raises(ValueError, match="numeric_error_bound"):
        replace(root, numeric_error_bound=0.01)
    with pytest.raises(ValueError, match="certified_box"):
        replace(root, certified_box=((2.1, 1.9),) + root.certified_box[1:])
    with pytest.raises(ValueError, match="latent_state"):
        replace(root, latent_state=(True,) + root.latent_state[1:])
    with pytest.raises(ValueError, match="graph_state"):
        other = AtomKey(Owner("persona", "bot:one", "bob"), "d04.feeling_state.v1", "block:one")
        replace(root, graph_state=CommittedRef(other.token, 1))
    with pytest.raises(ValueError, match="graph_state"):
        mood = AtomKey(Owner("persona", "bot:one", "alice"), "d04.mood_field.v1", "block:one")
        replace(root, graph_state=CommittedRef(mood.token, 1))
    with pytest.raises(ValueError, match="certificate_source"):
        replace(root, certificate_source="author_declared_box")


def test_codec_rejects_extra_nested_and_incompatible_candidate_fields():
    root = _checkpoint()
    wire = encode_numeric_checkpoint(root)
    wire["status"] = "candidate"
    with pytest.raises(ValueError, match="fields"):
        decode_numeric_checkpoint(wire)
    wire = encode_numeric_checkpoint(root)
    wire["graph_state"]["extra"] = True
    with pytest.raises(ValueError, match="fields"):
        decode_numeric_checkpoint(wire)
    wire = encode_numeric_checkpoint(root)
    wire["axes"][1] = wire["axes"][0]
    with pytest.raises(ValueError, match="axes"):
        decode_numeric_checkpoint(wire)
    wire = encode_numeric_checkpoint(root)
    wire["schema"] = "d04.root_numeric_checkpoint_candidate.v1"
    with pytest.raises(ValueError, match="schema"):
        decode_numeric_checkpoint(wire)


def test_regular_d04_proposal_cannot_write_committed_checkpoint():
    checkpoint = _checkpoint()
    key = AtomKey(Owner("persona", "bot:one", "alice"), "d04.numeric_checkpoint.v1", "block:one")
    namespace = NamespaceId("bot:one", "alice")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity("activity:one", None, "attempt:one", "prepare", "operation:one",
                          canonical_digest({"input_refs": ["source:one"]})),
        AuthorityContext("host:user", "d11", "capability:affect", namespace, ("persona",),
                         "respond", ("person:one",), "policy:1", 1),
        VersionGuard((GraphVersion(key, 0),), (QueryEpoch(namespace, "d04:affect", 0),),
                     0, 0, "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), ()),
        SourceQualification(("source:one",), "reported", 9.0, 10.0,
                            "external_report", "eligible", 0.7, "not_applicable"),
        ("source:one",), "budget:1", 20.0, 20.0, "clock:1", (),
    )
    provider = AffectProvider()
    proposal = provider.proposal_for(
        envelope, typed_writes=(GraphWrite(key, encode_numeric_checkpoint(checkpoint)),),
        dependencies=DependencySet(), contribution_keys=(), required_bundle_parts=(),
    )
    with pytest.raises(ValueError, match="D11 adoption path"):
        provider.validate(proposal)
