"""D04 issuer boundary; the positive reader below is a labeled trusted stub."""

from dataclasses import fields, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.domains.d04.encoding_baseline_v2 import (
    ExactGraphRefV2, ProjectionNumericErrorV2,
)
from sylanne3.domains.d04.projection_issuer_v2 import (
    D04CurrentProjectionReadFrameV2, D04InstalledProjectionIssuerV2,
    D04ProjectionIssuerHold, D04VerifiedJointProjectionOriginalV2,
)
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch, Owner,
)
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import AuthorityContext, FenceScope, canonical_digest

from .test_interval_projection_v2 import _case, _selection


class _LabeledTrustedW01Stub:
    """Exercises the callback contract; it is not an Authority verifier."""

    def __init__(self, frame):
        self.frame = frame

    def with_current_d04_encoding_projection_v2(
        self, authority, lease, *, baseline_id, source_ref, audience, purpose,
        project,
    ):
        assert lease is self
        assert authority.namespace == self.frame.namespace
        assert baseline_id == self.frame.baseline_id
        assert source_ref == self.frame.source_ref
        assert audience == ("entity:alice",)
        assert purpose == "context"
        return project(self.frame)


def _trusted_stub_case():
    receipt, asset, policy = _case()
    namespace = receipt.namespace
    source = source_key(*namespace.as_tuple, "source:one")
    access = access_key(*namespace.as_tuple, "source:one")
    correction = source_correction_head_key(namespace, "source:one")
    identity = {field.name: getattr(receipt, field.name) for field in fields(receipt)
                if field.name not in {"receipt_digest", "status"}}
    identity["source_versions"] = ((
        "drive:one", 1, source.token, 1, access.token, 1, "family:one",
    ),)
    receipt = replace(receipt, source_versions=identity["source_versions"],
                      receipt_digest=canonical_digest(identity))
    selected = _selection(receipt, 2)
    feelings = tuple(ExactGraphRefV2(item.key.token, item.revision)
                     for item in selected["then_feeling_versions"])
    perspective = ExactGraphRefV2(AtomKey(
        Owner("persona", *namespace.as_tuple), "d03.self_perspective.v1",
        "current",
    ).token, 1)
    source_record = SourceRecord(
        "source:one", "evidence", "speaker", "reported", "reported",
        1.0, 2.0, "family:one", ("entity:alice",), ("context",), (),
    )
    atoms = (
        GraphAtom(source, 1, source_record.to_dict()),
        GraphAtom(access, 1, {
            "source_id": "source:one", "audiences": ["entity:alice"],
            "purposes": ["context"], "status": "active", "recorded_at": 2.0,
        }),
        GraphAtom(correction, 0, {}, False),
        GraphAtom(perspective.key, perspective.revision, {}),
        *(GraphAtom(item.key, item.revision, {}) for item in feelings),
    )
    current_epoch = NamespaceEpoch(*namespace.as_tuple, 9)
    anchor = RestoreAnchor(
        authority_id="authority", namespace="authority-namespace",
        activation_generation=3, deletion_journal_id="deletion",
        deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution", execution_seq=0,
        execution_digest="genesis", revocation_epoch=0, proof="opaque-proof",
    )
    permit = FencePermitV2(
        authority_id=anchor.authority_id, namespace=anchor.namespace,
        subject="subject", holder="holder", generation=3, operation="read",
        operation_id="read-1", token="t" * 32, fence_epoch=9, revision=2,
        pinned_anchor=anchor,
    )
    fence = FenceScope(namespace, anchor.namespace, 3, "read", "read-1",
                       permit, anchor, current_epoch, 11)
    original = D04VerifiedJointProjectionOriginalV2(
        "joint-original:one", 1, receipt, "joint-operation:one", "1" * 64,
        ProjectionNumericErrorV2(0.01, 0.02, 0.03, 0.04, "2" * 64),
    )
    frame = D04CurrentProjectionReadFrameV2(
        namespace=namespace, baseline_id="baseline:one", source_ref=source.token,
        source_versions=(ExactGraphRefV2(source.token, 1),),
        source_access_correction_versions=(GraphVersion(access, 1),
                                           GraphVersion(correction, 0)),
        perspective_version=perspective, interpretation_versions=(),
        then_feeling_versions=feelings,
        member_bindings=selected["member_bindings"], as_known_at=2.0,
        snapshot=GraphSnapshot(atoms, (current_epoch,)), fence=fence,
        joint_original=original, graph_incarnation=receipt.graph_incarnation,
        graph_revision=11, access_epoch=7, delete_epoch=6,
    )
    port = _LabeledTrustedW01Stub(frame)
    # Deliberately bypass installation for the trusted-reader contract test.
    # The constructor is checked separately and no production port exists.
    issuer = object.__new__(D04InstalledProjectionIssuerV2)
    issuer._read_port = port
    issuer._asset = asset
    issuer._policy = policy
    issuer._manifest_sha256 = receipt.native_manifest_sha256
    authority = AuthorityContext(
        "host:user", "d04", "capability", namespace, ("persona",),
        "context", ("entity:alice",), "policy", 3,
    )
    return issuer, port, authority


def test_missing_w01_current_reader_fails_closed(tmp_path: Path):
    with pytest.raises(D04ProjectionIssuerHold, match="W01 current"):
        D04InstalledProjectionIssuerV2(
            read_port=object(), package_root=tmp_path,
            expected_manifest_sha256="a" * 64,
        )


def test_uninstalled_candidate_package_fails_closed(tmp_path: Path):
    with pytest.raises(D04ProjectionIssuerHold, match="verified formal"):
        D04InstalledProjectionIssuerV2(
            read_port=_LabeledTrustedW01Stub(None), package_root=tmp_path,
            expected_manifest_sha256="a" * 64,
        )


def test_pinned_candidate_policy_is_not_an_installed_policy(tmp_path: Path,
                                                             monkeypatch):
    monkeypatch.setattr(
        "sylanne3.domains.d04.projection_issuer_v2.verify_installed_package",
        lambda *args, **kwargs: SimpleNamespace(
            verified=True, build_mode="formal-alpha1",
        ),
    )
    binding = {
        "path": "resources/catalogue/d04-interval-projection-policy.v2.json",
        "sha256": "a" * 64, "bytes": 1,
        "policy_id": "policy:one", "version": "d04.interval-projection.v2",
        "stage_contract": "encoding_baseline_then_recollection_current_mood",
        "semantic_calibration": "unvalidated", "status": "candidate",
    }
    raw = json.dumps({"interval_projection_policy": binding}).encode()
    (tmp_path / "release-manifest.json").write_bytes(raw)
    with pytest.raises(D04ProjectionIssuerHold, match="installed projection"):
        D04InstalledProjectionIssuerV2(
            read_port=_LabeledTrustedW01Stub(None), package_root=tmp_path,
            expected_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        )


def test_trusted_stub_accepts_prewrite_numeric_stamp_and_returns_unsigned_current_cas():
    issuer, port, authority = _trusted_stub_case()
    proposal = issuer.issue_current(
        authority, port, baseline_id="baseline:one",
        source_ref=port.frame.source_ref, audience=("entity:alice",),
        purpose="context",
    )
    assert proposal.status == "unsigned_hold_for_w01_atomic_baseline_cas"
    assert proposal.projection.graph_revision == 8  # immutable prewrite input
    assert proposal.graph_revision == 11  # current CAS comparison target
    assert proposal.baseline.projection_receipt.graph_epoch == 7
    assert proposal.graph_epoch == 9
    assert proposal.baseline.semantic_calibration == "unvalidated"
    assert issuer.verify_current(proposal, authority, port,
                                 audience=("entity:alice",), purpose="context")


def test_trusted_stub_rejects_stale_current_access_and_changed_original():
    issuer, port, authority = _trusted_stub_case()
    request = dict(baseline_id="baseline:one", source_ref=port.frame.source_ref,
                   audience=("entity:alice",), purpose="context")
    access = access_key(*authority.namespace.as_tuple, "source:one")
    port.frame = replace(port.frame, snapshot=replace(
        port.frame.snapshot, atoms=tuple(
            replace(atom, revision=2) if atom.key == access else atom
            for atom in port.frame.snapshot.atoms
        ),
    ))
    with pytest.raises(D04ProjectionIssuerHold, match="source/access/correction"):
        issuer.issue_current(authority, port, **request)
    issuer, port, authority = _trusted_stub_case()
    port.frame = replace(port.frame, joint_original=replace(
        port.frame.joint_original,
        receipt=replace(port.frame.joint_original.receipt,
                        native_manifest_sha256="0" * 64),
    ))
    with pytest.raises(D04ProjectionIssuerHold, match="joint original"):
        issuer.issue_current(authority, port, **request)
