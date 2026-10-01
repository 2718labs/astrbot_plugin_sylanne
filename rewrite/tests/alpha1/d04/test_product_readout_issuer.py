"""The D04 issuer needs an installed package and a W01-owned current read."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from sylanne3.domains.d04 import (
    D04CurrentProductReadFrameV1, D04ProductReadoutIssuer,
    D04ReadoutHold, D04VerifiedNumericAdoptionV1,
)
from sylanne3.host.affect_scheme_asset import VerifiedAffectScheme
from sylanne3.native_runtime.loader import NativeLoadBinding
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId

from .test_product_readout_candidate import _case


class _CurrentReadPort:
    def __init__(self, frame):
        self.frame = frame

    def with_current_d04_product_readout_v1(
        self, authority, lease, *, checkpoint_ref, audience, purpose, project,
    ):
        assert lease is self
        assert checkpoint_ref == self.frame.checkpoint_ref
        assert authority.namespace == self.frame.source_read.namespace
        return project(self.frame)


def _installed_issuer(monkeypatch):
    checkpoint, checkpoint_ref, source_ref, scheme, asset, _, read = _case()
    binding = NativeLoadBinding("b" * 64, "c" * 64, "windows", "x86_64", None, 2)
    handle = SimpleNamespace(
        production_binding=binding,
        capabilities=SimpleNamespace(supports_fixed_block_interval_math_v1=True),
    )
    monkeypatch.setattr(
        "sylanne3.domains.d04.product_issuer.load_production_native",
        lambda *args, **kwargs: handle,
    )
    monkeypatch.setattr(
        "sylanne3.host.affect_scheme_asset.load_verified_affect_scheme",
        lambda *args, **kwargs: VerifiedAffectScheme(
            scheme, None, checkpoint.assets.scheme_sha256, binding.manifest_sha256,
        ),
    )
    adoption = D04VerifiedNumericAdoptionV1(
        checkpoint_ref, 3, checkpoint.commit_operation_id, "2" * 64,
        checkpoint.certificate_source, checkpoint.certificate_digest,
        checkpoint.asset_digest, checkpoint.numeric_error_bound,
        binding.manifest_sha256, binding.native_sha256,
        D04ProductReadoutIssuer._closure_digest(read),
    )
    frame = D04CurrentProductReadFrameV1(
        checkpoint, checkpoint_ref, 3, source_ref, read, scheme, adoption,
        "incarnation:one", 11, 0, 0,
    )
    port = _CurrentReadPort(frame)
    issuer = D04ProductReadoutIssuer(
        read_port=port, package_root=Path.cwd(),
        expected_manifest_sha256=binding.manifest_sha256,
        expected_readout_id=asset.readout_id,
    )
    monkeypatch.setattr(issuer, "_asset", lambda _: asset)
    authority = AuthorityContext(
        "host:user", "d04", "capability", NamespaceId("bot:one", "alice"),
        ("persona",), "context", ("entity:alice",), "policy", 3,
    )
    return issuer, port, authority, checkpoint_ref


def test_constructor_holds_without_w01_port_or_formal_package():
    with pytest.raises(D04ReadoutHold, match="W01 current"):
        D04ProductReadoutIssuer(
            read_port=object(), package_root=Path.cwd(),
            expected_manifest_sha256="0" * 64, expected_readout_id="readout:one",
        )
    with pytest.raises(D04ReadoutHold, match="formal ABI2 package"):
        D04ProductReadoutIssuer(
            read_port=_CurrentReadPort(None), package_root=Path.cwd(),
            expected_manifest_sha256="0" * 64, expected_readout_id="readout:one",
        )


def test_issuer_seals_mixed_affect_only_at_current_w01_fence(monkeypatch):
    # The stand-in port/package exercise the D04 contract; they do not qualify
    # this checkout or substitute for W01's production graph enumeration.
    issuer, port, authority, checkpoint_ref = _installed_issuer(monkeypatch)
    receipt = issuer.issue_current(
        authority, port, checkpoint_ref=checkpoint_ref,
        audience=("entity:alice",), purpose="context",
    )
    assert receipt.status == "d04_readout_issued_at_current_fence"
    assert receipt.readout.status == "hold_for_d11_product_admission"
    tendencies = {item.tendency for item in receipt.readout.tendencies
                  if item.lower > 0}
    assert {"care", "protect_boundary"} <= tendencies
    assert issuer.verify_current(receipt, authority, port)
    assert not issuer.verify_current(replace(receipt, issuer_seal="0" * 64), authority, port)
    assert not issuer.verify_current(replace(receipt, readout=object()), authority, port)
    port.frame = replace(port.frame, delete_epoch=1)
    assert not issuer.verify_current(receipt, authority, port)


def test_issuer_rejects_adoption_and_closure_mismatch(monkeypatch):
    issuer, port, authority, checkpoint_ref = _installed_issuer(monkeypatch)
    with pytest.raises(D04ReadoutHold, match="verified ABI2 adoption"):
        issuer.issue_current(replace(authority, activation_generation=4), port,
                             checkpoint_ref=checkpoint_ref,
                             audience=("entity:alice",), purpose="context")
    adoption = replace(port.frame.adoption, certificate_digest="0" * 64)
    port.frame = replace(port.frame, adoption=adoption)
    with pytest.raises(D04ReadoutHold, match="verified ABI2 adoption"):
        issuer.issue_current(authority, port, checkpoint_ref=checkpoint_ref,
                             audience=("entity:alice",), purpose="context")
    port.frame = replace(port.frame, adoption=replace(
        adoption, certificate_digest=port.frame.checkpoint.certificate_digest,
        graph_closure_digest="0" * 64,
    ))
    with pytest.raises(D04ReadoutHold, match="verified ABI2 adoption"):
        issuer.issue_current(authority, port, checkpoint_ref=checkpoint_ref,
                             audience=("entity:alice",), purpose="context")


def test_current_issuer_rechecks_correction_and_deleted_source(monkeypatch):
    issuer, port, authority, checkpoint_ref = _installed_issuer(monkeypatch)
    receipt = issuer.issue_current(
        authority, port, checkpoint_ref=checkpoint_ref,
        audience=("entity:alice",), purpose="context",
    )
    original = port.frame

    def install_atoms(atoms):
        read = replace(original.source_read, snapshot=replace(
            original.source_read.snapshot, atoms=atoms,
        ))
        port.frame = replace(
            original, source_read=read,
            adoption=replace(original.adoption,
                             graph_closure_digest=issuer._closure_digest(read)),
        )

    atoms = list(original.source_read.snapshot.atoms)
    atoms[2] = replace(atoms[2], revision=1, valid=True)
    install_atoms(tuple(atoms))
    with pytest.raises(D04ReadoutHold, match="corrected"):
        issuer.issue_current(authority, port, checkpoint_ref=checkpoint_ref,
                             audience=("entity:alice",), purpose="context")
    assert not issuer.verify_current(receipt, authority, port)

    atoms = list(original.source_read.snapshot.atoms)
    atoms[0] = replace(atoms[0], revision=2, valid=False, value={})
    install_atoms(tuple(atoms))
    with pytest.raises(D04ReadoutHold, match="source closure"):
        issuer.issue_current(authority, port, checkpoint_ref=checkpoint_ref,
                             audience=("entity:alice",), purpose="context")
    assert not issuer.verify_current(receipt, authority, port)


def test_current_issuer_holds_when_feeling_value_diverges_from_numeric_certificate(monkeypatch):
    issuer, port, authority, checkpoint_ref = _installed_issuer(monkeypatch)
    original = port.frame
    atoms = list(original.source_read.snapshot.atoms)
    feeling = dict(atoms[4].value)
    coordinates = [list(item) for item in feeling["coordinates"]]
    coordinates[6][1] = 0.1
    atoms[4] = replace(atoms[4], value={**feeling, "coordinates": coordinates})
    read = replace(original.source_read, snapshot=replace(
        original.source_read.snapshot, atoms=tuple(atoms),
    ))
    # A caller can recompute this digest; it cannot make the two graph states agree.
    port.frame = replace(original, source_read=read, adoption=replace(
        original.adoption, graph_closure_digest=issuer._closure_digest(read),
    ))
    with pytest.raises(D04ReadoutHold, match="24D coordinates differ"):
        issuer.issue_current(authority, port, checkpoint_ref=checkpoint_ref,
                             audience=("entity:alice",), purpose="context")
