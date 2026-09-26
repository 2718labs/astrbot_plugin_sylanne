"""D04 numeric inputs come from current graph rows; readout remains unavailable."""

from dataclasses import replace
import json

import pytest

from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, SCHEME_VERSION
from sylanne3.domains.d04 import AffectProvider
from sylanne3.domains.d04.numeric_drive import (
    SourcedNumericDrive, numeric_drive_id, sourced_numeric_drive_write,
)
from sylanne3.memory_types import access_key
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch
from sylanne3.runtime.current_numeric_sources import read_current_d04_numeric_sources
from sylanne3.runtime.authoritative_coupling_snapshot import CouplingSnapshotHold
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, OperationIdentity, SourceQualification,
    VersionGuard, canonical_digest,
)

from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import (
    _fixture, _insert, _read,
)


def _drive(root, source):
    return SourcedNumericDrive(
        numeric_drive_id(root.token, source.token, 1.0, 2.0), 1,
        root.token, 1, source.token, 1,
        access_key("bot", "persona", source.owner.subject).token, 1,
        "mapping:one", "compiler:one", SCHEME_VERSION, 1.0, 2.0,
        REGISTERED_AXIS_IDS, (0.1,) * 24,
    )


def test_graph_checkpoint_and_drive_are_read_but_readout_stays_hold(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        drive = _drive(root, source)
        write = sourced_numeric_drive_write(drive)
        _insert(store._db, namespace, write.key, write.value)
        candidate = _read(store, namespace, scheme, assets, root)
        store._db.execute("BEGIN IMMEDIATE")
        try:
            result = read_current_d04_numeric_sources(
                store._db, candidate=candidate, registry=store._registry,
                scheme=scheme, drive_ref=write.key.token,
                audience=("owner",), purpose="context",
            )
            assert result.initial_state == (2.0,) * 24
            assert result.drive == (0.1,) * 24
            assert result.status == "hold"
            assert "installed_readout_coefficients_asset_and_sha256_loader" in result.missing_sources
            assert result.drive_version in result.read_versions
        finally:
            store._db.execute("ROLLBACK")
    finally:
        store.close()


def test_stale_drive_source_and_ambiguous_interval_are_rejected(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        drive = _drive(root, source)
        write = sourced_numeric_drive_write(drive)
        _insert(store._db, namespace, write.key, write.value)
        candidate = _read(store, namespace, scheme, assets, root)
        store._db.execute("BEGIN IMMEDIATE")
        try:
            store._db.execute(
                "UPDATE graph_atoms SET revision=2 WHERE token=?",
                (drive.access_ref,),
            )
            with pytest.raises(CouplingSnapshotHold, match="source|access|changed"):
                read_current_d04_numeric_sources(
                    store._db, candidate=candidate, registry=store._registry,
                    scheme=scheme, drive_ref=write.key.token,
                    audience=("owner",), purpose="context",
                )
        finally:
            store._db.execute("ROLLBACK")
    finally:
        store.close()


def test_drive_schema_rejects_unbound_or_malformed_vector(tmp_path):
    store, _namespace, _scheme, _assets, source, root = _fixture(tmp_path)
    try:
        drive = _drive(root, source)
        with pytest.raises(ValueError, match="24 finite"):
            replace(drive, drive=(0.1,) * 23)
        with pytest.raises(ValueError, match="dependencies"):
            replace(drive, access_ref=access_key("bot", "persona", "other").token)
        assert sourced_numeric_drive_write(drive).value["drive"] == list(drive.drive)
    finally:
        store.close()


def test_drive_proposal_pins_committed_source_access_and_checkpoint(tmp_path):
    store, namespace, scheme, _assets, source, root = _fixture(tmp_path)
    try:
        drive = _drive(root, source)
        write = sourced_numeric_drive_write(drive)
        refs = write.dependencies
        atoms = []
        for key in refs:
            revision, encoded = store._db.execute(
                "SELECT revision,value FROM graph_atoms WHERE token=?", (key.token,),
            ).fetchone()
            atoms.append(GraphAtom(key, revision, json.loads(encoded)))
        snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 1),))
        inputs = (drive.drive_id, drive.checkpoint_ref, drive.source_ref,
                  drive.mapping_compiler_ref)
        envelope = CommandEnvelope(
            "sylanne.runtime.v1",
            OperationIdentity("activity-one", None, "attempt-one", "compile-drive",
                              "operation-one", canonical_digest({"input_refs": list(inputs)})),
            AuthorityContext("owner", "d04", "cap:d04", namespace, ("persona",),
                             "context", ("owner",), "policy:1", 1),
            VersionGuard((GraphVersion(write.key, 0), *(GraphVersion(atom.key, atom.revision)
                                                       for atom in atoms)), (), 0, 0,
                         "catalogue:1", scheme.scheme_version, scheme.operator_version,
                         "policy:1", (), (), ()),
            SourceQualification((source.token,), "authored", 0.0, 0.0,
                                "authored_content", "ineligible", None, "not_applicable"),
            inputs, "budget:1", 10.0, 10.0, "clock:1", (),
        )
        provider = AffectProvider(active_scheme=scheme)
        proposal = provider.propose_sourced_numeric_drive(envelope, snapshot, drive)
        assert proposal.typed_writes == (write,)
        with pytest.raises(ValueError, match="dependency is absent"):
            provider.validate(proposal, replace(snapshot, atoms=snapshot.atoms[:-1]))
        with pytest.raises(ValueError, match="provenance"):
            provider.validate(replace(proposal, typed_writes=(replace(
                write, value=dict(write.value, mapping_compiler_ref="caller")),)), snapshot)
    finally:
        store.close()
