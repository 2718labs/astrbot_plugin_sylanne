"""W01 frame boundary checks with a test verifier, not product admission."""

import json
import sqlite3
from dataclasses import asdict

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.current_product_frame import (
    D04CurrentReadHold, read_d04_current_product_frame_in_transaction,
)
from sylanne3.domains.d04.product_issuer import D04VerifiedNumericAdoptionV1
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_types import AtomKey
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId

from .test_product_readout_candidate import _case


class _TestOnlyVerifier:
    def __init__(self):
        self.live = True
        self.adopted = True

    def verify_live_read(self, db, authority, fence):
        assert db.in_transaction
        return self.live

    def verify_numeric_adoption(self, db, checkpoint, ref, revision, closure_digest):
        assert db.in_transaction
        if not self.adopted:
            raise D04CurrentReadHold("no persisted numeric adoption")
        return D04VerifiedNumericAdoptionV1(
            ref, revision, checkpoint.commit_operation_id, "2" * 64,
            checkpoint.certificate_source, checkpoint.certificate_digest,
            checkpoint.asset_digest, checkpoint.numeric_error_bound,
            "b" * 64, "c" * 64, closure_digest,
        )


def _db_case():
    checkpoint, ref, source, scheme, _, _, read = _case()
    db = sqlite3.connect(":memory:")
    db.executescript("""
        CREATE TABLE graph_atoms (
            bot TEXT, persona TEXT, type_name TEXT, token TEXT PRIMARY KEY,
            revision INTEGER, value TEXT, valid INTEGER);
        CREATE TABLE graph_epochs (bot TEXT, persona TEXT, revision INTEGER);
        CREATE TABLE graph_authority_epochs (
            bot TEXT, persona TEXT, access_epoch INTEGER, delete_epoch INTEGER);
        CREATE TABLE graph_recovery_metadata_v2 (
            bot TEXT, persona TEXT, requirements_json TEXT, graph_revision INTEGER);
        CREATE TABLE graph_guard_versions (
            bot TEXT, persona TEXT, kind TEXT, ref TEXT, version TEXT);
    """)
    for atom in read.snapshot.atoms:
        if atom.revision == 0:
            continue
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            "bot:one", "alice", atom.key.type_name, atom.key.token,
            atom.revision, canonical_json(atom.value), int(atom.valid),
        ))
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot:one", "alice", 7))
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
               ("bot:one", "alice", 0, 0))
    db.execute("INSERT INTO graph_recovery_metadata_v2 VALUES(?,?,?,?)", (
        "bot:one", "alice", canonical_json({"graph_incarnation": "incarnation:one"}), 11,
    ))
    for kind, version in (("scheme", scheme.scheme_version),
                          ("operator", scheme.operator_version)):
        db.execute("INSERT INTO graph_guard_versions VALUES(?,?,?,?,?)",
                   ("bot:one", "alice", kind, "current", version))
    db.commit()
    db.execute("BEGIN")
    authority = AuthorityContext(
        "host:user", "d04", "capability", NamespaceId("bot:one", "alice"),
        ("persona",), "context", ("entity:alice",), "policy", 3,
    )
    kwargs = dict(
        authority=authority, fence=read.fence, verifier=_TestOnlyVerifier(),
        checkpoint_ref=ref, source_ref=source, audience=("entity:alice",),
        purpose="context", installed_scheme=scheme,
        installed_scheme_sha256=checkpoint.assets.scheme_sha256,
    )
    return db, kwargs


def test_reads_current_frame_only_in_live_transaction():
    db, kwargs = _db_case()
    try:
        frame = read_d04_current_product_frame_in_transaction(db, **kwargs)
        assert frame.checkpoint.block.meaning_ref == "meaning:ambivalence"
        assert frame.source_read.complete
        assert frame.adoption.graph_closure_digest
        db.commit()
        with pytest.raises(D04CurrentReadHold, match="transaction"):
            read_d04_current_product_frame_in_transaction(db, **kwargs)
    finally:
        db.close()


def test_live_fence_and_numeric_adoption_are_required():
    db, kwargs = _db_case()
    try:
        kwargs["verifier"].live = False
        with pytest.raises(D04CurrentReadHold, match="Authority"):
            read_d04_current_product_frame_in_transaction(db, **kwargs)
        kwargs["verifier"].live = True
        kwargs["verifier"].adopted = False
        with pytest.raises(D04CurrentReadHold, match="persisted numeric"):
            read_d04_current_product_frame_in_transaction(db, **kwargs)
    finally:
        db.close()


@pytest.mark.parametrize("mutation, expected", [
    ("revoke", "source is missing"),
    ("correct", "source is missing"),
    ("scheme", "Scheme graph guard"),
    ("stale", "feeling state is stale"),
    ("coupled", "numeric coupling is invalid"),
    ("joint", "joint SCC"),
    ("mixed_sources", "single-source causal qualification"),
    ("active_driver", "single-source causal qualification"),
])
def test_current_source_scheme_and_numeric_closure_hold(mutation, expected):
    db, kwargs = _db_case()
    try:
        db.commit()
        if mutation == "revoke":
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?",
                       (kwargs["source_ref"],))
        elif mutation == "correct":
            correction = source_correction_head_key(kwargs["authority"].namespace,
                                                    "source:one")
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
                "bot:one", "alice", correction.type_name, correction.token,
                1, "{}", 1,
            ))
        elif mutation == "scheme":
            db.execute("UPDATE graph_guard_versions SET version='changed' WHERE kind='scheme'")
        elif mutation == "stale":
            db.execute("UPDATE graph_atoms SET revision=4 WHERE type_name='d04.feeling_state.v1'")
        elif mutation == "coupled":
            from sylanne3.domains.d04.numeric_coupling import TYPE_NAME
            coupling = AtomKey(AtomKey.from_token(kwargs["checkpoint_ref"]).owner,
                               TYPE_NAME, "edge:one")
            # A malformed live edge must hold instead of being ignored.
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
                "bot:one", "alice", TYPE_NAME, coupling.token, 1,
                canonical_json({"left_ref": kwargs["checkpoint_ref"],
                                "right_ref": kwargs["checkpoint_ref"]}), 1,
            ))
        elif mutation == "joint":
            from sylanne3.domains.d04.numeric_coupling import (
                FACTOR_KIND, SCHEME_VERSION, TEMPLATE, TYPE_NAME, NumericCoupling,
                coupling_id, REGISTERED_AXIS_IDS,
            )
            root = kwargs["checkpoint_ref"]
            other = AtomKey(AtomKey.from_token(root).owner,
                            "d04.numeric_checkpoint.v1", "block:two").token
            axis = REGISTERED_AXIS_IDS[0]
            edge_id = coupling_id(root, axis, other, axis)
            edge = NumericCoupling(
                edge_id, 1, SCHEME_VERSION, root, axis, other, axis,
                TEMPLATE, FACTOR_KIND, 0.1, kwargs["source_ref"], 0.0, 20.0,
            )
            key = AtomKey(AtomKey.from_token(root).owner, TYPE_NAME, edge_id)
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
                "bot:one", "alice", TYPE_NAME, key.token, 1,
                canonical_json(asdict(edge)), 1,
            ))
        elif mutation in {"mixed_sources", "active_driver"}:
            row = db.execute("SELECT token,value FROM graph_atoms WHERE "
                             "type_name='d04.feeling_state.v1'").fetchone()
            value = json.loads(row[1])
            if mutation == "mixed_sources":
                value["historical_source_refs"].append("another:source")
            else:
                value["active_driver_refs"].append("driver:one")
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_json(value), row[0]))
        db.commit()
        db.execute("BEGIN")
        with pytest.raises(D04CurrentReadHold, match=expected):
            read_d04_current_product_frame_in_transaction(db, **kwargs)
    finally:
        db.close()
