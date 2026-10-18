"""Actual signed point and immutable join-context tests; no installed permission."""
import sqlite3
import pytest
from sylanne3.runtime.artifact_phase_postconditions_v1 import _history_life_payload_point_v2
from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
from sylanne3.runtime.d11_life_preparation_v1 import SIGN_KIND
from sylanne3.runtime.issuers import D02ResourceIssuer,D11BudgetJobIssuer,IssuerAuthorityDenied
from sylanne3.runtime_contracts import NamespaceId,canonical_digest,canonical_serialize


def original_case():
    db=sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_d11_life_originals_v1(bot,persona,kind,original_ref,producing_operation_id,payload_json,payload_digest,signature)")
    db.execute("CREATE TABLE graph_bundle_operations(bot,persona,operation_id,digest,receipt_json,commit_seq)")
    ns=NamespaceId("bot","persona");issuer=D11BudgetJobIssuer(D02ResourceIssuer(b"d"*32),b"s"*32)
    raw={"schema":"history-reader-test.v1","original_ref":"original:1"};digest=canonical_digest(raw)
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((ns,"postcondition","original:1",digest)))
    db.execute("INSERT INTO graph_d11_life_originals_v1 VALUES(?,?,?,?,?,?,?,?)",
        (*ns.as_tuple,"postcondition","original:1","producer:1",canonical_serialize(raw),digest,signature))
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?)",
        (*ns.as_tuple,"producer:1","bundle:1",canonical_serialize({"commit_seq":1}),1))
    return db,ns,issuer,raw,digest


def read(db,ns,**context):
    return _history_life_payload_point_v2(db,("payload_digest","producing_operation_id"),
        namespace=ns,kind="postcondition",ref="original:1",**context)


def test_live_history_point_uses_actual_issuer_signature_and_positive_producer():
    db,ns,issuer,raw,digest=original_case()
    try:
        assert read(db,ns,issuer=issuer)==(digest,"producer:1")
        foreign=D11BudgetJobIssuer(D02ResourceIssuer(b"d"*32),b"x"*32)
        with pytest.raises(IssuerAuthorityDenied,match="signature"):
            read(db,ns,issuer=foreign)
    finally:db.close()


def test_c09_join_lookup_checks_canonical_fact_and_committed_producer():
    db,ns,issuer,raw,digest=original_case()
    def lookup(key):
        assert key==(ns,"postcondition","original:1")
        return "producer:1",raw,raw,digest
    try:
        assert read(db,ns,read_original=lookup)==(digest,"producer:1")
        db.execute("DELETE FROM graph_bundle_operations")
        with pytest.raises(ValueError,match="committed producing operation"):
            read(db,ns,read_original=lookup)
    finally:db.close()


def test_historical_lookup_cannot_replace_live_issuer_or_alter_digest():
    db,ns,issuer,raw,digest=original_case()
    try:
        with pytest.raises(ValueError,match="cannot replace"):
            read(db,ns,issuer=issuer,read_original=lambda key:None)
        with pytest.raises(ValueError,match="canonical original"):
            read(db,ns,read_original=lambda key:("producer:1",raw,{**raw,"changed":True},digest))
        with pytest.raises(MissingProductionOriginalV1,match="actual_signed_reader_or_C09"):
            read(db,ns)
    finally:db.close()
