"""Permanent metadata contract checks; not an installed Authority/P2 fixture."""
from dataclasses import replace
import json
import sqlite3
import unittest

from sylanne3.domains.d09.natural_disposition_v1 import (
    NaturalBatchDispositionV1, NaturalChildDispositionV1, child_identity_manifest_v1,
    natural_disposition_from_wire_v1, natural_disposition_write_v1,
)
from sylanne3.authority_service.natural_disposition_maintenance_v1 import (
    NaturalBatchMetadataV1, NaturalBubbleMetadataV1, NaturalFeeMetadataV1,
    validate_owner_natural_batch_metadata_v1,
)
from sylanne3.runtime.natural_same_batch_history_v3 import read_natural_roster_head_v1
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


def _roster():
    ns=NamespaceId("bot","persona")
    children=(NaturalChildDispositionV1(0,"child-0","effect-0","segment-0","a"*64),
        NaturalChildDispositionV1(1,"child-1","effect-1","segment-1","b"*64))
    return NaturalBatchDispositionV1(ns,"installation","parent-c02","activity","generation","c"*64,
        "review","d"*64,"e"*64,"child-0",canonical_digest(child_identity_manifest_v1(children)),(),100.0,children,birth_original_ref="natural-disposition-original:birth",authority_original_ref="natural-disposition-original:birth")


class NaturalDispositionContractTests(unittest.TestCase):
    def test_finite_identity_roster_roundtrips_and_unknown_is_a_pause_not_unsent(self):
        value=_roster(); raw=natural_disposition_write_v1(value).value
        self.assertEqual(natural_disposition_from_wire_v1(raw),value)
        held=replace(value.children[1],continuation_state="held",reason_code="predecessor_unknown",
            cause_kind="authority_effect_observation",cause_ref="effect-0",cause_digest="f"*64)
        updated=replace(value,children=(value.children[0],held),revision=2)
        self.assertEqual(natural_disposition_from_wire_v1(updated.to_wire()).children[1].continuation_state,"held")
        invalid=replace(value,children=(value.children[0],replace(held,continuation_state="cancelled",cause_kind=None,cause_ref=None,cause_digest=None)))
        with self.assertRaisesRegex(ValueError,"qualified cause"):
            natural_disposition_write_v1(invalid)

    def test_metadata_reader_keeps_original_identity_without_returning_private_batch_text(self):
        value=_roster(); write=natural_disposition_write_v1(value); batch_ref='batch-metadata'
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE graph_atoms(token TEXT,revision INTEGER,value TEXT,valid INTEGER,bot TEXT,persona TEXT,type_name TEXT)")
            db.execute("CREATE TABLE graph_history(token TEXT,revision INTEGER,event_id TEXT,value TEXT,valid INTEGER)")
            db.execute("CREATE TABLE graph_bundle_operations(bot TEXT,persona TEXT,operation_id TEXT,activity_id TEXT,effect_id TEXT,receipt_json TEXT)")
            wire=canonical_serialize(write.value)
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)",(write.key.token,1,wire,1,"bot","persona",value.schema))
            db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?)",(write.key.token,1,"child-0",wire,1))
            candidate={"natural_dispatch_candidate":{"refs":[["intent",1],["schema",1],["grant",1],[batch_ref,1]]}}
            db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?)",("bot","persona","child-0","activity","effect-0",json.dumps(candidate)))
            metadata={"paid_review":{"generation_original_operation_id":"generation","review_original_operation_id":"review"},
                "segment":{"payload_digest":"a"*64,"body":"PRIVATE-BATCH-TEXT"}}
            db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?)",(batch_ref,1,"child-0",json.dumps(metadata),1))
            head=read_natural_roster_head_v1(db,value.namespace,value.parent_original_id)
            self.assertEqual(head[2],value)
            self.assertNotIn("PRIVATE-BATCH-TEXT",canonical_serialize(head[2]))
            children=(value.children[0],replace(value.children[1],effect_id="foreign-effect"))
            altered=replace(value,children=children,identity_manifest_digest=canonical_digest(child_identity_manifest_v1(children)))
            db.execute("UPDATE graph_atoms SET value=?",(canonical_serialize(altered.to_wire()),))
            with self.assertRaisesRegex(ValueError,"adopted roster"):
                read_natural_roster_head_v1(db,value.namespace,value.parent_original_id)

    def test_owner_projection_preserves_accepted_read_unknown_and_parent_cost_once(self):
        fee=NaturalFeeMetadataV1("settlement-parent","pending_confirmation","USD",None,{"model_microusd":7})
        children=(NaturalBubbleMetadataV1(0,"child-0","effect-0","intent","admission","ready",None,
            "observed","accepted","observation","unknown",()),
            NaturalBubbleMetadataV1(1,"child-1","effect-1",None,None,"held","predecessor_unknown",
                "unavailable",None,None,"unknown",()))
        data=NaturalBatchMetadataV1("d12.natural-batch-metadata.v1","parent-c02",2,"adopted",(fee,),children).to_wire()
        validate_owner_natural_batch_metadata_v1(data,"parent-c02")
        duplicate=json.loads(json.dumps(data));duplicate["children"][0]["fees"]=[duplicate["parent_fees"][0]]
        with self.assertRaisesRegex(ValueError,"counted twice"):
            validate_owner_natural_batch_metadata_v1(duplicate,"parent-c02")
        forbidden=json.loads(json.dumps(data));forbidden["children"][0]["read_state"]="read"
        with self.assertRaisesRegex(ValueError,"actual observation"):
            validate_owner_natural_batch_metadata_v1(forbidden,"parent-c02")
        data["body"]="PRIVATE-BATCH-TEXT"
        with self.assertRaisesRegex(ValueError,"exact Owner"):
            validate_owner_natural_batch_metadata_v1(data,"parent-c02")


if __name__=="__main__":
    unittest.main()
