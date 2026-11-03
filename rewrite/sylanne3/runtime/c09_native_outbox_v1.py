"""Exact native R09/R03 outbox lineage over frozen C09 originals."""
from hashlib import sha256
import json
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .c09_paged_sql_v2 import C09PagedCaptureHold,read_c09_table_shape_v2
from .c09_graph_row_codec_v2 import read_c09_domain_row_v2

_D07="graph_d07_execution_originals_v1";_D01="graph_d01_production_inputs_v1"
_NATIVE=frozenset(("prepared","prepare_commit","ordinary_continuity_attention_v1",
    "ordinary_continuity_adoption_v1","single_event_review_attention_v1",
    "single_event_review_adoption_v1","single_event_review_cardinality_rejected_v1"))


class _C09NativeOutboxReadV1:
    def __init__(self,build,meter):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        if type(build) is not InstalledGraphRebaseBuildV2 or current_c09_sql_meter_v2() is not meter:
            raise C09PagedCaptureHold("actual frozen Graph outbox owner/reserved meter required")
        build.require_current()
        self.build,self.meter=build,meter;self.cache={};self.prepared={};self.values=[];self.closed=False
        build.session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        return 8192+_retained_size((self.cache,self.prepared,self.values),set())

    def require_current(self,ns):
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        if self.closed or current_c09_sql_meter_v2() is not self.meter or ns.as_tuple!=tuple(json.loads(self.build.scope.graph_namespace)):
            raise C09PagedCaptureHold("native outbox reader left its actual source namespace/quantum")
        self.build.require_current()

    def close(self):
        self.cache.clear();self.prepared.clear();self.values.clear();self.closed=True

    def _point(self,db,table,columns,where,args):
        from .c09_paged_sql_v2 import _quote,current_c09_sql_meter_v2
        if (self.closed or current_c09_sql_meter_v2() is not self.meter
                or db not in (self.build.pair.source,self.build.pair.candidate)):
            raise C09PagedCaptureHold("native outbox point left its actual source/candidate quantum")
        self.build.require_current()
        lengths=db.execute("SELECT "+",".join("length(CAST("+_quote(name)+" AS BLOB))"for name in columns)
            +" FROM "+_quote(table)+" WHERE "+where+" LIMIT 1",args).fetchone()
        self.meter.charge_read(len(columns)*8)
        if lengths is None:return None
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter,
            additional_bytes=sum(value or 0 for value in lengths)*12+32768)
        return self.meter.read_fixed_row(db,table,columns,where,args)

    def _load(self,ns,dependency):
        from .domain_production_erasure_v1 import TABLE_COLUMNS
        from .c09_d07_execution_v1 import COLUMNS as D07_COLUMNS
        from .c09_graph_rebase_candidate_v2 import _actual_source_row_origin_v2
        self.require_current(ns)
        if type(dependency) is not tuple or len(dependency)!=3:
            raise C09PagedCaptureHold("closed native outbox dependency required")
        table,key,digest=dependency
        if (table not in {_D07,_D01} or type(key) is not tuple or key[:2]!=ns.as_tuple
                or table==_D07 and (len(key)!=4 or key[2] not in _NATIVE)
                or table==_D01 and len(key)!=3):
            raise C09PagedCaptureHold("native outbox dependency escaped its registered exact family/PK")
        identity=(table,key,digest)
        if identity in self.cache:return self.cache[identity]
        shape=read_c09_table_shape_v2(self.build.pair.source,table,meter=self.meter)
        expected=D07_COLUMNS if table==_D07 else TABLE_COLUMNS[_D01]
        if shape.columns!=expected or shape.primary_key_columns!=(("bot","persona","kind","original_ref") if table==_D07 else ("bot","persona","original_ref")):
            raise C09PagedCaptureHold("native outbox source schema/PK differs")
        from .c09_paged_sql_v2 import _quote
        lengths=",".join("length(CAST("+_quote(name)+" AS BLOB))" for name in expected)
        where=" AND ".join(_quote(name)+"=?" for name in shape.primary_key_columns)
        metadata=self.build.pair.source.execute("SELECT "+lengths+" FROM "+_quote(table)+" WHERE "+where,key).fetchone()
        self.meter.charge_read(8*len(expected))
        if metadata is None:raise C09PagedCaptureHold("native outbox original is absent")
        size=sum(n or 0 for n in metadata)
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter,additional_bytes=size*12+32768)
        row=tuple(self.meter.read_row(self.build.pair.source,shape,key))
        original=read_c09_domain_row_v2(table,shape.columns,row,
            authority_namespace=self.build.scope.authority_namespace,
            issuer=self.build.session.get_c09_domain_original_issuer_v2())
        if original.original_commitment!=digest:
            raise C09PagedCaptureHold("native outbox original differs from its exact complete source digest")
        if table==_D01:
            from .d01_production_operations_v1 import SIGN_KIND
            if original.kind!="single_event_review_case_v1":
                raise C09PagedCaptureHold("native D01 outbox requires its actual registered Review Case")
            self.build.session.get_c09_domain_original_issuer_v2()._signer.verify(
                SIGN_KIND,row[shape.columns.index("payload_json")],row[shape.columns.index("signature")])
        origin=_actual_source_row_origin_v2(self.build,shape,key,row,self.meter)
        proof=self._point(self.build.pair.candidate,"c09_graph_dispositions_v2",
            ("old_commitment","disposition","new_commitment"),
            "scope_digest=? AND table_name=? AND key_digest=?",
            (self.build.scope.scope_digest,table,canonical_digest((table,key))))
        if proof is None or proof[0]!=origin["origin_commitment"] or proof[1] not in {"preserved_exact","derived_removed"}:
            raise C09PagedCaptureHold("native outbox original lacks its actual classified frozen-source disposition")
        result=row,original,proof[1];self.cache[identity]=result
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter)
        return result

    def causal(self,ns,dependency,domain_row):
        row,original,disposition=self._load(ns,dependency);raw=original.payload
        op=domain_row[2]
        if original.family==_D01:
            if row[4]!=op or raw["registration_operation_id"]!=op:
                raise C09PagedCaptureHold("native Case changed its actual registration producer")
        elif original.kind in {"ordinary_continuity_attention_v1","single_event_review_attention_v1"}:
            if raw["registration_operation_id"]!=op or raw["registration_receipt_digest"]!=domain_row[11]:
                raise C09PagedCaptureHold("native attention changed its actual Domain registration receipt")
        elif original.kind in {"ordinary_continuity_adoption_v1","single_event_review_adoption_v1"}:
            if (raw["operation_id"]!=op or raw["domain_original_digest"]!=domain_row[6]
                    or raw["commit_receipt_digest"]!=domain_row[11]):
                raise C09PagedCaptureHold("native completion changed its actual paid Domain adoption/receipt")
        else:raise C09PagedCaptureHold("unregistered native causal original")
        if original.family!=_D01:
            from .domain_production_originals_v1 import _receipt
            receipt=_receipt(json.loads(domain_row[10]))
            self._native_graph(ns,original,receipt=receipt)
        return disposition

    def command(self,ns,dependency,operations):
        row,original,disposition=self._load(ns,dependency);raw=original.payload
        if original.kind=="prepare_commit":
            prepared=self._prepared(ns,dependency[1][3])
            if (prepared.operation_id not in operations or raw["prepare_operation_id"]!=prepared.prepare_operation_id
                    or raw["prepared_digest"]!=prepared.digest):
                raise C09PagedCaptureHold("native command commit lost its actual signed Prepared")
        elif original.kind=="prepared":
            prepared=self._prepared(ns,dependency[1][3])
            if prepared.operation_id not in operations:
                raise C09PagedCaptureHold("native command Prepared belongs to another actual Owner command")
        elif original.kind in {"single_event_review_adoption_v1","single_event_review_cardinality_rejected_v1"}:
            if raw["operation_id"] not in operations:
                raise C09PagedCaptureHold("native command terminal belongs to another actual Owner command")
            prepared=self._prepared(ns,raw["job_id"])
            if raw["operation_id"]!=prepared.operation_id or raw["prepared_original"]["original_ref"]!=prepared.job_id:
                raise C09PagedCaptureHold("native command terminal lost its actual Prepared parent")
        else:raise C09PagedCaptureHold("unregistered native command dependency")
        if original.kind in {"single_event_review_adoption_v1","single_event_review_cardinality_rejected_v1"}:
            self._native_graph(ns,original)
        return disposition,prepared.operation_id

    def _prepared(self,ns,job):
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        self.require_current(ns)
        if job in self.prepared:return self.prepared[job]
        header=self._point(self.build.pair.source,_D07,("payload_digest",),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*ns.as_tuple,"prepared",job))
        if header is None:raise C09PagedCaptureHold("native command lost its real Prepared original")
        _,original,_=self._load(ns,(_D07,(*ns.as_tuple,"prepared",job),header[0]))
        raw=original.payload
        from .d07_ordinary_continuity_cognition_v1 import D07OrdinaryContinuityPreparedV1
        from .d07_single_event_review_v1 import D07SingleEventReviewPreparedV1
        cls={"d07.ordinary-continuity-prepared.v1":D07OrdinaryContinuityPreparedV1,
            "d07.single-event-review-prepared.v1":D07SingleEventReviewPreparedV1}.get(raw.get("schema"))
        if cls is None:raise C09PagedCaptureHold("native Serve requires its independent official prepared variant")
        from .c09_logical_source_v3 import _retained_size
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter,
            additional_bytes=_retained_size(raw,set())*2+8192)
        prepared=decode_typed_production_value_v1(raw,cls)
        if prepared.namespace!=ns or prepared.job_id!=job:
            raise C09PagedCaptureHold("native command Prepared changed namespace/job identity")
        self.prepared[job]=prepared
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter)
        return prepared

    def job(self,ns,token,operations):
        from .d07_execution_v1 import d07_execution_ids_v1
        from .domain_production_originals_v1 import _receipt
        from .d11_types import runtime_job_key,RuntimeJobValue
        from .d10_offline_tick_execution_v1 import _decode_json
        self.require_current(ns);matches=[]
        for operation in operations:
            row=self._point(self.build.pair.source,"graph_owner_domain_attempts_v3",("receipt_json",),
                "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation))
            if row is None or row[0] is None:raise C09PagedCaptureHold("native job lost its actual Owner command receipt")
            data=json.loads(row[0]);receipt=_receipt(data["receipt"])
            job=d07_execution_ids_v1(ns,operation,"concern")["job"]
            key=runtime_job_key(*ns.as_tuple,receipt.activity_id,job)
            if key.token==token:
                versions=tuple(v for v in receipt.write_versions if v.key==key)
                if len(versions)!=1 or versions[0].revision<1:
                    raise C09PagedCaptureHold("native job is not an actual Owner preparation receipt member")
                matches.append((operation,job,receipt,versions[0]))
        if len(matches)!=1:raise C09PagedCaptureHold("native job has no unique actual command producer")
        operation,job,receipt,version=matches[0]
        encoded=self._history_value(ns,version,receipt.activity_id,receipt.operation_id,retain=True)
        value=_decode_json(encoded,RuntimeJobValue)
        if ((value.bot_id,value.persona_id,value.activity_id,value.operation_id,value.job_id,value.phase)!=
                (*ns.as_tuple,receipt.activity_id,operation,job,"queued")):
            raise C09PagedCaptureHold("native preparation job history changed its actual original queued identity")
        self.values.append(value)
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter)
        proof=self._point(self.build.pair.candidate,"c09_graph_dispositions_v2",("disposition",),
            "scope_digest=? AND table_name=? AND key_digest=?",
            (self.build.scope.scope_digest,"graph_atoms",canonical_digest(("graph_atoms",(token,)))))
        if proof is None:raise C09PagedCaptureHold("native job lacks its actual classified current Graph row")
        if proof[0] not in {"preserved_exact","logical_preserved_v3","derived_removed","payload_erased_retained_facts","rebuilt_from_surviving_sources"}:
            raise C09PagedCaptureHold("native job has an unknown target disposition")
        return ("derived_removed" if proof[0] in {"derived_removed","payload_erased_retained_facts"} else "preserved_exact"),operation

    def _native_graph(self,ns,original,*,receipt=None):
        from ..graph_types import GraphVersion,GraphReceipt,NamespaceEpoch
        from ..graph_store import GraphStore
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        raw=original.payload;roles=[]
        if original.kind in {"ordinary_continuity_attention_v1","single_event_review_attention_v1"}:
            op=raw["registration_operation_id"]
            roles.append((raw["ticket_ref"],raw["ticket_value_digest"]))
        elif original.kind=="single_event_review_cardinality_rejected_v1":
            op=raw["rejection_operation_id"]
            roles.extend(((raw["job_version"],raw["job_value_digest"]),(raw["ticket_version"],raw["ticket_value_digest"])))
        else:
            op=raw["operation_id"]
            roles.append((raw["interpretation_version"],raw["interpretation_value_digest"]))
            if original.kind=="single_event_review_adoption_v1":
                roles.extend(((raw["adoption_version"],None),(raw["review_version"],None)))
        if receipt is None:
            if original.kind=="single_event_review_cardinality_rejected_v1":
                activity=raw["activity_id"]
            else:
                from .domain_production_originals_v1 import _receipt
                saved=self._point(self.build.pair.source,"graph_domain_production_originals_v1",
                    ("receipt_json","original_digest"),"bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,op))
                if saved is None or saved[1]!=raw["domain_original_digest"]:
                    raise C09PagedCaptureHold("native terminal lost its actual Domain adoption original")
                receipt=_receipt(json.loads(saved[0]));activity=receipt.activity_id
        else:
            activity=receipt.activity_id
        if receipt is not None and receipt.operation_id!=op:
            raise C09PagedCaptureHold("native member changed its actual Graph producer")
        event=self._point(self.build.pair.source,"graph_events",
            ("revisions","invalidated","epoch_revision"),"bot=? AND persona=? AND session=? AND event_id=?",
            (*ns.as_tuple,activity,op))
        if event is None:raise C09PagedCaptureHold("native member lost its actual producing event")
        graph_receipt=GraphReceipt("committed",GraphStore._version_rows(event[0]),
            GraphStore._version_rows(event[1]),NamespaceEpoch(*ns.as_tuple,event[2]))
        self.values.append(graph_receipt)
        if "graph_receipt_digest" in raw and canonical_digest(graph_receipt)!=raw["graph_receipt_digest"]:
            raise C09PagedCaptureHold("native member changed its original Graph receipt")
        if receipt is not None and tuple(receipt.write_versions)!=tuple(graph_receipt.revisions):
            raise C09PagedCaptureHold("native Domain receipt differs from its full actual event writes")
        for encoded,digest in roles:
            version=decode_typed_production_value_v1(encoded,GraphVersion)
            if version not in graph_receipt.revisions or NamespaceId.from_key(version.key)!=ns:
                raise C09PagedCaptureHold("native role is not an actual same-namespace event write")
            observed=self._history_value(ns,version,activity,op,retain=False)
            if digest is not None and observed!=digest:
                raise C09PagedCaptureHold("native role differs from its complete actual history value")
        self.build.session._control.require_c09_retained_arena_v3(meter=self.meter)

    def _history_value(self,ns,version,activity,operation,*,retain):
        db=self.build.pair.source;meter=self.meter
        shape=read_c09_table_shape_v2(db,"graph_history",meter=meter)
        column="value_cell_id" if "value_cell_id" in shape.columns else "value"
        row=self._point(db,"graph_history",(column,"valid","event_bot","event_persona","event_session","event_id"),
            "token=? AND revision=?",(version.key.token,version.revision))
        if row is None or row[1:]!=(1,*ns.as_tuple,activity,operation):
            raise C09PagedCaptureHold("native member has no actual valid same-producer history")
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        parser=C09CanonicalJSONStreamV2(ensure_ascii=True);digest=sha256();raw=bytearray() if retain else None
        if column=="value":
            encoded=row[0];block=encoded.encode("ascii")
            self.build.session._control.require_c09_retained_arena_v3(meter=meter,additional_bytes=len(block)*3+8192)
            for offset in range(0,len(block),4096):
                fragment=block[offset:offset+4096];parser.feed(fragment,lambda event:None);digest.update(fragment)
            if retain:raw.extend(block)
            meter.charge_encode(len(block))
        else:
            from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
            ddl=self._point(db,"sqlite_master",("sql",),"type=? AND name=?",("table","graph_history"))
            if ddl!=(GRAPH_REF_DDLS_V3["graph_history"],):raise C09PagedCaptureHold("native member physical history schema differs")
            scope=self.build.session.begin_source_physical_read_v3(self.build.pair,meter=meter)
            header=scope.read_cell_header_v3(row[0],meter=meter)
            if header[1:3]!=("canonical-json.ascii.v1",version.key.token):
                raise C09PagedCaptureHold("native member cell changed codec/owner")
            self.build.session._control.require_c09_retained_arena_v3(meter=meter,
                additional_bytes=(header[4]*3 if retain else 0)+32768)
            meter.require_available(header[4]*2+header[5]*1024+8192)
            size=0;root=canonical_digest(("sylanne3.segmented-cell-genesis.v1",row[0]))
            for ordinal in range(header[5]):
                segment=scope.read_cell_segment_v3(row[0],ordinal,meter=meter)
                if segment is None or segment[0]!=size:raise C09PagedCaptureHold("native history fragments changed")
                parser.feed(segment[1],lambda event:None);digest.update(segment[1])
                root=canonical_digest(("sylanne3.segmented-cell-link.v1",root,row[0],
                    ordinal,size,len(segment[1]),segment[2]));size+=len(segment[1])
                if retain:raw.extend(segment[1])
            scope.require_cell_eof_v3(row[0],header[5],meter=meter)
            if (size,digest.hexdigest(),root)!=(header[4],header[6],header[7]):
                raise C09PagedCaptureHold("native member logical Source EOF/SHA/root differs")
            scope.require_current(meter=meter)
        parser.finish();parser._emit_callback=None
        if not retain:return digest.hexdigest()
        encoded=raw.decode("ascii");meter.charge_encode(len(raw))
        self.values.append(encoded)
        return encoded
