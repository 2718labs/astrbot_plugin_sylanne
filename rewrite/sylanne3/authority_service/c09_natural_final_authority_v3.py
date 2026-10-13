"""Frozen Core final fence and original Owner issue, with no live reauthorization."""
from copy import copy
from dataclasses import asdict,fields,is_dataclass
import json
import sys
from hashlib import sha256
from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold,_D13PaidRowStreamV3


class NaturalFinalAuthorityOriginalReadV3:
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_final_core_owner_originals'
                or parent.natural_final_original is None or not parent.natural_final_original.complete):
            raise C09PagedCaptureHold("natural final Core originals require full actual Graph original links")
        self.parent=parent;self.capture=parent.capture;self.builder=self.capture.builder
        self.source=parent.natural_reference_facts.source;self.graph_original=parent.natural_final_original
        self.payload=self.graph_original.payload_values;self.pair=self.builder.pair;self.source_original=self.pair.source_original
        self.phase='scope';self.scope=None;self.guard=None;self.fence=None;self.owner_small=None
        self.buffer=bytearray();self.offset=0;self.total=None;self.blob_index=0;self.proof=None;self.receipt=None
        self.issue_guard=None;self.pending_small=None;self.pending_operation=None;self.pending_receipt=None
        self.ticket_small=None;self.ticket=None;self.complete=False;self.source_qualified_complete=False;self.required_core_rows=();self.obligation_index=0;self.obligation_reader=None;self.source.arena.add(self);self.source.require_arena()
    _digest=_D13PaidRowStreamV3._digest
    def _source_heap_bytes(self):
        def size(value):
            total=sys.getsizeof(value)
            if type(value) is dict:total+=sum(size(k)+size(v) for k,v in value.items())
            elif type(value) in (list,tuple,set):total+=sum(size(v) for v in value)
            elif is_dataclass(value) and not isinstance(value,type):total+=sum(size(getattr(value,f.name)) for f in fields(value))
            return total
        return sys.getsizeof(self.__dict__)+sum(size(v) for v in
            (self.scope,self.guard,self.fence,self.owner_small,self.buffer,self.proof,self.receipt,self.issue_guard,
              self.pending_small,self.pending_operation,self.pending_receipt,self.ticket_small,self.ticket,self.required_core_rows))+4096
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self);result.buffer=bytearray(self.buffer)
        self.source.arena.add(result);return result
    def _json(self,value,meter,*,ascii):
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        upper=c09_canonical_json_size_v3(value,ascii=ascii)
        meter.require_available(upper);self.source.require_arena(upper*32+65536)
        raw=json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=ascii,allow_nan=False).encode('utf-8')
        meter.charge_encode(len(raw));return raw
    def _scope(self,meter):
        from .v2_contract import from_wire,FencePermitV2
        from .v2_owner_contract import OwnerAuthorizationGuardV1
        from ..runtime.restore_anchor import RestoreAnchor
        from ..runtime_contracts import NamespaceId,FenceScope
        from ..graph_types import NamespaceEpoch
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        raw=self.payload['scope'];self.source.require_arena(32*sum(c09_canonical_json_size_v3(value,ascii=False)
            for value in (raw,self.payload['owner_guard']))+65536)
        if type(raw['permit']) is not dict or raw['permit'].get('kind')!='fence_permit':
            raise C09PagedCaptureHold("actual final original has another permit codec kind")
        permit=from_wire(raw['permit'])
        if type(permit) is not FencePermitV2:raise C09PagedCaptureHold("actual final original lacks formal write permit")
        scope=FenceScope(NamespaceId(**raw['namespace']),raw['authority_namespace'],raw['generation'],raw['operation'],
            raw['operation_id'],permit,RestoreAnchor(**raw['pinned_anchor']),NamespaceEpoch(**raw['graph_epoch']),raw['graph_revision'])
        guard=OwnerAuthorizationGuardV1(**{**self.payload['owner_guard'],
            'namespace':NamespaceId(**self.payload['owner_guard']['namespace'])})
        actual=self.builder.scope
        if (scope.namespace!=self.parent.namespace or scope.operation!='write'
                or (guard.authority_id,guard.installation_id,guard.namespace)!=(actual.authority_id,actual.installation_id,self.parent.namespace)
                or scope.authority_namespace!=actual.authority_namespace or scope.permit.authority_id!=actual.authority_id
                or scope.pinned_anchor.revocation_epoch!=0 or guard.minimum_revocation_revision!=0
                or guard.minimum_revocation_epoch!=0 or guard.pending_revoke_operation_id is not None):
            raise C09PagedCaptureHold("actual final historical Owner/fence crosses installed scope or revocation watermark")
        self.scope=scope;self.guard=guard;self.phase='core_source'
    def _read_blob(self,table,column,where,key,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        with legacy_cell_read_transaction_v2(self.pair.source):
            if self.total is None:
                _,self.total,kind=read_legacy_sql_cell_fragment_v2(self.pair.source,table=table,column=column,
                    where=where,parameters=key,start=0,length=0,meter=meter)
                if kind!='blob' or self.total<=0:raise C09PagedCaptureHold("actual final Core original BLOB absent")
                self.source.require_arena(self.total*2+32768);return False
            amount=min(8192,self.total-self.offset);self.source.require_arena(amount*8+32768)
            raw,total,kind=read_legacy_sql_cell_fragment_v2(self.pair.source,table=table,column=column,
                where=where,parameters=key,start=self.offset,length=amount,meter=meter)
        if kind!='blob' or total!=self.total or len(raw)!=amount:raise C09PagedCaptureHold("actual final Core BLOB source changed")
        self.buffer.extend(raw);self.offset+=amount;return self.offset==self.total
    def _fence_decode(self,meter):
        from .v2_contract import from_wire,to_wire,_reject_duplicate_pairs,_reject_constant
        self.source.require_arena(self.total*32+65536);meter.require_available(self.total)
        raw=bytes(self.buffer);meter.charge_encode(len(raw))
        wire=json.loads(raw.decode('utf-8'),object_pairs_hook=_reject_duplicate_pairs,parse_constant=_reject_constant)
        if type(wire) is not dict or wire.get('kind')!='fence_permit':
            raise C09PagedCaptureHold("actual Core final BLOB has another permit codec kind")
        permit=from_wire(wire)
        encoded=self._json(to_wire(permit),meter,ascii=False)
        if permit!=self.scope.permit or raw!=encoded:raise C09PagedCaptureHold("actual final frozen Core permit differs from Graph authorization original")
        expected='sha256:'+self._digest({'action':'finish_natural_final','attempt_id':self.scope.operation_id,'permit_token':permit.token},meter)
        if self.fence['finish_request_digest']!=expected:raise C09PagedCaptureHold("actual final Core finish has another original digest")
        self.buffer.clear();self.offset=0;self.total=None;self.phase='owner_row'
    def _owner_decode(self,meter):
        from .v2_owner_contract import (from_wire,to_wire,_unique_pairs,_reject_constant,
            OwnerGraphCommitProofV1,OwnerAuthorizationReceiptV1,OwnerAuthorizationGuardV1,
            OwnerAuthorizationOperationV1,OwnerClaimTicketV1)
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        family=self.phase.removesuffix('_decode')
        classes={'owner':(OwnerGraphCommitProofV1,OwnerAuthorizationReceiptV1,OwnerAuthorizationGuardV1),
            'pending':(OwnerAuthorizationOperationV1,OwnerAuthorizationReceiptV1),'ticket':(OwnerClaimTicketV1,)}
        expected=classes[family][self.blob_index]
        self.source.require_arena(self.total*32+65536);meter.require_available(self.total)
        raw=bytes(self.buffer);meter.charge_encode(len(raw))
        wire=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique_pairs,parse_constant=_reject_constant)
        kind={OwnerGraphCommitProofV1:'owner_graph_commit_proof_v1',
            OwnerAuthorizationReceiptV1:'owner_authorization_receipt_v1',OwnerAuthorizationGuardV1:'owner_authorization_guard_v1',
            OwnerAuthorizationOperationV1:'owner_authorization_operation_v1',OwnerClaimTicketV1:'owner_claim_ticket_v1'}[expected]
        if type(wire) is not dict or wire.get('kind')!=kind:
            raise C09PagedCaptureHold("actual original Owner BLOB has another closed codec kind")
        constructor_wire=wire if expected is OwnerAuthorizationOperationV1 else wire.get('operation') if expected is OwnerAuthorizationReceiptV1 else None
        if expected is OwnerAuthorizationReceiptV1 and (type(constructor_wire) is not dict
                or constructor_wire.get('kind')!='owner_authorization_operation_v1'):
            raise C09PagedCaptureHold("actual original Owner receipt has another operation codec kind")
        constructor_size=0
        if constructor_wire is not None:
            # The formal operation constructor serializes this exact wire once
            # while verifying request_digest. Charge that hidden encoding too.
            unsigned={name:value for name,value in constructor_wire.items() if name!='request_digest'}
            constructor_size=c09_canonical_json_size_v3(unsigned,ascii=False,exact=True)
            meter.require_available(constructor_size);self.source.require_arena(constructor_size*32+65536)
        value=from_wire(wire)
        if constructor_size:meter.charge_encode(constructor_size)
        if type(value) is not expected:raise C09PagedCaptureHold("actual original Owner issue codec kind differs")
        encoded=self._json(to_wire(value),meter,ascii=False)
        if raw!=encoded:raise C09PagedCaptureHold("actual original Owner issue codec/roundtrip differs")
        if family=='owner':
            if self.blob_index==0:self.proof=value
            elif self.blob_index==1:self.receipt=value
            else:self.issue_guard=value
        elif family=='pending':
            if self.blob_index==0:self.pending_operation=value
            else:self.pending_receipt=value
        else:self.ticket=value
        self.buffer.clear();self.total=None;self.offset=0;self.blob_index+=1
        if self.blob_index==len(classes[family]):
            self.blob_index=0;self.phase={'owner':'pending_row','pending':'ticket_row','ticket':'owner_identity'}[family]
        else:self.phase=family+'_blob'
    def _owner_identity(self,meter):
        from .v2_owner_contract import to_wire
        proof=self.proof;receipt=self.receipt;guard=self.issue_guard;graph=self.graph_original
        operation=self.pending_operation;pending=self.pending_receipt;ticket=self.ticket;owner=graph.owner_small
        saved=self.pending_small;claim=self.ticket_small
        operation_namespace='ns:sha256:'+self._digest(list(operation.namespace.as_tuple),meter)
        ticket_namespace='ns:sha256:'+self._digest(list(ticket.namespace.as_tuple),meter)
        if (operation.action!='issue' or operation.ticket!=ticket or pending.operation!=operation
                or pending.phase!='pending' or pending.guard!=operation.expected_guard
                or pending.receipt_ref!='owner-issue-pending:'+operation.request_digest.removeprefix('sha256:')[:48]
                or (saved['operation_id'],saved['authority_namespace'],saved['ticket_id'],saved['request_digest'])!=(
                    operation.operation_id,operation_namespace,ticket.ticket_id,operation.request_digest)
                or saved['authority_namespace']!=self.scope.authority_namespace
                or ticket_namespace!=saved['authority_namespace']
                or (claim['authority_namespace'],claim['ticket_id'],claim['issue_operation_id'])!=(
                    saved['authority_namespace'],saved['ticket_id'],operation.operation_id)
                or receipt.operation!=operation):
            raise C09PagedCaptureHold("actual committed Owner issue lost its original pending operation/receipt/claim ticket")
        if (receipt.phase!='committed' or receipt.guard!=guard or guard!=self.guard
                or proof.namespace!=self.parent.namespace or proof.operation_id!=self.owner_small['operation_id']
                or (proof.operation_id,proof.request_digest,proof.grant_id,proof.grant_digest,proof.graph_incarnation,
                    proof.graph_access_epoch,proof.graph_epoch,proof.graph_receipt_digest)!=(
                    owner['operation_id'],owner['request_digest'],owner['grant_id'],owner['grant_digest'],owner['graph_incarnation'],
                    owner['graph_access_epoch'],owner['graph_epoch'],owner['graph_receipt_digest'])
                or (operation.authority_id,operation.installation_id,operation.namespace,operation.operation_id,
                    operation.grant_id,operation.grant_digest,operation.request_digest)!=(
                    guard.authority_id,guard.installation_id,guard.namespace,proof.operation_id,proof.grant_id,proof.grant_digest,proof.request_digest)
                or proof.grant_revision!=1 or receipt.grant_revision!=1 or receipt.graph_access_epoch!=proof.graph_access_epoch
                or guard.authorization_revision!=1 or proof.graph_epoch>self.scope.graph_epoch.revision
                or receipt.receipt_ref!='owner-issue-committed:'+proof.graph_receipt_digest.removeprefix('sha256:')[:48]):
            raise C09PagedCaptureHold("actual historical Core/Graph Owner issue/guard facts differ")
        wire=self._json(to_wire(proof),meter,ascii=False)
        if guard.authorization_head!='sha256:'+sha256(wire).hexdigest():raise C09PagedCaptureHold("actual final Owner authorization head differs from original issue proof")
        from ..runtime.c09_paged_sql_v2 import c09_canonical_json_size_v3
        self.source.require_arena(c09_canonical_json_size_v3(proof)*32+65536);plain=asdict(proof)
        if graph.owner_values['proof_json']!=plain:raise C09PagedCaptureHold("actual Graph Owner proof JSON differs from Core original")
        proof_json=self._json(plain,meter,ascii=True).decode('ascii')
        locator={name:owner[name] for name in ('operation_id','request_digest','grant_id','grant_digest',
            'graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest')}
        locator['proof_json']=proof_json
        if self.payload['owner_issue_original']!=locator:
            raise C09PagedCaptureHold("actual final payload Owner issue locator differs from captured Graph row")
        self.phase='obligations'
    def advance(self,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_c09_table_shape_v2
        self.source.require_current();self.builder.require_current();result=self.copy();db=self.pair.source
        if self.pair is not self.builder.pair or self.source_original!=self.pair.source_original:
            raise C09PagedCaptureHold("final Core reader lost actual frozen role source")
        if result.phase=='scope':result._scope(meter)
        elif result.phase=='core_source':
            original=self.builder.session._control.maintenance.control.read_build_original_v1(
                operation_id=self.builder.scope.operation_id,kind='capture_role_source_v2_core')
            if original is None or original['details']!=asdict(self.source_original):raise C09PagedCaptureHold("final Core role provenance differs")
            result.phase='fence_row'
        elif result.phase=='fence_row':
            columns=('operation_id','namespace','subject','token','fence_epoch','revision','state','permit','finish_request_id','finish_request_digest','pending')
            with legacy_cell_read_transaction_v2(db):
                shape=read_c09_table_shape_v2(db,'authority_v2_fences',meter=meter)
                if shape.columns!=columns or shape.primary_key_columns!=('operation_id',):raise C09PagedCaptureHold("actual final Core fence schema differs")
                names=tuple(name for name in columns if name!='permit')
                row=meter.read_fixed_row(db,shape.table,names,'operation_id=?',(result.scope.operation_id,))
            if row is None:raise C09PagedCaptureHold("actual final Core fence original absent")
            result.fence=dict(zip(names,row,strict=True));f=result.fence;permit=result.scope.permit
            if ((f['operation_id'],f['namespace'],f['subject'],f['token'],f['fence_epoch'],f['revision'])!=(
                    permit.operation_id,permit.namespace,permit.subject,permit.token,permit.fence_epoch,permit.revision)
                    or f['state']!='finished' or f['pending'] is not None or f['finish_request_id']!='finish:'+permit.operation_id):
                raise C09PagedCaptureHold("actual final historical Core fence state/identity differs")
            result.phase='fence_blob'
        elif result.phase=='fence_blob':
            if result._read_blob('authority_v2_fences','permit','operation_id=?',(result.scope.operation_id,),meter):result.phase='fence_decode'
        elif result.phase=='fence_decode':result._fence_decode(meter)
        elif result.phase=='owner_row':
            columns=('authority_namespace','operation_id','proof_bytes','receipt_bytes','guard_bytes')
            with legacy_cell_read_transaction_v2(db):
                shape=read_c09_table_shape_v2(db,'authority_owner_issue_committed_v1',meter=meter)
                if (shape.columns!=columns or shape.primary_key_columns!=('authority_namespace',)
                        or shape.primary_key_types!=('text',)):raise C09PagedCaptureHold("actual Core Owner issue schema differs")
                row=meter.read_fixed_row(db,shape.table,columns[:2],'authority_namespace=?',(result.scope.authority_namespace,))
            if row!=(result.scope.authority_namespace,self.graph_original.owner_small['operation_id']):raise C09PagedCaptureHold("actual Core Owner issue namespace/op differs")
            result.owner_small=dict(zip(columns[:2],row,strict=True));result.phase='owner_blob'
        elif result.phase=='owner_blob':
            name=('proof_bytes','receipt_bytes','guard_bytes')[result.blob_index]
            if result._read_blob('authority_owner_issue_committed_v1',name,'authority_namespace=?',(result.scope.authority_namespace,),meter):result.phase='owner_decode'
        elif result.phase in {'owner_decode','pending_decode','ticket_decode'}:result._owner_decode(meter)
        elif result.phase=='pending_row':
            columns=('operation_id','authority_namespace','ticket_id','request_digest','operation_bytes','receipt_bytes')
            with legacy_cell_read_transaction_v2(db):
                shape=read_c09_table_shape_v2(db,'authority_owner_issue_pending_v1',meter=meter)
                if (shape.columns!=columns or shape.primary_key_columns!=('operation_id',)
                        or shape.primary_key_types!=('text',)):raise C09PagedCaptureHold("actual Core Owner pending schema differs")
                row=meter.read_fixed_row(db,shape.table,columns[:4],'operation_id=?',(result.owner_small['operation_id'],))
            if row is None or row[:2]!=(result.owner_small['operation_id'],result.scope.authority_namespace):
                raise C09PagedCaptureHold("actual committed Owner issue lacks exact pending origin")
            result.pending_small=dict(zip(columns[:4],row,strict=True));result.phase='pending_blob'
        elif result.phase=='pending_blob':
            name=('operation_bytes','receipt_bytes')[result.blob_index]
            if result._read_blob('authority_owner_issue_pending_v1',name,'operation_id=?',(result.owner_small['operation_id'],),meter):result.phase='pending_decode'
        elif result.phase=='ticket_row':
            columns=('authority_namespace','ticket_id','ticket_bytes','issue_operation_id')
            with legacy_cell_read_transaction_v2(db):
                shape=read_c09_table_shape_v2(db,'authority_owner_claim_tickets_v1',meter=meter)
                if (shape.columns!=columns or shape.primary_key_columns!=('authority_namespace',)
                        or shape.primary_key_types!=('text',)):raise C09PagedCaptureHold("actual Core Owner claim ticket schema differs")
                row=meter.read_fixed_row(db,shape.table,('authority_namespace','ticket_id','issue_operation_id'),
                    'authority_namespace=?',(result.scope.authority_namespace,))
            if row!=(result.scope.authority_namespace,result.pending_small['ticket_id'],result.owner_small['operation_id']):
                raise C09PagedCaptureHold("actual pending Owner issue lacks exact consumed claim ticket")
            result.ticket_small=dict(zip(('authority_namespace','ticket_id','issue_operation_id'),row,strict=True));result.phase='ticket_blob'
        elif result.phase=='ticket_blob':
            if result._read_blob('authority_owner_claim_tickets_v1','ticket_bytes','authority_namespace=?',(result.scope.authority_namespace,),meter):result.phase='ticket_decode'
        elif result.phase=='owner_identity':result._owner_identity(meter)
        elif result.phase=='obligations':
            from .c09_natural_final_history_v4 import emit_natural_final_core_row_obligation_v4,_NaturalFinalCoreRowCommitmentReadV4,_CORE_OBLIGATION_TOKEN_V4
            rows=(('authority_v2_fences',(result.scope.operation_id,)),
                ('authority_owner_issue_committed_v1',(result.scope.authority_namespace,)),
                ('authority_owner_issue_pending_v1',(result.owner_small['operation_id'],)),
                ('authority_owner_claim_tickets_v1',(result.scope.authority_namespace,)))
            if result.obligation_index==len(rows):result.complete=True;result.source_qualified_complete=True
            else:
                table,key=rows[result.obligation_index]
                if result.obligation_reader is None:
                    result.obligation_reader=_NaturalFinalCoreRowCommitmentReadV4(_CORE_OBLIGATION_TOKEN_V4,result.builder,table,key,result.source.arena)
                    result.source.require_arena();return result
                if not result.obligation_reader.complete:
                    result.obligation_reader=result.obligation_reader.advance(meter);result.source.require_arena();return result
                row=emit_natural_final_core_row_obligation_v4(result.builder,source=result.source,table=table,key=key,
                    operation_id=result.scope.operation_id,fence_token=result.scope.permit.token,meter=meter,row_reader=result.obligation_reader)
                result.required_core_rows+= (row,)
                result.builder.basis.record_source_qualified_natural_final_core_rows_v4(result,meter=meter)
                result.obligation_index+=1;result.obligation_reader=None
        else:raise C09PagedCaptureHold("unknown actual final Core/Owner original phase")
        self.source.require_current();self.source.require_arena();return result
