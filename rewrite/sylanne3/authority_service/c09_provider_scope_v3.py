"""Verified model provider scopes retained in the actual protected Control originals."""
from __future__ import annotations
from hashlib import sha256
from weakref import WeakSet
import json
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2

_SCOPE='sylanne3.c09.model-provider-scope.v3'
_COMPLETE='sylanne3.c09.provider-scopes-complete.v3'
_ISSUER=object()
_PROOFS=WeakSet()


def provider_scope_kind_v3(call_id):return 'provider_scope_original_v3_'+sha256(call_id.encode('utf8')).hexdigest()


class VerifiedModelProviderScopeV3:
    def __init__(self,token,core,business,seal,original,intent,commitment):
        if token is not _ISSUER:raise AuthorityUnavailable('actual verified model intent provider issuer required')
        self.core,self.business,self.seal,self.original=core,business,seal,original
        self.provider_id,self.provider_config_digest=intent.provider_id,intent.provider_config_digest
        self.source_ledger_commitment=commitment;self.used=False;_PROOFS.add(self)
    def require_for(self,producer,original,core,graph):
        from .c09_paged_recovery_facts_v2 import C09PagedRecoveryFactsProducerV2
        if (self not in _PROOFS or self.used or type(producer) is not C09PagedRecoveryFactsProducerV2
                or self.core is not core or self.business is not graph or self.original is not original
                or producer.source != self.seal or not core.in_transaction or not graph.in_transaction
                or producer.scope.operation_id != original.operation_id or original.provider_id != self.provider_id
                or self.source_ledger_commitment not in original.source_row_commitments):
            raise AuthorityUnavailable('actual provider scope proof left its verified source interval')
        root=current_c09_sql_meter_v2()
        connections=producer._natural_model_connections_v3
        if (connections is None or connections[:2]!=(core,graph) or connections[2].parent is not root):
            raise AuthorityUnavailable('actual provider scope proof crossed its current frozen source/root reservation')
        producer.session.require_current();producer.pair.require_current()
        return self


def issue_verified_model_provider_scope_v3(*,token,core_db,business,seal,original,intent,source_ledger_commitment):
    from .c09_model_budget_original_v1 import _MODEL_PROVIDER_SCOPE_ISSUER_V3
    if token is not _MODEL_PROVIDER_SCOPE_ISSUER_V3:
        raise AuthorityUnavailable('only the complete actual model original reader may issue provider scope')
    return VerifiedModelProviderScopeV3(_ISSUER,core_db,business,seal,original,intent,source_ledger_commitment)


def retain_verified_model_provider_scope_v3(producer,proof,original,*,core,graph):
    if type(proof) is not VerifiedModelProviderScopeV3:
        raise AuthorityUnavailable('actual private verified model provider scope required')
    proof.require_for(producer,original,core,graph)
    details=dict(schema=_SCOPE,scope_digest=producer.scope.scope_digest,authority_id=original.authority_id,
        installation_id=original.installation_id,namespace=original.namespace,operation_id=original.operation_id,
        call_id=original.call_id,model_original_digest=original.original_digest,provider_id=proof.provider_id,
        provider_config_digest=proof.provider_config_digest,source_ledger_commitment=proof.source_ledger_commitment,
        source_execution_seal_digest=proof.seal.seal_digest)
    result=producer.control.record_build_original_v1(operation_id=original.operation_id,
        kind=provider_scope_kind_v3(original.call_id),details=details)
    proof.used=True
    return result


def read_provider_scope_for_model_v3(control,model,*,meter):
    original=control.read_build_original_v1(operation_id=model.operation_id,kind=provider_scope_kind_v3(model.call_id))
    if original is None:raise AuthorityUnavailable('actual historical model provider configuration original is absent')
    details=original['details']
    fields={'schema','scope_digest','authority_id','installation_id','namespace','operation_id','call_id',
        'model_original_digest','provider_id','provider_config_digest','source_ledger_commitment','source_execution_seal_digest'}
    if (set(details)!=fields or details['schema']!=_SCOPE or details['authority_id']!=model.authority_id
            or details['installation_id']!=model.installation_id or details['namespace']!=model.namespace
            or details['operation_id']!=model.operation_id or details['call_id']!=model.call_id
            or details['model_original_digest']!=model.original_digest or details['provider_id']!=model.provider_id
            or details['source_ledger_commitment'] not in model.source_row_commitments):
        raise AuthorityUnavailable('actual historical provider scope differs from its complete model source original')
    if original['operation_id']!=model.operation_id or original['original_kind']!=provider_scope_kind_v3(model.call_id):
        raise AuthorityUnavailable('actual protected provider scope locator differs')
    return original


class _ProviderScopeCoverageReadV3:
    def __init__(self,scope,model_complete_digest):
        self.scope,self.model_complete_digest=scope,model_complete_digest
        self.after='';self.count=0
        self.root=canonical_digest((_COMPLETE,scope.scope_digest,model_complete_digest))
        self.complete=False
    def next(self,db,meter):
        from .c09_selected_history_v3 import _read_one
        return _read_one(db,'SELECT item_key FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? '
            'AND item_key COLLATE BINARY>? ORDER BY item_key COLLATE BINARY LIMIT 1',(self.scope.scope_digest,'model',self.after),meter)
    def observe(self,model,original):
        self.count+=1;self.after=model.call_id
        self.root=canonical_digest((self.root,self.count,model.call_id,model.original_digest,original['original_digest']))
    def details(self):
        return dict(schema=_COMPLETE,scope_digest=self.scope.scope_digest,model_complete_digest=self.model_complete_digest,
            record_count=self.count,ordered_root=self.root,last_call_id=self.after,
            eof_digest=canonical_digest((_COMPLETE,self.scope.scope_digest,self.model_complete_digest,self.count,self.after,self.root)),complete=True)


def advance_capture_provider_scope_complete_v3(producer,*,meter):
    from .c09_paged_recovery_facts_v2 import C09PagedRecoveryFactsProducerV2,model_budget_original_from_wire_v1
    from .c09_selected_history_v3 import _read_one,_bounded
    if type(producer) is not C09PagedRecoveryFactsProducerV2 or meter is not current_c09_sql_meter_v2():
        raise AuthorityUnavailable('actual installed recovery provider coverage quantum required')
    producer.session.require_current();producer.pair.require_current()
    if not producer._verification.get('model',{}).get('done'):
        raise AuthorityUnavailable('actual provider scope census requires complete authenticated model stream EOF')
    reader=getattr(producer,'_provider_scope_coverage_v3',None)
    if reader is None:
        row=_bounded(producer.pair.candidate,meter).execute('SELECT locator_json FROM c09_recovery_family_seals_v2 WHERE scope_digest=? AND family=?',
            (producer.scope.scope_digest,'model')).fetchone()
        if row is None:raise AuthorityUnavailable('actual sealed model descriptor is absent')
        from .c09_paged_recovery_facts_v2 import c09_paged_value_from_wire_v2,C09SealedStreamLocatorV2
        locator=c09_paged_value_from_wire_v2(json.loads(row[0]),C09SealedStreamLocatorV2)
        reader=_ProviderScopeCoverageReadV3(producer.scope,locator.complete.digest)
        reader.expected_count=locator.complete.record_count;producer._provider_scope_coverage_v3=reader
        return False
    if reader.complete:return True
    key=reader.next(producer.pair.candidate,meter)
    if key is None:
        if reader.count!=reader.expected_count:raise AuthorityUnavailable('actual provider scope EOF omits a sealed model')
        producer.control.record_build_original_v1(operation_id=producer.scope.operation_id,kind='provider_scope_complete_v3',details=reader.details())
        reader.complete=True;return True
    row=_bounded(producer.pair.candidate,meter).execute('SELECT value_json FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key=?',
        (producer.scope.scope_digest,'model',key[0])).fetchone()
    model=model_budget_original_from_wire_v1(json.loads(row[0]))
    original=read_provider_scope_for_model_v3(producer.control,model,meter=meter)
    reader.observe(model,original);return False


class SelectedProviderScopeProofV3:
    def __init__(self,token,reader,original):
        if token is not _ISSUER or not reader.complete:raise AuthorityUnavailable('actual complete selected provider scope issuer required')
        self.basis,self.original,self.details=reader.basis,original,original['details']
    def require_current(self,*,meter):
        self.basis.require_current(meter=meter)
        original=self.basis.control.read_build_original_v1(operation_id=self.basis.prepared['operation_id'],kind='provider_scope_complete_v3')
        if original!=self.original:raise AuthorityUnavailable('actual immutable provider scope completion changed')
        return self


class SelectedProviderScopeReadV3:
    def __init__(self,basis,scope,completion):
        self.basis,self.scope,self.completion=basis,scope,completion
        self.reader=_ProviderScopeCoverageReadV3(scope,completion.model_stream.complete.digest)
        self.original=None;self.complete=False;self.proof=None
    def advance(self,meter):
        from .c09_selected_history_v3 import _bounded
        from .c09_model_budget_original_v1 import model_budget_original_from_wire_v1
        self.basis.require_current(meter=meter)
        if self.complete:return True
        if self.original is None:
            self.original=self.basis.control.read_build_original_v1(operation_id=self.basis.prepared['operation_id'],kind='provider_scope_complete_v3')
            if self.original is None or self.original['original_digest']!=self.basis.prepared['provider_scope_complete_original_digest']:
                raise AuthorityUnavailable('actual selected provider scope completion original is absent or differs from PREPARED')
            return False
        with self.basis.read_database('graph',meter=meter) as db:
            key=self.reader.next(db,meter)
            if key is not None:
                row=_bounded(db,meter).execute('SELECT value_json FROM c09_recovery_items_v2 WHERE scope_digest=? AND family=? AND item_key=?',
                    (self.scope.scope_digest,'model',key[0])).fetchone()
                model=model_budget_original_from_wire_v1(json.loads(row[0]))
                original=read_provider_scope_for_model_v3(self.basis.control,model,meter=meter)
                self.reader.observe(model,original);return False
        if self.reader.count!=self.completion.model_stream.complete.record_count or self.reader.details()!=self.original['details']:
            raise AuthorityUnavailable('actual provider scope completion lacks full model-source count/root/EOF')
        self.complete=True;self.proof=SelectedProviderScopeProofV3(_ISSUER,self,self.original);return True
