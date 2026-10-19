"""Current consumption of a D13 block from its real settled paid original.

W01 reopens its immutable authenticated result read and signed cost originals.
Authority additionally joins those bytes to its independently owned model
ledger. Neither path calls a provider or repurposes the D09 review verifier.
"""
from __future__ import annotations

from dataclasses import asdict, replace
import json
import sqlite3
from weakref import WeakKeyDictionary

from ..graph_types import AtomKey, Owner
from ..model_broker.d13_precompression import (
    D13PrecompressionInstallationV1, freeze_d13_precompression_request_v1,
    issue_unadmitted_d13_model_request_v1, parse_d13_precompression_output_v1,
)
from ..runtime_contracts import canonical_digest,canonical_serialize
from .contract import AuthorityUnavailable


class InstalledD13PaidBlockVerifierV1:
    def __init__(self, db, *, installation, resource_issuer, budget_issuer,
                 authority_store=None, max_slots=64):
        from ..runtime.issuers import D02ResourceIssuer, D11BudgetGrantIssuer
        from .v2_model_egress_store import AuthorityV2ModelEgressStore
        if (type(db) is not sqlite3.Connection
                or type(installation) is not D13PrecompressionInstallationV1
                or type(resource_issuer) is not D02ResourceIssuer
                or not isinstance(budget_issuer, D11BudgetGrantIssuer)
                or authority_store is not None and type(authority_store) is not AuthorityV2ModelEgressStore
                or type(max_slots) is not int or not 1 <= max_slots <= 64):
            raise ValueError("installed D13 paid original authorities required")
        self._db, self._installation = db, installation
        self._resource, self._budget = resource_issuer, budget_issuer
        self._authority, self._max_slots = authority_store, max_slots

    def _current_window(self, window):
        from ..runtime.d13_completed_paid_read_v3 import current_completed_d13_reader_v3
        completed=current_completed_d13_reader_v3(self._db)
        if completed is not None:return completed.reader.current_window
        from ..runtime.d13_current_window import read_current_d13_window_for_authority_v1
        return read_current_d13_window_for_authority_v1(self._db, window.namespace,
            AtomKey.from_token(window.scene_ref.ref).owner.subject, window.conversation_ref,
            self._max_slots, window.trusted_utc, expected_activation_generation=window.activation_epoch)

    def _stored_block(self, candidate, window, original, evidence, settlement):
        from ..runtime.d13_completed_paid_read_v3 import current_completed_d13_reader_v3
        completed=current_completed_d13_reader_v3(self._db)
        if completed is not None:
            if (window!=completed.reader.current_window or original!=completed.saved.original
                    or evidence!=completed.saved.evidence or settlement!=completed.saved.settlement
                    or candidate.block_ref!=completed.reader.job[13]):
                raise AuthorityUnavailable("D13 actual paid verifier crossed completed original material")
            return completed.block
        from ..domains.d13.provider import _block_from_graph_value
        key = AtomKey(Owner("persona", *window.namespace.as_tuple), "d13.compressed_turn_block.v2", candidate.block_ref)
        row = self._db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (row is None or row[1] != 1 or self._db.execute("SELECT 1 FROM graph_d13_retirements_v1 "
                "WHERE bot=? AND persona=? AND block_token=?", window.namespace.as_tuple + (key.token,)).fetchone()):
            return None
        return _block_from_graph_value(json.loads(row[0]))

    def verify_current_paid_model_block_v2(self, candidate, *, plan, window):
        try:
            return self._verify(candidate, plan, window)
        except Exception as error:
            from .current_authority_graph_read_v3 import (AuthorityGraphAttachmentRequiredV3,
                AuthorityNaturalOriginalRequiredV3)
            from .contract import AuthorityUnavailable
            from ..runtime.c09_paged_sql_v2 import C09PagedCaptureHold
            if isinstance(error,(AuthorityGraphAttachmentRequiredV3,AuthorityNaturalOriginalRequiredV3,
                    AuthorityUnavailable,C09PagedCaptureHold)):
                raise
            return False

    def _verify(self, candidate, plan, window):
        from ..domains.d13.precompression import compile_extractive_model_output, EXTRACTIVE_MODEL_VERSION
        from ..domains.d13.provider import _block_from_graph_value, retirement_reason
        from ..runtime.d13_paid_intent_original_v1 import (
            load_d13_paid_intent_original_v1, read_d13_paid_call_original_v1, PAID_WORK_KIND,
        )
        from ..runtime.d13_paid_coordinator_v1 import (
            read_paid_d13_evidence_in_transaction_v1, read_paid_d13_settlement_in_transaction_v1,
        )
        from ..runtime.jobs import get_job
        from ..runtime.d11_types import job_graph_write
        from .v2_worker_model_result_contract import d13_paid_read_attempt_id_v1
        db = self._db
        if not db.in_transaction or candidate.compiler_version != EXTRACTIVE_MODEL_VERSION or candidate.status != "candidate":
            return False
        current = self._current_window(window)
        if current != window or retirement_reason(replace(candidate, status="standby"), plan, window) is not None:
            return False
        prepared=None
        if getattr(self,'_authority_collection',None)is not None:
            work,_cap=self._authority_collection
            from ..runtime.installed_d13_natural_frame_v6 import require_authority_derived_blocks_reader_v6
            prepared=require_authority_derived_blocks_reader_v6(work).paid_requests.get(plan.job_ref)
            if type(prepared)is not PreparedD13PaidRequestEOFV3:
                raise AuthorityUnavailable('actual D13 Paid request EOF was not prepared')
            materials=prepared.require_originals_v3(self,plan,window)
            if materials is None:return False
            original,frozen,call,request=materials
            loaded=(original,frozen)
        else:loaded=load_d13_paid_intent_original_v1(db,window.namespace,plan.job_ref)
        if loaded is None:return False
        original,frozen=loaded
        current_turns=(freeze_d13_precompression_request_v1(window,plan,self._installation).turns
            if prepared is None else prepared.current_turns)
        if (frozen.plan!=plan or frozen.installation!=self._installation
                or window.trusted_utc<frozen.window.trusted_utc
                or window.trusted_utc>=original.binding.expires_at_utc or current_turns!=frozen.turns):
            return False
        saved_call=(read_d13_paid_call_original_v1(db,window.namespace,plan.job_ref)
            if prepared is None else (call,request))
        if saved_call is None:return False
        call,request=saved_call
        if (call.binding_digest!=original.binding.binding_digest or call.intent_original_digest!=original.original_digest
                or prepared is None and request!=issue_unadmitted_d13_model_request_v1(request.envelope,frozen,
                    call_id=original.binding.call_id,timeout_seconds=request.timeout_seconds,privacy_tier=request.privacy_tier)):
            return False
        evidence = read_paid_d13_evidence_in_transaction_v1(db, original, call)
        if evidence is None:
            return False
        settlement = read_paid_d13_settlement_in_transaction_v1(db, original, evidence)
        if settlement is None or settlement.receipt.status != "settled":
            return False
        read, fact = evidence.read, evidence.fact
        intent, binding = fact.intent, original.binding
        read.require_original_intent(intent)
        from .d13_source_identity_v1 import d13_original_source_identity_v1
        source_ids, source_revisions, access_revisions = d13_original_source_identity_v1(frozen)
        if (intent.source_refs != source_ids or intent.source_revisions != source_revisions
                or intent.access_revisions != access_revisions
                or read.request.purpose != "d13_precompress_paid"
                or read.request.namespace != window.namespace
                or read.request.binding_digest != binding.binding_digest
                or read.request.installation_id != self._installation.installation_id
                or read.request.consumer_operation_id != "d13-adopt:" + binding.binding_digest
                or not any(read.request.read_attempt_id == d13_paid_read_attempt_id_v1(
                    read.request.consumer_operation_id, n) for n in range(1, 65))
                or intent.binding_digest != binding.binding_digest
                or intent.request_digest != call.request_digest
                or intent.call_id != binding.call_id or intent.job_id != binding.job_ref
                or intent.operation_id != binding.original_operation_id
                or intent.acquire_operation_id != binding.original_operation_id
                or intent.budget_reservation_operation_id != original.budget_operation_id
                or intent.budget_reservation_digest != original.budget_reservation_digest
                or dict(intent.budget_ceiling) != original.ceiling
                or intent.worker_fence != call.worker_fence
                or (intent.provider_id, intent.model_id, intent.provider_config_digest,
                    intent.max_output_tokens) != (self._installation.provider_id,
                    self._installation.model_id, self._installation.provider_config_digest,
                    self._installation.max_output_tokens)
                or fact.recovery.state != "observed" or fact.recovery.content_erased
                or read.terminal_receipt != fact.receipt
                or fact.receipt.finish_digest != "sha256:" + read.observation.digest):
            return False
        job = get_job(db, plan.job_ref)
        if (job.work_kind != PAID_WORK_KIND or job.phase != "completed" or job.cancel_epoch != 0
                or (job.bot_id, job.persona_id) != window.namespace.as_tuple
                or job.fence != call.worker_fence or job.result_ref != candidate.block_ref
                or job.operation_id != binding.original_operation_id or job.budget_ref != intent.budget_lease_id
                or job.continuation.get("binding_digest") != binding.binding_digest):
            return False
        job_write = job_graph_write(job)
        from .current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
        handled,job_row=read_bound_authority_graph_attachment_v3(db,table='graph_atoms',columns=('value','valid'),
            key_columns=('token',),key=(job_write.key.token,))
        from ..runtime.d13_completed_paid_read_v3 import current_completed_d13_reader_v3
        completed=current_completed_d13_reader_v3(db)
        if completed is not None:
            if job!=completed.job:
                raise AuthorityUnavailable("D13 verifier actual completed job original differs")
            job_row=(canonical_serialize(job_write.value),1)
        elif not handled:
            job_row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_write.key.token,)).fetchone()
        if job_row is None or job_row[1] != 1 or json.loads(job_row[0]) != job_write.value:
            return False
        if completed is not None:
            quote,grant,reservation,receipt=completed.accounting_v3(self)
        else:
            quote = self._resource.original_signed_quote(db, original.quote_id, original.quote_version)
            grant, _signature = self._budget.signed_budget_grant_at_version(db, job.budget_ref, original.grant_version)
            reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (job.budget_ref, original.budget_operation_id)).fetchone()
            receipt = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
                "AND operation_id=? AND phase='settle'", window.namespace.as_tuple + (original.budget_operation_id,)).fetchone()
        if (canonical_digest(quote) != original.quote_digest or canonical_digest(grant) != original.grant_digest
                or quote.work_kind != PAID_WORK_KIND or quote.operation_id != original.budget_operation_id
                or quote.parent_budget_lease_ref != job.budget_ref or dict(quote.ceiling) != original.ceiling
                or grant.grant_id != original.grant_id or PAID_WORK_KIND not in grant.allowed_work_kinds
                or (quote.bot_id, quote.persona_id) != window.namespace.as_tuple
                or (grant.bot_id, grant.persona_id) != window.namespace.as_tuple
                or reservation is None or reservation[0] != original.budget_reservation_digest
                or json.loads(reservation[1]) != original.ceiling or reservation[2] != "settled"
                or receipt is None or json.loads(receipt[0]) != asdict(settlement.receipt)):
            return False
        stored = self._stored_block(candidate, window, original, evidence, settlement)
        if stored is None or stored.status not in {"standby", "active"} or replace(stored, status="candidate") != candidate:
            return False
        result = json.loads(read.observation.result_json)
        if type(result) is not dict or set(result) != {"text"} or type(result["text"]) is not str:
            return False
        parsed = parse_d13_precompression_output_v1(result["text"], frozen)
        if compile_extractive_model_output(window,plan,parsed.model_text,_prepared_paid_eof_v3=prepared) != candidate:
            return False
        if completed is not None:
            completed.require_terminal_v3(fact,read)
        elif self._authority is not None:
            # Authority owns this store and lock; W01 never supplies a "verified"
            # boolean. Holding only its read lock here performs no RPC or writes.
            store = self._authority
            with store._lock:
                opened = not store._db.in_transaction
                if opened:
                    store._db.execute("BEGIN")
                try:
                    recovery = store._read(store._db, binding.call_id)
                    if recovery is None or recovery != fact.recovery or recovery.intent != intent:
                        return False
                    admission, report_digest, terminal = store.read_admission_locked(store._db, intent)
                    from .v2_fence_store import AuthorityV2FenceStore
                    fence_row = AuthorityV2FenceStore._row(store._db, intent.operation_id)
                    if fence_row is None or fence_row[6] != "finished" or fence_row[10] is not None:
                        return False
                    permit = AuthorityV2FenceStore._permit(fence_row)
                    if (permit.operation != "model_egress"
                            or (permit.authority_id, permit.namespace, permit.subject,
                                permit.operation_id, permit.token, permit.fence_epoch, permit.revision,
                                permit.generation, canonical_digest(asdict(permit.pinned_anchor))) !=
                               (intent.authority_id, intent.namespace, intent.subject, intent.operation_id,
                                intent.fence_token, intent.fence_epoch, intent.fence_revision,
                                intent.authority_activation_generation, intent.anchor_digest)
                            or fence_row[8:10] != (intent.call_id, fact.receipt.finish_digest)):
                        return False
                    if (admission != fact.admission or terminal != fact.receipt
                            or report_digest != terminal.report_digest
                            or not store.is_fence_bound_locked(store._db, intent)
                            or store._read_observation_locked(store._db, intent) != read.observation):
                        return False
                finally:
                    if opened:
                        store._db.execute("ROLLBACK")
        return True


def build_installed_d13_paid_block_verifier_v1(db, *, installation,
        resource_issuer, budget_issuer, authority_store=None, max_slots=64):
    if installation is None:
        return None
    return InstalledD13PaidBlockVerifierV1(db, installation=installation,
        resource_issuer=resource_issuer, budget_issuer=budget_issuer,
        authority_store=authority_store, max_slots=max_slots)

_PAID_EOF_ISSUER_V3=object()
_PAID_EOFS_V3=WeakKeyDictionary()
_PAID_FROZEN_EOFS_V3=WeakKeyDictionary()
_PAID_MODEL_REQUESTS_V3={}
_PAID_FINAL_EOFS_V3=WeakKeyDictionary()


class PreparedD13PaidRequestEOFV3:
    """Replay material from two actual immutable originals in the same Authority Work."""
    def __init__(self,issuer,work,*,verifier,plan,window):
        from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
        if issuer is not _PAID_EOF_ISSUER_V3 or type(work)is not AuthorityGraphReadWorkV3:
            raise ValueError('actual independently issued D13 Paid EOF reader required')
        work._actual()
        from ..runtime.installed_d13_natural_frame_v6 import require_authority_derived_blocks_reader_v6
        from .d13_authority_model_source_v3 import require_d13_authority_paid_eof_v3
        authority=require_d13_authority_paid_eof_v3(work,verifier,plan,window)
        if not authority:
            reader=require_authority_derived_blocks_reader_v6(work)
            if reader.verifier is not verifier or reader.active_plan is not plan or reader.collection.window is not window:
                raise ValueError('D13 Paid original must be prepared for its actual current candidate')
        self.work,self.verifier,self.plan,self.window=work,verifier,plan,window
        self.operation,self.scope=work.operation,work.scope
        self.phase='columns';self.complete=False;self.missing=False
        self.intent_column=self.call_column=self.nested=self.comparison=None
        self.original=self.frozen=self.call=self.request=None
        self.intent_data=self.call_data=self.frozen_data=self.request_data=None
        self.jobs=[];self.digests={};self.current_turns=None;self.request_fields=None
        _PAID_EOFS_V3[self]=(work,verifier,plan,window,self.operation,self.scope)
    def _actual(self):
        from .contract import AuthorityUnavailable
        if (_PAID_EOFS_V3.get(self)!=(self.work,self.verifier,self.plan,self.window,self.operation,self.scope)
                or self.work.operation is not self.operation or self.work.scope is not self.scope):
            raise AuthorityUnavailable('D13 Paid EOF reader lost its actual Work/operation/scope')
        self.work._actual()
    def _comparison(self,value,target=None):
        from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
        return _CanonicalComparisonV3(value,target,operation=self.operation)
    def _columns(self):
        from .current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
        from ..runtime.d13_paid_intent_original_v1 import D13PaidIntentOriginalV1,D13PaidCallOriginalV1
        from dataclasses import fields,asdict
        work=self.work;ns=work.namespace;job=self.plan.job_ref
        columns=('operation_id','original_json','original_digest')
        _,intent=read_bound_authority_graph_attachment_v3(work.db,table='graph_d13_paid_intent_originals_v1',
            columns=columns,key_columns=('bot','persona','job_ref'),key=(*ns.as_tuple,job))
        if intent is None:self.missing=self.complete=True;return
        request=('graph_d13_paid_intent_originals_v1',columns,('bot','persona','job_ref'),(*ns.as_tuple,job))
        intent_column=work.attachments[request].json_columns['original_json']
        columns=('call_id','original_json','original_digest')
        _,call=read_bound_authority_graph_attachment_v3(work.db,table='graph_d13_paid_call_originals_v1',
            columns=columns,key_columns=('bot','persona','job_ref'),key=(*ns.as_tuple,job))
        if call is None:self.missing=self.complete=True;return
        request=('graph_d13_paid_call_originals_v1',columns,('bot','persona','job_ref'),(*ns.as_tuple,job))
        call_column=work.attachments[request].json_columns['original_json']
        data=intent_column.require_v3(work);call_data=call_column.require_v3(work)
        if (type(data)is not dict or set(data)!={field.name for field in fields(D13PaidIntentOriginalV1)}
                or data['namespace']!=asdict(ns) or type(call_data)is not dict
                or set(call_data)!={field.name for field in fields(D13PaidCallOriginalV1)}
                or call_data['namespace']!=asdict(ns) or call_data['job_ref']!=job):
            raise ValueError('actual D13 Paid original wire fields/namespace/job differ')
        self.intent_column,self.call_column=intent_column,call_column
        self.intent_row,self.call_row=intent,call
        self.intent_data,self.call_data=data,call_data
        from .current_authority_graph_read_v3 import _AuthorityCanonicalTextReadV3
        self.nested=_AuthorityCanonicalTextReadV3(work,data['frozen_json']);self.phase='frozen_json'
    def _frozen_values(self):
        from ..model_broker import d13_precompression as model
        from dataclasses import fields
        data=self.frozen_data
        if type(data)is not dict or set(data)!={f.name for f in fields(model.FrozenD13PrecompressionRequestV1)}:
            raise ValueError('actual complete D13 frozen fields differ')
        window,plan=model._d13_typed_window_plan_v1(data)
        installation=model.D13PrecompressionInstallationV1(**data['installation'])
        turns=model._planned_turns_shape_v1(window,plan)
        messages=tuple(model.D13ModelMessageV1(**row)for row in data['messages'])
        expected_messages=(model.D13ModelMessageV1('system',model.SYSTEM_MESSAGE),model.D13ModelMessageV1('user',data['canonical_input']))
        if (messages!=expected_messages or data['output_schema']!=model.EXTRACTIVE_OUTPUT_SCHEMA
                or data['template_version']!=model.TEMPLATE_VERSION):
            raise ValueError('actual D13 frozen message/template/output schema changed')
        self.frozen=model.FrozenD13PrecompressionRequestV1(**{**data,'window':window,'plan':plan,
            'turns':turns,'installation':installation,'messages':messages})
        from ..domains.d13.precompression import _fingerprint_value_v1
        self.jobs=[('fingerprint',self._comparison(_fingerprint_value_v1(window,turns))),
            ('read_closure',self._comparison(model._d13_read_closure_value_v1(window)))]
        self.phase='frozen_jobs'
    def _next_frozen_jobs(self):
        from ..model_broker import d13_precompression as model
        from dataclasses import asdict
        f=self.frozen
        if not hasattr(self,'payload_jobs'):
            self.payload_jobs=True
            self.jobs=[('input',self._comparison(model._d13_frozen_payload_value_v1(f.window,f.plan,f.turns,f.read_closure_digest),f.canonical_input)),
                ('messages_wire',self._comparison([asdict(m)for m in f.messages],f.messages_wire)),
                ('wire',self._comparison(model._d13_frozen_wire_value_v1(f.installation,f.messages),f.canonical_wire)),
                ('full_frozen',self._comparison(asdict(f),self.intent_data['frozen_json']))]
            return
        from ..runtime.d13_paid_intent_original_v1 import D13PaidIntentOriginalV1,D13PaidCallOriginalV1
        from ..domains.d13.paid_lifecycle import D13PaidOriginalBindingV1,_paid_original_binding_value_v1
        data=self.intent_data;binding=D13PaidOriginalBindingV1(**data['binding'])
        expected=_paid_original_binding_value_v1(f,original_operation_id=binding.original_operation_id,call_id=binding.call_id)
        if (binding!=D13PaidOriginalBindingV1(**expected,binding_digest=canonical_digest({'schema':'d13.paid_original_binding.v1',**expected}))
                or self.intent_row[0]!=binding.original_operation_id or binding.job_ref!=self.plan.job_ref
                or f.window.namespace!=self.work.namespace):
            raise ValueError('actual D13 frozen binding/namespace/job changed')
        count=None if data['exact_count']is None else model.D13ExactTokenCountV1(**data['exact_count'])
        self.original=D13PaidIntentOriginalV1(**{**data,'namespace':self.work.namespace,'binding':binding,'exact_count':count})
        self.call=D13PaidCallOriginalV1(**{**self.call_data,'namespace':self.work.namespace})
        _PAID_FROZEN_EOFS_V3[self]=(self.work,self.operation,self.scope,f,self.intent_column,
            tuple(sorted(self.digests.items())))
        if model.gate_d13_exact_token_count_v1(f,count,_prepared_paid_eof_v3=self).status!='ready':
            raise ValueError('actual D13 frozen optional count changed')
        from dataclasses import fields
        original_fields={v.name:getattr(self.original,v.name)for v in fields(D13PaidIntentOriginalV1)if v.name!='original_digest'}
        call_fields={v.name:getattr(self.call,v.name)for v in fields(D13PaidCallOriginalV1)if v.name!='original_digest'}
        self.current_turns=model._planned_turns_shape_v1(self.window,self.plan)
        from ..domains.d13.precompression import _fingerprint_value_v1
        self.jobs=[('intent_digest',self._comparison({'schema':'d13.paid_intent_original.v1',**original_fields})),
            ('call_digest',self._comparison({'schema':'d13.paid_call_original.v1',**call_fields})),
            ('current_fingerprint',self._comparison(_fingerprint_value_v1(self.window,self.current_turns)))]
        self.phase='original_jobs'
    def advance(self,*,meter):
        self._actual();self.work.require_current(meter=meter)
        if self.complete:return self
        if self.phase=='columns':self._columns();return self
        if self.phase in ('frozen_json','request_json'):
            if not self.nested.advance_v3(meter):return self
            if self.phase=='frozen_json':
                self.frozen_data=self.nested.value;self.nested=None;self._frozen_values()
            else:
                self.request_data=self.nested.value;self.nested=None;self._request_values()
            return self
        if self.phase in ('frozen_jobs','original_jobs','request_digest'):
            if meter.available_bytes<196608:return self
            name,comparison=self.jobs[0]
            if not comparison.advance(meter):return self
            digest=comparison.digest
            expected={'fingerprint':self.frozen.plan.input_digest,'read_closure':self.frozen.read_closure_digest,
                'input':self.frozen.digest,'wire':self.frozen.wire_digest,
                'intent_digest':self.original.original_digest if self.original else None,
                'call_digest':self.call.original_digest if self.call else None,
                'current_fingerprint':self.plan.input_digest,
                'request_digest':self.call.request_digest if self.call else None}.get(name)
            if expected is not None and expected!=digest:raise ValueError('actual D13 Paid complete EOF digest differs: '+name)
            self.digests[name]=digest;self.jobs.pop(0)
            if self.jobs:return self
            if self.phase=='frozen_jobs':self._next_frozen_jobs();return self
            if self.phase=='original_jobs':
                if self.intent_row[2]!=self.original.original_digest or self.call_row[2]!=self.call.original_digest:
                    raise ValueError('actual immutable D13 Paid stored original digest differs')
                from .current_authority_graph_read_v3 import _AuthorityCanonicalTextReadV3
                self.nested=_AuthorityCanonicalTextReadV3(self.work,self.call_data['request_json']);self.phase='request_json';return self
            _register_paid_model_request_v3(self.request,self)
            self.complete=True
            _PAID_FINAL_EOFS_V3[self]=(self.work,self.operation,self.scope,self.original,self.frozen,self.call,
                self.request,self.current_turns,tuple(sorted(self.digests.items())))
            return self
        raise ValueError('unregistered actual D13 Paid EOF preparation phase')
    def _request_values(self):
        from ..model_broker.d13_precompression import _d13_model_request_fields_v1
        from ..model_broker.broker import ModelCallRequest
        from .v2_model_egress_wire import command_envelope_from_wire_v2
        from dataclasses import fields
        raw=self.request_data
        if type(raw)is not dict or set(raw)!={field.name for field in fields(ModelCallRequest)}:
            raise ValueError('actual immutable D13 model request fields differ')
        envelope=command_envelope_from_wire_v2(raw['envelope'])
        expected=_d13_model_request_fields_v1(envelope,self.frozen,call_id=self.original.binding.call_id,
            timeout_seconds=raw['timeout_seconds'],privacy_tier=raw['privacy_tier'])
        expected_raw={**expected,'envelope':raw['envelope'],'required_capabilities':sorted(expected['required_capabilities'])}
        if expected_raw!=raw or self.call_row[0]!=expected['call_id']:
            raise ValueError('actual paid call request differs from its full frozen recipe')
        from types import MappingProxyType
        self.request_fields={**expected,'payload':MappingProxyType(dict(expected['payload']))}
        self.phase='request_ctor'
        self.request=ModelCallRequest(**expected,_prepared_payload_eof_v3=self)
        self.jobs=[('request_digest',self._comparison(_paid_request_digest_value_v3(self.request)))]
        self.phase='request_digest'
    def require_frozen_v3(self,frozen):
        self._actual();facts=_PAID_FROZEN_EOFS_V3.get(self)
        if facts is None or facts[:5]!=(self.work,self.operation,self.scope,frozen,self.intent_column):
            raise ValueError('actual D13 Paid frozen full EOF required')
        return dict(facts[5])
    def _require_final_v3(self):
        self._actual()
        facts=_PAID_FINAL_EOFS_V3.get(self)
        if facts!=(self.work,self.operation,self.scope,self.original,self.frozen,self.call,
                self.request,self.current_turns,tuple(sorted(self.digests.items()))):
            raise AuthorityUnavailable('actual D13 Paid final EOF facts changed')
        return facts
    def require_current_fingerprint_v3(self,window,turns):
        self._actual()
        if not self.complete or self.missing or window is not self.window or turns!=self.current_turns:
            raise AuthorityUnavailable('actual D13 Paid current turn/fingerprint EOF required')
        self._require_final_v3()
        return self.digests['current_fingerprint']
    def require_originals_v3(self,verifier,plan,window):
        self._actual()
        if not self.complete or verifier is not self.verifier or plan!=self.plan or window is not self.window:
            raise ValueError('actual D13 Paid original replay preparation required')
        if self.missing:return None
        self._require_final_v3();self.require_frozen_v3(self.frozen)
        return self.original,self.frozen,self.call,self.request
    def release_payload_v3(self):
        _PAID_EOFS_V3.pop(self,None);_PAID_FROZEN_EOFS_V3.pop(self,None);_PAID_FINAL_EOFS_V3.pop(self,None)
        if self.request is not None:_PAID_MODEL_REQUESTS_V3.pop(id(self.request),None)
        self.original=self.frozen=self.call=self.request=self.nested=None
        self.intent_column=self.call_column=self.intent_data=self.call_data=self.frozen_data=self.request_data=None
        self.jobs.clear();self.digests.clear();self.request_fields=self.current_turns=None


def _paid_request_digest_value_v3(request):
    return {'envelope':request.envelope,'call_id':request.call_id,'provider_id':request.provider_id,
        'model_id':request.model_id,'purpose':request.envelope.authority.purpose,
        'required_capabilities':sorted(request.required_capabilities),'privacy_tier':request.privacy_tier,
        'template':request.prompt_template_digest,'payload':dict(request.payload),
        'timeout_seconds':float(request.timeout_seconds),'max_output_tokens':request.max_output_tokens}


def require_prepared_d13_paid_payload_eof_v3(witness,request):
    if type(witness)is not PreparedD13PaidRequestEOFV3:raise ValueError('actual D13 Paid request EOF required')
    witness.require_frozen_v3(witness.frozen)
    if witness.phase!='request_ctor' or witness.request is not None or witness.request_fields is None:
        raise ValueError('actual D13 Paid payload EOF is not at its original single constructor')
    for name,value in witness.request_fields.items():
        actual=getattr(request,name)
        if name=='payload':
            if set(actual)!=set(value) or any(actual[key]is not value[key]for key in value):
                raise ValueError('D13 Paid payload differs from its actual complete EOF text')
        elif actual!=value:raise ValueError('D13 Paid request constructor differs from its original fields')
    return witness


def _register_paid_model_request_v3(request,witness):
    import weakref
    key=id(request)
    _PAID_MODEL_REQUESTS_V3[key]=(weakref.ref(request,lambda _,key=key:_PAID_MODEL_REQUESTS_V3.pop(key,None)),witness)


def prepared_d13_paid_request_digest_v3(request):
    item=_PAID_MODEL_REQUESTS_V3.get(id(request))
    if item is None:return None
    ref,witness=item
    if ref()is not request or witness.request is not request or not witness.complete:
        raise ValueError('actual D13 Paid complete request digest required')
    witness.require_frozen_v3(witness.frozen)
    for name,value in witness.request_fields.items():
        actual=getattr(request,name)
        if name=='payload':
            if set(actual)!=set(value) or any(actual[key]is not value[key]for key in value):
                raise ValueError('actual D13 Paid request payload changed after EOF')
        elif actual!=value:raise ValueError('actual D13 Paid request fields changed after EOF')
    witness._require_final_v3()
    return witness.digests['request_digest']


def begin_authority_d13_paid_request_read_v3(work,*,verifier,plan,window):
    return PreparedD13PaidRequestEOFV3(_PAID_EOF_ISSUER_V3,work,verifier=verifier,plan=plan,window=window)
