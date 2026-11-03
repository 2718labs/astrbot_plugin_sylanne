"""C09 historical Numeric-Life originals from actual frozen Sources.

This module issues no live Owner, Source, worker, provider or accounting right.
The Graph stage authenticates existing producer lineage; execution is joined
independently against the final frozen Core/execution facts.
"""
from contextlib import contextmanager
from dataclasses import asdict, fields
from hashlib import sha256
import json
import re
from weakref import WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..graph_types import AtomKey, GraphVersion
from .c09_paged_sql_v2 import (C09PagedCaptureHold, current_c09_sql_meter_v2,
    read_c09_table_shape_v2, legacy_cell_read_transaction_v2)
from ..domains.d01.production_operations_v1 import plain_v1

NUMERIC_KINDS = frozenset({
    'numeric_context_v1','numeric_prepared_v1','numeric_binding_v1',
    'numeric_request_v1','numeric_acquire_commit_v1','numeric_call_v1',
    'numeric_read_attempt_v1','numeric_paid_v1','numeric_appraisal_acceptance_v1',
    'numeric_drive_v1','d04_interval_baseline_v1','numeric_trace_v1'})
_SOURCE_READS = WeakSet()


def _closed(raw, names, schema):
    if type(raw) is not dict or set(raw) != set(names) or raw.get('schema') != schema:
        raise C09PagedCaptureHold('Numeric-Life original has another closed producer schema')
    return raw


def decode_numeric_life_original_v1(kind, raw):
    from .d06_life_numeric_context_v1 import decode_life_numeric_context_original_v1
    from .d06_life_numeric_task_v1 import decode_life_numeric_prepared_v1, decode_life_numeric_appraisal_acceptance_v1
    from .d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
    from .d06_life_numeric_drive_v1 import decode_life_numeric_drive_original_v1
    from .d04_life_encoding_baseline_v1 import decode_life_encoding_baseline_v1
    from .d06_life_numeric_trace_v1 import decode_life_numeric_trace_value_v1, PROVENANCE
    decoders = {
        'numeric_context_v1':decode_life_numeric_context_original_v1,
        'numeric_prepared_v1':decode_life_numeric_prepared_v1,
        'numeric_binding_v1':decode_life_numeric_worker_binding_v1,
        'numeric_appraisal_acceptance_v1':decode_life_numeric_appraisal_acceptance_v1,
        'numeric_drive_v1':decode_life_numeric_drive_original_v1,
        'd04_interval_baseline_v1':decode_life_encoding_baseline_v1}
    if kind in decoders:
        value = decoders[kind](raw)
        manifest = raw.get('role_support_manifest')
        if manifest is not None:
            from .c09_d04_originals_v3 import c09_life_role_manifest_metadata_v4
            c09_life_role_manifest_metadata_v4(manifest,value.namespace)
        return value
    if kind == 'numeric_trace_v1':
        return decode_life_numeric_trace_value_v1(PROVENANCE,raw)
    from ..authority_service.current_life_numeric_v1 import (LifeNumericModelResultReadV1,
        LifeNumericModelResultReadRequestV1, life_numeric_result_from_wire_v1)
    if kind == 'numeric_read_attempt_v1':
        return life_numeric_result_from_wire_v1(raw,LifeNumericModelResultReadRequestV1)
    if kind == 'numeric_request_v1':
        from .natural_reply_job_v2 import _request_from_wire
        from ..model_broker.internal_life_numeric_v1 import TEMPLATE_DIGEST
        _closed(raw,('schema','prepared_digest','binding_digest','request_digest','wire'),
            'd06.internal-life-numeric-request.v1')
        value = _request_from_wire(raw['wire'])
        if (value.digest != raw['request_digest'] or value.identity.phase != 'internal_life_numeric_v1'
                or value.prompt_template_digest != TEMPLATE_DIGEST):
            raise C09PagedCaptureHold('Numeric-Life request differs from its actual typed template/digest/phase')
        return value
    if kind == 'numeric_acquire_commit_v1':
        from .domain_production_originals_v1 import _receipt
        _closed(raw,('schema','prepared_digest','binding_digest','receipt','request_digest','receipt_digest'),
            'd06.internal-life-numeric-acquire-commit.v1')
        value = _receipt(raw['receipt'])
        if value.status != 'committed' or canonical_digest(value) != raw['receipt_digest']:
            raise C09PagedCaptureHold('Numeric-Life acquisition lacks its actual typed COMMIT')
        return value
    if kind == 'numeric_call_v1':
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        from ..authority_service.v2_contract import FencePermitV2, from_wire as permit_from_wire
        _closed(raw,('schema','prepared_digest','binding_digest','request_digest','intent','permit'),
            'd06.internal-life-numeric-call.v1')
        intent = from_wire(raw['intent'],ModelEgressIntentV1)
        permit = permit_from_wire(raw['permit'])
        if type(permit) is not FencePermitV2:
            raise C09PagedCaptureHold('Numeric-Life call lacks the actual FencePermitV2')
        if ((permit.namespace,permit.subject,permit.operation_id,permit.operation,
                permit.token,permit.fence_epoch,permit.revision) !=
                (intent.namespace,intent.subject,intent.operation_id,'model_egress',
                 intent.fence_token,intent.fence_epoch,intent.fence_revision)
                or canonical_digest(asdict(permit.pinned_anchor)) != intent.anchor_digest
                or raw['request_digest'] != intent.request_digest or raw['binding_digest'] != intent.binding_digest):
            raise C09PagedCaptureHold('Numeric-Life sealed call lost its exact original permit/intent binding')
        return intent,permit
    if kind == 'numeric_paid_v1':
        from .model_cost_settlement import OriginalModelCostCommitV1
        _closed(raw,('schema','prepared_digest','binding_digest','result','cost','cost_digest','paid'),
            'd06.internal-life-numeric-paid-result.v1')
        if type(raw['cost']) is not dict or set(raw['cost']) != {field.name for field in fields(OriginalModelCostCommitV1)}:
            raise C09PagedCaptureHold('Numeric-Life paid result has another exact model-cost receipt')
        result = life_numeric_result_from_wire_v1(raw['result'],LifeNumericModelResultReadV1)
        cost = OriginalModelCostCommitV1(**raw['cost'])
        if (raw['paid'] is not True or cost.status != 'committed'
                or canonical_digest(cost) != raw['cost_digest']
                or cost.call_id != result.request.call_id
                or cost.terminal_receipt_digest != canonical_digest(asdict(result.terminal_receipt))):
            raise C09PagedCaptureHold('Numeric-Life paid result lacks its real completed terminal/cost COMMIT')
        return result,cost
    raise C09PagedCaptureHold('unregistered actual Numeric-Life original kind')


class _NumericFrozenGraphReadV1:
    """A private finite logical-column adapter for existing historical readers."""
    def __init__(self, session, pair, meter, *, _borrowed=None):
        from ..authority_service.c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        from ..authority_service.c09_role_capture_pair_v2 import InstalledC09RolePairV2
        from ..authority_service.c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2, _C09ReadonlyPointMeterV3
        if (type(session) is not C09PagedCaptureSessionV2 or type(pair) is not InstalledC09RolePairV2
                or pair._producer.session is not session or pair.source_original.role != 'graph'
                or pair.source_original.scope_digest != session.scope.scope_digest):
            raise AuthorityUnavailable('Numeric C09 history requires its actual same-scope frozen Graph Source')
        self.session,self.pair = session,pair
        self.namespace = session._control.maintenance.namespace_id
        self.scope = session.begin_source_physical_read_v3(pair,meter=meter)
        self.strings = [];self.native_rows=[];self.decoded_values=[];self.native_decode_peak=0
        if _borrowed is not None and (type(_borrowed)is not _BoundedReadConnectionV2 or _borrowed.db is not pair.source):
            raise AuthorityUnavailable('Numeric borrowed reader is not its actual frozen Graph connection')
        self.db = (_BoundedReadConnectionV2(pair.source,_C09ReadonlyPointMeterV3(meter))
            if _borrowed is None else _borrowed)
        if self.db._life_numeric_source_v1 is not None:
            raise AuthorityUnavailable('Numeric frozen reader already has an active source interval')
        self.facts_binding=None
        self.db._life_numeric_source_v1 = self
        _SOURCE_READS.add(self)
        session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        actual=_retained_size((self.native_rows,self.decoded_values),set())
        return 8192+sum(len(value)*4+64 for value in self.strings)+max(actual,self.native_decode_peak)

    def require_current(self, db):
        if self not in _SOURCE_READS or self.db is not db or db.db is not self.pair.source:
            raise AuthorityUnavailable('Numeric C09 history adapter left its actual frozen Source')
        self.session.require_current();self.pair.require_current()
        self.scope.require_current(meter=current_c09_sql_meter_v2())
        return self

    def close(self):
        if self.db is not None:self.db._life_numeric_source_v1 = None
        self.strings.clear();self.native_rows.clear();self.decoded_values.clear();self.facts_binding=None;self.db = None
        _SOURCE_READS.discard(self)

    def preflight_native_v1(self,db,size):
        self.require_current(db);meter=current_c09_sql_meter_v2()
        if size*6+256>meter.budget.max_bytes or size*8>meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('Numeric native original requires its registered large-original continuation')
        self.session._control.require_c09_retained_arena_v3(meter=meter,additional_bytes=size*8+32768)

    def retain_native_v1(self,db,row,size):
        self.require_current(db);self.native_rows.append(row);self.native_decode_peak+=size*8
        self.session._control.require_c09_retained_arena_v3(meter=current_c09_sql_meter_v2())

    def retain_values_v1(self,db,values):
        self.require_current(db);self.decoded_values.append(values)
        self.session._control.require_c09_retained_arena_v3(meter=current_c09_sql_meter_v2())

    def read_logical_point_v1(self, db, sql, parameters):
        self.require_current(db)
        match = re.fullmatch(r'SELECT\s+([a-z_, ]+)\s+FROM\s+(graph_atoms|graph_history)\s+WHERE\s+(.+)',
            sql,re.I)
        if match is None:return None
        columns = tuple(name.strip().lower() for name in match[1].split(','))
        table = match[2].lower()
        allowed = {'token','revision','valid','value','bot','persona','type_name','owner_kind','owner_subject'} if table == 'graph_atoms' else {
            'token','revision','valid','value','dependencies','event_bot','event_persona','event_session','event_id'}
        if 'value' not in columns or any(name not in allowed for name in columns):return None
        clauses = re.split(r'\s+AND\s+',match[3],flags=re.I)
        criteria = {};arguments = iter(parameters)
        for clause in clauses:
            part = re.fullmatch(r'(token|revision|bot|persona|event_bot|event_persona)\s*=\s*(\?|[0-9]+)',clause.strip(),re.I)
            if part is None:return None
            name = part[1].lower()
            if name in criteria:return None
            criteria[name] = next(arguments) if part[2] == '?' else int(part[2])
        try:next(arguments)
        except StopIteration:pass
        else:raise AuthorityUnavailable('Numeric logical point has extra arguments')
        if ('token' not in criteria or NamespaceId.from_key(AtomKey.from_token(criteria['token'])) != self.namespace
                or table == 'graph_history' and ('revision' not in criteria or criteria['revision'] < 1)):
            raise AuthorityUnavailable('Numeric logical point crossed its original member/namespace')
        for name,expected in (('bot',self.namespace.bot_id),('persona',self.namespace.persona_id),
                ('event_bot',self.namespace.bot_id),('event_persona',self.namespace.persona_id)):
            if name in criteria and criteria[name] != expected:
                raise AuthorityUnavailable('Numeric point selector differs from its actual namespace')
        meter = current_c09_sql_meter_v2()
        shape = read_c09_table_shape_v2(self.pair.source,table,meter=meter)
        if 'value_cell_id' not in shape.columns:return None
        from ..segmented_sql_cell_v1 import GRAPH_REF_DDLS_V3
        ddl = meter.read_fixed_row(self.pair.source,'sqlite_master',('sql',),'type=? AND name=?',('table',table))
        if ddl != (GRAPH_REF_DDLS_V3[table],):
            raise AuthorityUnavailable('Numeric historical Graph physical schema differs')
        names = tuple('value_cell_id' if name == 'value' else name for name in columns)
        where = ' AND '.join(name+'=?' for name in criteria)
        row = meter.read_fixed_row(self.pair.source,table,names,where,tuple(criteria.values()))
        description = tuple((name,None,None,None,None,None,None)for name in columns)
        if row is None:return (),description
        cell_id = row[columns.index('value')]
        header = self.scope.read_cell_header_v3(cell_id,meter=meter)
        if header[1] != 'canonical-json.ascii.v1' or header[2] != criteria['token']:
            raise AuthorityUnavailable('Numeric historical Graph cell codec/owner differs')
        size = header[4]
        if size*6+32*len(columns)>meter.budget.max_bytes or size*8>meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('Numeric logical history needs its registered continuation at the original point budget')
        self.session._control.require_c09_retained_arena_v3(meter=meter,additional_bytes=size*8+32768)
        meter.require_available(size*2+header[5]*1024+8192)
        raw = bytearray();digest = sha256();root = canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell_id))
        for ordinal in range(header[5]):
            segment = self.scope.read_cell_segment_v3(cell_id,ordinal,meter=meter)
            if segment is None or segment[0] != len(raw):
                raise AuthorityUnavailable('Numeric logical history ordered Source bytes differ')
            digest.update(segment[1])
            root = canonical_digest(('sylanne3.segmented-cell-link.v1',root,cell_id,ordinal,len(raw),len(segment[1]),segment[2]))
            raw.extend(segment[1])
        self.scope.require_cell_eof_v3(cell_id,header[5],meter=meter)
        if (len(raw),digest.hexdigest(),root)!=(header[4],header[6],header[7]):
            raise AuthorityUnavailable('Numeric logical history complete Source SHA/root/EOF differs')
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        meter.charge_encode(len(raw)*2)
        for start in range(0,len(raw),4096):parser.feed(bytes(raw[start:start+4096]),lambda event:None)
        parser.finish();parser._emit_callback=None
        text = raw.decode('ascii');self.strings.append(text)
        self.require_current(db)
        values = tuple(text if name == 'value' else item for name,item in zip(columns,row,strict=True))
        return (values,),description


def read_numeric_frozen_logical_point_v1(db, sql, parameters):
    value = db._life_numeric_source_v1
    if type(value) is not _NumericFrozenGraphReadV1 or value not in _SOURCE_READS:
        raise AuthorityUnavailable('actual registered Numeric C09 Source required')
    return value.read_logical_point_v1(db,sql,parameters)


@contextmanager
def numeric_frozen_graph_read_v1(session,pair,meter):
    with legacy_cell_read_transaction_v2(pair.source):
        source = _NumericFrozenGraphReadV1(session,pair,meter)
        try:yield source.db
        finally:source.close()


def _numeric_signed_v1(db,issuer,namespace,kind,ref):
    from .d11_life_preparation_v1 import _read_signed_life_payload_v1
    saved = _read_signed_life_payload_v1(db,issuer=issuer,namespace=namespace,kind=kind,ref=ref)
    if saved is None:
        raise C09PagedCaptureHold('Numeric-Life actual signed parent is absent: '+kind)
    value = decode_numeric_life_original_v1(kind,saved[0])
    retain_numeric_frozen_values_v1(db,(value,saved[0]))
    return value,saved[0],saved[1]


def _numeric_domain_v1(db,namespace,operation,domain,kind):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    original = read_adopted_domain_operation_v1(db,namespace,operation)
    if (original is None or (original['domain'],original['operation_kind']) != (domain,kind)
            or original['receipt'].status != 'committed'):
        raise C09PagedCaptureHold('Numeric-Life signed companion lacks its actual committed Domain producer')
    from ..contracts import Event,Scope
    receipt=original['receipt']
    row=db.execute('SELECT reads,revisions,digest,occurred_at,epoch_revision FROM graph_events '
        'WHERE bot=? AND persona=? AND session=? AND event_id=?',
        (*namespace.as_tuple,receipt.activity_id,operation)).fetchone()
    if (row is None or row[4]<1 or row[2]!=Event(Scope(*namespace.as_tuple,receipt.activity_id),
            operation,row[3],'domain_bundle',{'bundle_digest':receipt.operation_digest}).digest
            or json.loads(row[0])!=[[v.key.token,v.revision]for v in receipt.read_versions]
            or json.loads(row[1])!=[[v.key.token,v.revision]for v in receipt.write_versions]):
        raise C09PagedCaptureHold('Numeric-Life actual W01 event/readset/writes/receipt differs')
    for version in receipt.write_versions:
        history=db.execute('SELECT event_bot,event_persona,event_session,event_id,valid FROM graph_history '
            'WHERE token=? AND revision=?',(version.key.token,version.revision)).fetchone()
        if history!=(*namespace.as_tuple,receipt.activity_id,operation,1):
            raise C09PagedCaptureHold('Numeric-Life W01 write lacks its same-namespace/session/operation history')
    return original


def _numeric_history_v1(db,namespace,version,operation,expected):
    row = db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?',
        (version.key.token,version.revision)).fetchone()
    if (NamespaceId.from_key(version.key) != namespace
            or row != (canonical_serialize(expected),1,operation)):
        raise C09PagedCaptureHold('Numeric-Life exact historical write value/producer differs')


def _numeric_baseline_v1(db,namespace,issuer,value):
    from .d04_life_encoding_baseline_v1 import D04LifeEncodingBaselineV1,life_encoding_baseline_ids_v1,OPERATION
    from .c04_encoding_baseline_store_v3 import read_c04_encoding_baseline_v3
    context,_,_ = _numeric_signed_v1(db,issuer,namespace,'numeric_context_v1',value.context_ref)
    record = read_c04_encoding_baseline_v3(db,namespace=namespace,
        encoding_operation_id=value.encoding_operation_id,source_ref=value.source_ref)
    c,proof = context,record.proof
    ids = life_encoding_baseline_ids_v1(namespace,c.episode_ref,record.joint_operation_id)
    expected = D04LifeEncodingBaselineV1(c.namespace,ids['original'],ids['operation'],c.episode_ref,
        c.occurrence_digest,c.execution_id,c.before_ref,c.before_digest,c.original_ref,c.digest,
        c.source_ref,c.source_revision,c.perspective_ref,record.joint_operation_id,record.record_digest,
        proof.proof_digest,proof.projection.salience_interval,proof.projection.tone_interval,
        canonical_digest(plain_v1(proof.numeric_error)),proof.native_manifest_sha256,proof.native_sha256,
        proof.readout_sha256,proof.policy_digest,proof.as_known_at,c.owner_head_digest,
        c.activation_generation,c.graph_incarnation,value.appraisal_acceptance_digests)
    original = _numeric_domain_v1(db,namespace,value.encoding_operation_id,'d06',OPERATION)
    if (value != expected or original['receipt'] != record.encoding_receipt
            or original['receipt'].write_versions or original['payload']['writes']
            or original['payload']['provenance'] != {
                'schema':value.schema,'context_digest':c.digest,'before_digest':c.before_digest,
                'joint_output_digest':proof.output_original_digest,
                'appraisal_acceptance_digests':plain_v1(value.appraisal_acceptance_digests),
                'as_known_at':proof.as_known_at,'causal_effect':'not_identified'}):
        raise C09PagedCaptureHold('Numeric-Life interval baseline differs from actual C04/CPU/history/provenance')
    return value


def verify_numeric_life_graph_history_v1(build,original,*,producing_operation_id,meter):
    if original.family != 'graph_d11_life_originals_v1' or original.kind not in NUMERIC_KINDS:return
    from .d06_life_numeric_task_v1 import (read_life_numeric_prepared_v1,
        read_life_numeric_appraisal_acceptance_v1)
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    from .d06_life_numeric_paid_v1 import (read_life_numeric_cost_commit_v1,
        require_life_numeric_paid_membership_v3)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .d11_life_preparation_v1 import _read_signed_life_payload_v1
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1
    issuer = build.session.get_c09_domain_original_issuer_v2()
    namespace = NamespaceId(**original.payload['namespace']) if 'namespace' in original.payload else NamespaceId(
        *json.loads(build.scope.graph_namespace))
    if namespace.as_tuple != tuple(json.loads(build.scope.graph_namespace)):
        raise C09PagedCaptureHold('Numeric-Life original differs from actual Graph capture namespace')
    kind,ref,raw = original.kind,original.original_ref,original.payload
    value = decode_numeric_life_original_v1(kind,raw)
    build.require_current()
    with numeric_frozen_graph_read_v1(build.session,build.pair,meter) as db:
        retain_numeric_frozen_values_v1(db,(original,value))
        saved = _read_signed_life_payload_v1(db,issuer=issuer,namespace=namespace,kind=kind,ref=ref)
        if saved != (raw,producing_operation_id):
            raise C09PagedCaptureHold('Numeric-Life actual signed row/producer differs from captured original')
        if kind == 'numeric_context_v1':
            from .d06_life_numeric_context_v1 import OPERATION,_writes
            if (value.namespace,value.original_ref,value.operation_id) != (namespace,ref,producing_operation_id):
                raise C09PagedCaptureHold('Numeric-Life context signed selector differs')
            parent = _numeric_domain_v1(db,namespace,value.operation_id,'d06',OPERATION)
            writes = _writes(value)
            if (parent['payload']['provenance']['context_original'] != raw
                    or parent['payload']['provenance']['before_original_digest'] != value.before_digest
                    or set(parent['receipt'].write_versions) != {GraphVersion(write.key,1)for write in writes}):
                raise C09PagedCaptureHold('Numeric-Life context differs from actual occurrence/before/two-member W01')
            for write in writes:_numeric_history_v1(db,namespace,GraphVersion(write.key,1),value.operation_id,write.value)
        elif kind == 'numeric_prepared_v1':
            checked = read_life_numeric_prepared_v1(db,namespace=namespace,issuer=issuer,job_id=ref)
            if checked != value or producing_operation_id != value.operation_id:
                raise C09PagedCaptureHold('Numeric-Life prepared signed selector/actual job differs')
        elif kind in {'numeric_binding_v1','numeric_request_v1','numeric_acquire_commit_v1','numeric_call_v1',
                'numeric_read_attempt_v1','numeric_paid_v1'}:
            job_id = value.job_id if kind == 'numeric_read_attempt_v1' else ref
            p,b,model = read_committed_life_numeric_request_v1(db,namespace=namespace,issuer=issuer,job_id=job_id)
            retain_numeric_frozen_values_v1(db,(p,b,model))
            if kind == 'numeric_binding_v1':
                if value != b or producing_operation_id != b.acquire_operation_id:
                    raise C09PagedCaptureHold('Numeric-Life binding original is not its actual acquisition')
            elif kind == 'numeric_request_v1':
                if value != model or producing_operation_id != b.acquire_operation_id:
                    raise C09PagedCaptureHold('Numeric-Life request original is not its actual acquired model request')
            elif kind == 'numeric_acquire_commit_v1':
                parent = read_adopted_domain_operation_v1(db,namespace,b.acquire_operation_id)
                if parent is None or value != parent['receipt'] or producing_operation_id != b.acquire_operation_id:
                    raise C09PagedCaptureHold('Numeric-Life acquisition receipt differs from its actual W01')
            elif kind == 'numeric_call_v1':
                intent,permit = value
                quote = issuer.resource_issuer.original_signed_quote(db,p.quote_id,p.quote_version)
                sources = tuple(sorted((v.key.owner.subject,v.revision)for v in model.envelope.version_guard.read_versions
                    if v.key.type_name == 'memory.source' and v.revision > 0))
                accesses = tuple(sorted((v.key.owner.subject,v.revision)for v in model.envelope.version_guard.read_versions
                    if v.key.type_name == 'memory.access' and v.revision > 0))
                if (producing_operation_id != b.acquire_operation_id
                        or (intent.authority_id,intent.namespace,intent.subject,intent.operation_id,intent.call_id,
                            intent.request_digest,intent.job_id,intent.acquire_operation_id,intent.binding_digest,
                            intent.source_refs,intent.source_revisions,intent.access_revisions,
                            intent.budget_lease_id,intent.budget_reservation_operation_id,intent.budget_reservation_digest,
                            intent.budget_ceiling,intent.provider_id,intent.model_id,intent.provider_config_digest,intent.max_output_tokens) !=
                           (build.scope.authority_id,build.scope.authority_namespace,b.worker_subject,b.acquire_operation_id,p.call_id,
                            model.digest,p.job_id,b.acquire_operation_id,b.digest,
                            tuple(ref for ref,_ in sources),sources,accesses,quote.parent_budget_lease_ref,
                            p.operation_id,p.reservation_digest,tuple(sorted(quote.ceiling.items())),
                            model.provider_id,model.model_id,p.frozen.appraisal.installation.provider_config_digest,model.max_output_tokens)):
                    raise C09PagedCaptureHold('Numeric-Life sealed intent differs from actual acquired sources/request/reservation/worker')
            elif kind == 'numeric_read_attempt_v1':
                from ..model_broker.internal_life_numeric_v1 import internal_life_numeric_ids_v1
                ids = internal_life_numeric_ids_v1(p.frozen.identity)
                expected = LifeNumericModelResultReadRequestV1(build.scope.authority_id,build.scope.authority_namespace,
                    namespace,p.installation_id,p.episode_ref,p.occurrence_digest,p.causal_operation_id,p.job_id,
                    b.acquire_operation_id,p.operation_id,p.call_id,b.digest,p.digest,model.digest,
                    ids['adopt'],value.read_attempt_id)
                if value != expected or ref != value.read_attempt_id or producing_operation_id != b.acquire_operation_id:
                    raise C09PagedCaptureHold('Numeric-Life read attempt differs from its existing original acquisition')
            else:
                result,stored_cost=value
                (intent,_),_,call_operation=_numeric_signed_v1(db,issuer,namespace,'numeric_call_v1',p.job_id)
                result.require_original(intent,p,p.frozen,b)
                cost=read_life_numeric_cost_commit_v1(db,namespace=namespace,issuer=issuer,
                    prepared=p,intent=intent,terminal=result.terminal_receipt)
                if (stored_cost!=cost or call_operation!=b.acquire_operation_id
                        or canonical_digest(raw)!=original.original_commitment):
                    raise C09PagedCaptureHold('Numeric-Life paid body differs from its real cost/terminal/original model')
                require_life_numeric_paid_membership_v3(producing_operation_id=producing_operation_id,
                    prepared_digest=raw['prepared_digest'],binding_digest=raw['binding_digest'],
                    cost_value=raw['cost'],cost_digest=raw['cost_digest'],result_request_digest=result.request.model_request_digest,
                    prepared=p,binding=b,model=model,cost=cost)
        elif kind == 'numeric_appraisal_acceptance_v1':
            checked = read_life_numeric_appraisal_acceptance_v1(db,namespace,ref,issuer)
            if checked != value or producing_operation_id != value.operation_id:
                raise C09PagedCaptureHold('Numeric-Life appraisal lacks its full paid/job/actual adoption history')
        elif kind == 'numeric_drive_v1':
            from .d06_life_numeric_drive_v1 import OPERATION
            context,_,_ = _numeric_signed_v1(db,issuer,namespace,'numeric_context_v1',value.context_ref)
            acceptance = read_life_numeric_appraisal_acceptance_v1(db,namespace,value.appraisal_ref,issuer)
            from .d04_appraisal_driver_v3 import read_d04_original_v3
            mapping = read_d04_original_v3(db,namespace,'semantic_mapping',value.mapping_ref)
            parent = _numeric_domain_v1(db,namespace,value.operation_id,'d04',OPERATION)
            if (producing_operation_id != value.operation_id or value.original_ref != ref
                    or context.digest != value.context_digest or context.before_digest != value.before_digest
                    or context.episode_ref != value.episode_ref or context.source_ref != value.source_ref
                    or acceptance is None or acceptance.digest != value.appraisal_acceptance_digest
                    or acceptance.operation_id != value.appraisal_adoption_operation_id
                    or mapping is None or mapping[1] != value.mapping_digest
                    or mapping[0]['role_support_manifest'] != acceptance.role_support_manifest
                    or parent['payload']['provenance']['life_numeric_drive_original'] != raw
                    or set((v.key.token,v.revision)for v in parent['receipt'].write_versions) != set(value.drive_versions)):
                raise C09PagedCaptureHold('Numeric-Life drive differs from its actual context/paid mapping/clock/Domain parent')
            for write in parent['payload']['writes']:
                _numeric_history_v1(db,namespace,GraphVersion(AtomKey.from_token(write['key']),1),
                    value.operation_id,write['value'])
        elif kind == 'd04_interval_baseline_v1':
            if value.original_ref != ref or value.encoding_operation_id != producing_operation_id:
                raise C09PagedCaptureHold('Numeric-Life interval baseline signed operation differs')
            _numeric_baseline_v1(db,namespace,issuer,value)
        elif kind == 'numeric_trace_v1':
            from .d06_life_numeric_trace_v1 import OPERATION,_writes
            trace = value.trace
            baseline,_,_ = _numeric_signed_v1(db,issuer,namespace,'d04_interval_baseline_v1',trace.baseline.original_ref)
            _numeric_baseline_v1(db,namespace,issuer,baseline)
            parent = _numeric_domain_v1(db,namespace,trace.producing_operation_id,'d06',OPERATION)
            writes = _writes(value)
            if (trace.trace_ref != ref or trace.producing_operation_id != producing_operation_id
                    or trace.baseline != baseline or parent['payload']['provenance']['numeric_trace_provenance'] != raw
                    or set(parent['receipt'].write_versions) != {GraphVersion(write.key,1)for write in writes}):
                raise C09PagedCaptureHold('Numeric-Life trace differs from actual numerical baseline/three-member W01')
            for write in writes:_numeric_history_v1(db,namespace,GraphVersion(write.key,1),producing_operation_id,write.value)
        else:raise C09PagedCaptureHold('unregistered Numeric-Life historical producer')
    build.require_current()


class _NumericPaidMetadataV1:
    """Selected fixed metadata, with the complete original bytes authenticated."""
    def __init__(self,session):
        from .c09_canonical_json_stream_v2 import _CanonicalJSONValueBuilderV3
        self.session=session;self.selected={};self.current=None;self.prefix=None
        self.keys=set();self.result_keys=set()
        self.builder_type=_CanonicalJSONValueBuilderV3
        session._source_parser_arena_v3.add(self)

    def _source_heap_bytes(self):
        import sys
        def size(value):
            if type(value)is dict:return sys.getsizeof(value)+sum(size(k)+size(v)for k,v in value.items())
            if type(value)in(tuple,list,set):return sys.getsizeof(value)+sum(size(v)for v in value)
            return sys.getsizeof(value)
        return 8192+size(self.selected)+size(self.keys)+size(self.result_keys)+(0 if self.current is None else
            size(self.current.nodes)+size(self.current.scalar)+size(self.current.value))

    def emit(self,event):
        from dataclasses import replace
        if event.kind=='key' and len(event.path)==1:self.keys.add(event.key)
        if event.kind=='key' and len(event.path)==2 and event.path[0]=='result':self.result_keys.add(event.key)
        prefixes=(('schema',),('prepared_digest',),('binding_digest',),('cost',),('cost_digest',),('paid',),
            ('result','schema'),('result','request'),('result','terminal_receipt'),
            ('result','current_scope_digest'),('result','read_at_utc'))
        if self.current is None:
            if event.path not in prefixes or event.kind not in ('scalar_start','object_start','array_start'):return
            parent=self
            class SelectedValue(self.builder_type):
                def _reserve(self,extra=0):
                    parent.session._control.require_c09_retained_arena_v3(
                        meter=current_c09_sql_meter_v2(),additional_bytes=extra+16384)
            self.current=SelectedValue()
            self.current._initialize_json_value_v3(incremental_retention=False,
                frozen_object_type=None,frozen_array_type=None)
            self.prefix=event.path
        if event.path[:len(self.prefix)]!=self.prefix:return
        self.current._emit(replace(event,path=event.path[len(self.prefix):]))
        if event.path==self.prefix and event.kind in ('scalar_end','object_end','array_end'):
            self.selected[self.prefix]=self.current.value;self.current=None;self.prefix=None


def _read_numeric_paid_metadata_v1(session,pair,issuer,namespace,job_id,meter):
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
    from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
    row=meter.read_fixed_row(pair.source,TABLE,
        ('producing_operation_id','payload_digest','signature'),
        'bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'numeric_paid_v1',job_id))
    if row is None:return None
    where='bot=? AND persona=? AND kind=? AND original_ref=?'
    args=(*namespace.as_tuple,'numeric_paid_v1',job_id)
    lengths=pair.source.execute('SELECT length(CAST(payload_json AS BLOB)) FROM '+TABLE+' WHERE '+where,args).fetchone()
    if lengths is None or type(lengths[0])is not int:
        raise C09PagedCaptureHold('Numeric paid original lacks its actual fixed Source bytes')
    size=lengths[0];meter.charge_read(8)
    # This is the inherited native original profile, not an arbitrary whole-value allowance.
    if size*6+256>meter.budget.max_bytes or size*8>meter.budget.reserved_arena_bytes:
        raise C09PagedCaptureHold('Numeric paid original requires its registered large-original continuation')
    meter.require_available(size*3+8192)
    capture=_NumericPaidMetadataV1(session);parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
    with legacy_cell_read_transaction_v2(pair.source):
        for start in range(0,size,4096):
            fragment,total,storage_class=read_legacy_sql_cell_fragment_v2(pair.source,table=TABLE,column='payload_json',
                where=where,parameters=args,start=start,length=min(4096,size-start),meter=meter)
            if total!=size or storage_class!='text' or len(fragment)!=min(4096,size-start):
                raise C09PagedCaptureHold('Numeric paid original Source EOF/storage class changed')
            parser.feed(fragment,capture.emit)
        result=parser.finish();parser._emit_callback=None
    if (result.byte_count,result.sha256)!=(size,row[1]) or capture.current is not None:
        raise C09PagedCaptureHold('Numeric paid complete Source digest/EOF differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,'numeric_paid_v1',job_id,row[1])),row[2])
    if (capture.keys!={'schema','prepared_digest','binding_digest','result','cost','cost_digest','paid'}
            or capture.result_keys!={'schema','request','observation','terminal_receipt','read_at_utc','current_scope_digest'}
            or capture.selected.get(('schema',))!='d06.internal-life-numeric-paid-result.v1'
            or capture.selected.get(('paid',))is not True):
        raise C09PagedCaptureHold('Numeric paid original has another closed metadata shape')
    pair.require_current();session.require_current()
    return capture,row[0],row[1]


def verify_numeric_life_model_fact_v1(transform,original,meter):
    """Join actual frozen Core/execution fact to its signed Graph producer."""
    from ..authority_service.v2_model_egress_store import _decoded
    from ..authority_service.c09_model_budget_original_v1 import MODEL_COLUMNS,validate_model_core_row_v1
    from ..authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
    from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
    from ..authority_service.current_life_numeric_v1 import LifeNumericModelResultReadRequestV1,life_numeric_result_from_wire_v1,SCHEMA
    from ..model_broker.internal_life_numeric_v1 import WORK_KIND
    meter=current_c09_sql_meter_v2()
    session=transform.basis.session
    graph=session.require_actual_post_mirror_graph_v3()
    graph.require_current();transform.pair.require_current()
    namespace=NamespaceId(*json.loads(transform.scope.graph_namespace))
    issuer=session.get_c09_domain_original_issuer_v2()
    with numeric_frozen_graph_read_v1(session,graph.pair,meter) as db:
        quote=issuer.resource_issuer.original_signed_quote(db,original.quote_id,original.quote_version)
        table_exists=meter.read_fixed_row(graph.pair.source,'sqlite_master',('name',),'type=? AND name=?',
            ('table','graph_d11_life_originals_v1'))
        if table_exists is None:
            if quote.work_kind==WORK_KIND:raise C09PagedCaptureHold('Numeric quote lacks its actual Graph original family')
            return
        saved=meter.read_fixed_row(graph.pair.source,'graph_d11_life_originals_v1',('payload_digest',),
            'bot=? AND persona=? AND kind=? AND original_ref=?',
            (*namespace.as_tuple,'numeric_call_v1',original.job_id))
        if quote.work_kind!=WORK_KIND:
            if saved is not None:raise C09PagedCaptureHold('Numeric sealed call is attached to another actual work-kind quote')
            return
        if (canonical_digest(quote)!=original.quote_digest or (quote.bot_id,quote.persona_id)!=namespace.as_tuple
                or original.authority_id!=transform.scope.authority_id
                or original.installation_id!=transform.scope.installation_id
                or original.namespace!=transform.scope.authority_namespace):
            raise C09PagedCaptureHold('Numeric model original changed its actual quote/installation/namespace')
        # A prepared reservation can precede the sealed Core call. It cannot claim paid execution.
        if saved is None:
            from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
            prepared,binding,request=read_committed_life_numeric_request_v1(
                db,namespace=namespace,issuer=issuer,job_id=original.job_id)
            with legacy_cell_read_transaction_v2(transform.pair.source):
                table='authority_model_egress_v1'
                pending=meter.read_fixed_row(transform.pair.source,table,MODEL_COLUMNS[table],
                    'call_id=?',(original.call_id,))
                if pending is None:raise C09PagedCaptureHold('Numeric prepared fact lacks its actual frozen Core identity')
                validate_model_core_row_v1(table,MODEL_COLUMNS[table],pending)
                pending_intent=_decoded(pending[4])
            if (pending[5:]!=('prepared',None)
                    or (pending_intent.job_id,pending_intent.call_id,pending_intent.acquire_operation_id,
                        pending_intent.operation_id,pending_intent.request_digest,pending_intent.binding_digest,
                        pending_intent.subject,pending_intent.budget_reservation_operation_id,pending_intent.budget_reservation_digest)!=
                       (prepared.job_id,prepared.call_id,binding.acquire_operation_id,binding.acquire_operation_id,
                        request.digest,binding.digest,binding.worker_subject,prepared.operation_id,prepared.reservation_digest)
                    or (original.model_operation_id,original.acquire_operation_id,original.request_digest,original.binding_digest)!=
                       (pending_intent.operation_id,binding.acquire_operation_id,request.digest,binding.digest)
                    or original.provider_state!='prepared' or original.terminal_digest_or_none is not None
                    or (prepared.call_id,prepared.operation_id,prepared.reservation_digest,prepared.quote_id,prepared.quote_version)!=
                       (original.call_id,original.reservation_operation_id,original.reservation_digest,original.quote_id,original.quote_version)
                    or meter.read_fixed_row(graph.pair.source,'graph_d11_life_originals_v1',('payload_digest',),
                        'bot=? AND persona=? AND kind=? AND original_ref=?',
                        (*namespace.as_tuple,'numeric_paid_v1',original.job_id))is not None):
                raise C09PagedCaptureHold('Numeric model execution lacks its actual sealed call')
            return
        (intent,permit),raw,operation=_numeric_signed_v1(db,issuer,namespace,'numeric_call_v1',original.job_id)
        with legacy_cell_read_transaction_v2(transform.pair.source):
            table='authority_model_egress_v1'
            row=meter.read_fixed_row(transform.pair.source,table,MODEL_COLUMNS[table],'call_id=?',(original.call_id,))
            if row is None:raise C09PagedCaptureHold('Numeric Graph sealed call lacks its real frozen Core original')
            validate_model_core_row_v1(table,MODEL_COLUMNS[table],row);core_intent=_decoded(row[4])
        if (core_intent!=intent or operation!=intent.acquire_operation_id
                or (intent.call_id,intent.operation_id,intent.job_id,intent.acquire_operation_id,
                    intent.request_digest,intent.binding_digest,intent.provider_id,intent.budget_lease_id,
                    intent.budget_reservation_operation_id,intent.budget_reservation_digest)!=
                   (original.call_id,original.model_operation_id,original.job_id,original.acquire_operation_id,
                    original.request_digest,original.binding_digest,original.provider_id,original.parent_budget_id,
                    original.reservation_operation_id,original.reservation_digest)
                or row[5]!=original.provider_state or row[6]!=original.observation_digest_or_none):
            raise C09PagedCaptureHold('Numeric actual Core identity/state differs from its signed original Graph call')
        paid=_read_numeric_paid_metadata_v1(session,graph.pair,issuer,namespace,original.job_id,meter)
        if paid is None:return
        capture,paid_operation,_=paid;selected=capture.selected
        selector=life_numeric_result_from_wire_v1(selected[('result','request')],LifeNumericModelResultReadRequestV1)
        terminal=model_from_wire(selected[('result','terminal_receipt')],ModelTerminalReceiptV2)
        from .model_cost_settlement import OriginalModelCostCommitV1
        cost_raw=selected[('cost',)]
        if type(cost_raw)is not dict or set(cost_raw)!={field.name for field in fields(OriginalModelCostCommitV1)}:
            raise C09PagedCaptureHold('Numeric paid metadata cost is not its exact official receipt')
        cost=OriginalModelCostCommitV1(**cost_raw)
        if (selected[('result','schema')]!=SCHEMA
                or (selector.authority_id,selector.authority_namespace,selector.namespace,selector.installation_id,
                    selector.job_id,selector.acquire_operation_id,selector.original_operation_id,selector.call_id,
                    selector.binding_digest,selector.prepared_digest,selector.model_request_digest)!=
                   (transform.scope.authority_id,transform.scope.authority_namespace,namespace,transform.scope.installation_id,
                    original.job_id,original.acquire_operation_id,original.reservation_operation_id,original.call_id,
                    original.binding_digest,raw['prepared_digest'],original.request_digest)
                or selected[('prepared_digest',)]!=selector.prepared_digest
                or selected[('binding_digest',)]!=selector.binding_digest
                or original.provider_state!='observed' or original.reservation_state!='settled'
                or original.terminal_digest_or_none!=canonical_digest(terminal)
                or original.observation_digest_or_none!=terminal.observation_digest
                or (terminal.call_id,terminal.request_digest,terminal.installation_id)!=
                   (original.call_id,original.request_digest,original.installation_id)
                or cost.operation_id!=paid_operation or cost.call_id!=original.call_id
                or cost.terminal_receipt_digest!=canonical_digest(asdict(terminal))
                or selected[('cost_digest',)]!=canonical_digest(cost)):
            raise C09PagedCaptureHold('Numeric paid Graph original differs from actual final model/terminal/cost facts')
    graph.require_current();transform.pair.require_current()


_NUMERIC_REVERSE = WeakSet()
_NUMERIC_REVERSE_TOKEN=object()


class _NumericCoreReverseReadV1:
    """Full signed call/paid Graph keyset EOF against actual final model facts."""
    def __init__(self,token,builder):
        from ..authority_service.c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        if token is not _NUMERIC_REVERSE_TOKEN or type(builder)is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!='core':
            raise AuthorityUnavailable('actual final Core builder required for Numeric reverse lineage')
        builder.require_current();self.builder=builder
        self.graph=builder.session.require_actual_post_mirror_graph_v3();self.graph.require_current()
        self.after=None;self.complete=False;self.count=0
        self.root=canonical_digest(('sylanne3.c09.numeric-core-reverse.v1',builder.scope.scope_digest,
            builder.pair.source_original.role_source_digest,self.graph.pair.source_original.role_source_digest))
        _NUMERIC_REVERSE.add(self)
        builder.session._control.maintenance.control.register_c09_retained_state_v3(self)

    def _c09_retained_heap_bytes_v3(self):
        return 8192+(0 if self.after is None else sum(len(s)*4+64 for s in self.after))

    def require_complete(self,builder):
        if (self not in _NUMERIC_REVERSE or self.builder is not builder or not self.complete
                or self.graph is not builder.session.require_actual_post_mirror_graph_v3()):
            raise AuthorityUnavailable('actual complete Numeric Graph/Core reverse EOF required')
        builder.require_current();self.graph.require_current()
        return self.root,self.count

    def advance(self):
        from copy import copy
        from .d11_life_preparation_v1 import TABLE
        if self not in _NUMERIC_REVERSE:raise AuthorityUnavailable('actual Numeric reverse Source cursor required')
        self.builder.require_current();self.graph.require_current()
        meter=current_c09_sql_meter_v2();result=copy(self);_NUMERIC_REVERSE.add(result)
        self.builder.session._control.maintenance.control.register_c09_retained_state_v3(result)
        ns=NamespaceId(*json.loads(self.builder.scope.graph_namespace))
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            exists=meter.read_fixed_row(self.graph.pair.source,'sqlite_master',('name',),'type=? AND name=?',('table',TABLE))
            if exists is None:result.complete=True;return result
            after=('','')if self.after is None else self.after
            identity=meter.read_fixed_row(self.graph.pair.source,TABLE,('kind','original_ref','payload_digest'),
                "bot=? AND persona=? AND kind IN ('numeric_call_v1','numeric_paid_v1') AND "
                "(kind COLLATE BINARY>? OR (kind=? AND original_ref COLLATE BINARY>?)) ORDER BY kind COLLATE BINARY,original_ref COLLATE BINARY",
                (*ns.as_tuple,after[0],after[0],after[1]))
            if identity is None:result.complete=True;return result
            kind,ref,digest=identity;issuer=self.builder.session.get_c09_domain_original_issuer_v2()
            with numeric_frozen_graph_read_v1(self.builder.session,self.graph.pair,meter)as db:
                if kind=='numeric_call_v1':
                    (intent,_),_,_=_numeric_signed_v1(db,issuer,ns,kind,ref);call_id=intent.call_id
                else:
                    capture,_,actual_digest=_read_numeric_paid_metadata_v1(self.builder.session,self.graph.pair,issuer,ns,ref,meter)
                    call_id=capture.selected[('result','request')]['call_id']
                    if actual_digest!=digest:raise C09PagedCaptureHold('Numeric paid Source digest changed')
            fact=self.builder.transform.facts.lookup_model_original(call_id,meter=meter)
            if fact is None:raise C09PagedCaptureHold('orphan Numeric Graph call/paid original lacks actual frozen model facts')
            self.builder.transform._verify_model(fact,meter)
            result.after=(kind,ref);result.count+=1
            result.root=canonical_digest(('sylanne3.c09.numeric-core-reverse-member.v1',
                self.root,result.count,kind,ref,digest,fact.original_digest))
        self.builder.require_current();self.graph.require_current()
        return result


def advance_numeric_life_core_reverse_v1(builder):
    value=builder.numeric_core_reverse_v1
    if value is None:value=_NumericCoreReverseReadV1(_NUMERIC_REVERSE_TOKEN,builder)
    builder._pending_numeric_core_reverse_v1=value.advance()


def require_numeric_life_core_reverse_v1(builder):
    value=builder.numeric_core_reverse_v1
    if type(value)is not _NumericCoreReverseReadV1:
        raise AuthorityUnavailable('actual Numeric final reverse proof required')
    return value.require_complete(builder)


def preflight_numeric_frozen_native_v1(db,size):
    source=db._life_numeric_source_v1
    if type(source)is not _NumericFrozenGraphReadV1 or source not in _SOURCE_READS:
        raise AuthorityUnavailable('actual Numeric frozen native original reader required')
    source.preflight_native_v1(db,size)


def retain_numeric_frozen_native_v1(db,row,size):
    source=db._life_numeric_source_v1
    if type(source)is not _NumericFrozenGraphReadV1 or source not in _SOURCE_READS:
        raise AuthorityUnavailable('actual Numeric frozen native original reader required')
    source.retain_native_v1(db,row,size)


def retain_numeric_frozen_values_v1(db,values):
    source=db._life_numeric_source_v1
    if type(source)is not _NumericFrozenGraphReadV1 or source not in _SOURCE_READS:
        raise AuthorityUnavailable('actual Numeric decoded history arena required')
    source.retain_values_v1(db,values)


@contextmanager
def numeric_model_facts_source_v1(producer,core,graph,meter,budget):
    """Borrow only the actual pre-mirror facts producer's current connections."""
    from ..authority_service.c09_paged_recovery_facts_v2 import C09PagedRecoveryFactsProducerV2,C09RecoveryMeterV2,_BoundedReadConnectionV2
    actual=current_c09_sql_meter_v2()
    if (type(producer)is not C09PagedRecoveryFactsProducerV2 or type(meter)is not C09RecoveryMeterV2
            or type(graph)is not _BoundedReadConnectionV2 or graph.db is not producer.pair.source
            or graph.meter is not meter or meter.parent is not actual or actual.budget is not budget
            or producer._natural_model_connections_v3!=(core,graph,meter)
            or producer._natural_model_reservation_v3 is not budget):
        raise AuthorityUnavailable('Numeric facts require the actual source producer/current reservation interval')
    producer.session.require_current();producer.pair.require_current()
    source=_NumericFrozenGraphReadV1(producer.session,producer.pair,actual,_borrowed=graph)
    source.facts_binding=(producer,core,graph,meter,budget,producer.source,producer._verification_id,producer._readback_only)
    try:yield
    finally:source.close()


def read_numeric_frozen_model_source_rows_v1(db,*,namespace,seal,issuer,intent,permit,job,quote,installation,record,terminal):
    """Existing exact Numeric originals; never a new dispatch or paid assertion."""
    from .d06_life_numeric_worker_v1 import read_committed_life_numeric_request_v1
    from .d06_life_numeric_paid_v1 import read_life_numeric_cost_commit_v1
    from .d11_life_preparation_v1 import TABLE
    from ..model_broker.internal_life_numeric_v1 import WORK_KIND
    from ..authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
    from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
    source=db._life_numeric_source_v1
    if type(source)is not _NumericFrozenGraphReadV1 or source not in _SOURCE_READS:
        raise AuthorityUnavailable('actual Numeric frozen model Source registry required')
    source.require_current(db)
    binding=source.facts_binding
    if binding is None:raise AuthorityUnavailable('Numeric producer is outside its original facts capture phase')
    p,core,graph,meter,budget,old_seal,verification,readback=binding
    if (db is not graph or old_seal is not seal or p.source is not seal
            or p._natural_model_connections_v3!=(core,graph,meter)
            or p._natural_model_reservation_v3 is not budget or meter.parent is not current_c09_sql_meter_v2()
            or p._verification_id!=verification or p._readback_only!=readback
            or p.session is not source.session or p.pair is not source.pair
            or namespace!=source.namespace or job.work_kind!=WORK_KIND or issuer is not p.original_port.budget_job_issuer):
        raise AuthorityUnavailable('Numeric original facts proof left its actual capture/session/Graph/Core interval')
    prepared,worker,model=read_committed_life_numeric_request_v1(db,namespace=namespace,issuer=issuer,job_id=job.job_id)
    retain_numeric_frozen_values_v1(db,(prepared,worker,model,quote,intent,permit,terminal))
    sources=tuple(sorted((v.key.owner.subject,v.revision)for v in model.envelope.version_guard.read_versions
        if v.key.type_name=='memory.source' and v.revision>0))
    accesses=tuple(sorted((v.key.owner.subject,v.revision)for v in model.envelope.version_guard.read_versions
        if v.key.type_name=='memory.access' and v.revision>0))
    if ((prepared.namespace,prepared.job_id,prepared.call_id,prepared.installation_id,prepared.quote_id,
            prepared.quote_version,prepared.quote_digest,prepared.reservation_digest,prepared.operation_id,
            worker.acquire_operation_id,worker.worker_subject,worker.digest,model.digest,
            model.provider_id,model.model_id,model.max_output_tokens)!=
           (namespace,job.job_id,intent.call_id,installation,quote.quote_id,quote.version,canonical_digest(quote),
            intent.budget_reservation_digest,intent.budget_reservation_operation_id,
            intent.acquire_operation_id,intent.subject,intent.binding_digest,intent.request_digest,
            intent.provider_id,intent.model_id,intent.max_output_tokens)
            or (intent.authority_id,intent.namespace,intent.operation_id,intent.source_refs,intent.source_revisions,
                intent.access_revisions,intent.budget_lease_id,intent.provider_config_digest)!=
               (seal.authority_id,seal.namespace,worker.acquire_operation_id,tuple(ref for ref,_ in sources),sources,
                accesses,quote.parent_budget_lease_ref,prepared.frozen.appraisal.installation.provider_config_digest)
            or (intent.access_epoch,intent.delete_epoch)!=(model.envelope.version_guard.access_epoch,
                model.envelope.version_guard.delete_epoch)):
        raise C09PagedCaptureHold('Numeric original model differs from actual signed acquired request/worker/quote/Source set')
    kinds=['numeric_prepared_v1','numeric_binding_v1','numeric_request_v1','numeric_acquire_commit_v1']
    signed_call=db.execute('SELECT payload_digest FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
        (*namespace.as_tuple,'numeric_call_v1',job.job_id)).fetchone()
    if signed_call is None:
        if record.state!='prepared' or terminal is not None:
            raise C09PagedCaptureHold('Numeric actual execution lacks its original authenticated call seal')
    else:
        (saved_intent,saved_permit),_,operation=_numeric_signed_v1(db,issuer,namespace,'numeric_call_v1',job.job_id)
        if (saved_intent,saved_permit,operation)!=(intent,permit,worker.acquire_operation_id):
            raise C09PagedCaptureHold('Numeric actual Core original differs from its signed call/permit')
        kinds.append('numeric_call_v1')
    paid=_read_numeric_paid_metadata_v1(source.session,source.pair,issuer,namespace,job.job_id,current_c09_sql_meter_v2())
    if paid is not None:
        capture,operation,_=paid;selected=capture.selected
        if terminal is None:raise C09PagedCaptureHold('Numeric Graph paid original has no actual Core terminal')
        saved_terminal=model_from_wire(selected[('result','terminal_receipt')],ModelTerminalReceiptV2)
        request=selected[('result','request')]
        cost=read_life_numeric_cost_commit_v1(db,namespace=namespace,issuer=issuer,
            prepared=prepared,intent=intent,terminal=terminal)
        if (saved_terminal!=terminal or record.state!='observed'
                or selected[('prepared_digest',)]!=prepared.digest or selected[('binding_digest',)]!=worker.digest
                or request['model_request_digest']!=model.digest or request['call_id']!=intent.call_id
                or request['job_id']!=job.job_id or request['installation_id']!=installation
                or selected[('cost',)]!=plain_v1(cost) or selected[('cost_digest',)]!=canonical_digest(cost)
                or operation!=cost.operation_id):
            raise C09PagedCaptureHold('Numeric actual Core terminal differs from real paid original/cost membership')
        kinds.append('numeric_paid_v1');retain_numeric_frozen_values_v1(db,(capture.selected,cost))
    rows=[]
    for kind in kinds:
        row=db.execute('SELECT bot,persona,kind,original_ref,producing_operation_id,payload_json,payload_digest,signature '
            'FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',
            (*namespace.as_tuple,kind,job.job_id)).fetchone()
        if row is None:raise C09PagedCaptureHold('Numeric required signed original disappeared from its frozen Source')
        issuer._signer.verify('d11.life-original.v1',canonical_serialize((namespace,kind,job.job_id,row[6])),row[7])
        encoded=row[5].encode('ascii');current_c09_sql_meter_v2().charge_encode(len(encoded))
        if sha256(encoded).hexdigest()!=row[6]:
            raise C09PagedCaptureHold('Numeric actual source-row bytes differ from authenticated producer commitment')
        rows.append((TABLE,row))
    source.require_current(db)
    return tuple(rows)
