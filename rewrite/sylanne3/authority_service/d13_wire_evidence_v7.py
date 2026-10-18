"""Explicit Core-signed V7 count originals and actual foreground reservation gate.



Metadata is immutable and independently signed. It does not grant Source access

or substitute current W01/Authority verification. No V6 signature is accepted.

"""

from dataclasses import asdict,replace

import json,sqlite3

from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest,canonical_serialize

from ..model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7,freeze_natural_reply_request_v7,TEMPLATE_DIGEST

from ..runtime.installed_d13_natural_frame_v7 import (NaturalHistoryPairV7,NaturalHistoryDecisionV7,

    core_collection_binding_digest_v7,core_paid_block_binding_v7,core_paid_blockset_digest_v7)

from .d13_core_counter_contract_v1 import (InstalledD13WirePolicyV7,D13CoreFrameIntentHeaderV7,

    D13CurrentWireCountSelectorV1,D13CoreFullWireEnvelopeV1,d13_core_counter_from_wire_v1,

    verify_signed_d13_core_wire_evidence_v1)

from .d13_wire_evidence_v1 import D13ForegroundBudgetBindingV1,D13ForegroundBudgetPreparationV1,_verify_foreground_budget



TABLE='graph_d13_core_wire_evidence_v1'

TABLE_DDL="CREATE TABLE graph_d13_core_wire_evidence_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,frame_intent_id TEXT NOT NULL,evidence_digest TEXT NOT NULL,policy_digest TEXT NOT NULL,c02_operation_id TEXT NOT NULL,selector_json TEXT NOT NULL,envelope_json TEXT NOT NULL,PRIMARY KEY(bot,persona,frame_intent_id))"

INDEX_DDL="CREATE INDEX graph_d13_core_wire_parent_v1 ON graph_d13_core_wire_evidence_v1(bot,persona,c02_operation_id,policy_digest)"

TRIGGER_DDLS=tuple((f'graph_d13_core_wire_evidence_v1_no_{action.lower()}',

    f"CREATE TRIGGER graph_d13_core_wire_evidence_v1_no_{action.lower()} BEFORE {action} ON {TABLE} BEGIN SELECT RAISE(ABORT,'immutable Core V7 full-wire original'); END") for action in ('UPDATE','DELETE'))





def install_d13_core_wire_evidence_schema_v1(db):

    for name,kind,ddl in ((TABLE,'table',TABLE_DDL),('graph_d13_core_wire_parent_v1','index',INDEX_DDL),

            *((name,'trigger',ddl) for name,ddl in TRIGGER_DDLS)):

        found=db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',(kind,name)).fetchone()

        if found is None:db.execute(ddl)

        elif found!=(ddl,):raise ValueError('registered V7 signed count schema differs')





def record_signed_d13_core_wire_evidence_v1(db,*,policy,selector,frame,envelope,now_utc):

    if not db.in_transaction:raise ValueError('Core V7 evidence import requires current fenced short transaction')

    if type(envelope) is dict:envelope=d13_core_counter_from_wire_v1(envelope,D13CoreFullWireEnvelopeV1)

    verify_signed_d13_core_wire_evidence_v1(policy,envelope,selector=selector,frame=frame,now_utc=now_utc)

    encoded=canonical_serialize(asdict(envelope));selector_json=canonical_serialize(asdict(selector))

    prior=db.execute(f'SELECT evidence_digest,policy_digest,c02_operation_id,selector_json,envelope_json FROM {TABLE} WHERE bot=? AND persona=? AND frame_intent_id=?',

        (*frame.namespace.as_tuple,frame.frame_intent_id)).fetchone()

    expected=(envelope.evidence_digest,policy.policy_digest,frame.c02_operation_id,selector_json,encoded)

    if prior is not None:

        if prior!=expected:raise ValueError('actual Core count original changed under same immutable frame')

        return envelope.evidence_digest

    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?)',(*frame.namespace.as_tuple,frame.frame_intent_id,*expected))

    return envelope.evidence_digest





def read_signed_d13_core_wire_original_v1(db,*,namespace,c02_operation_id,policy):

    if not db.in_transaction:raise ValueError('actual V7 original read requires current transaction')

    from .current_authority_graph_read_v3 import (read_bound_authority_graph_attachment_v3,

        read_bound_authority_graph_attachment_rows_v3)

    handled,identities=read_bound_authority_graph_attachment_rows_v3(db,table=TABLE,

        columns=('frame_intent_id',),key_columns=('bot','persona','c02_operation_id','policy_digest'),

        key=(*namespace.as_tuple,c02_operation_id,policy.policy_digest),order_column='frame_intent_id')

    if handled:

        if not identities:return None

        if len(identities)!=1:raise ValueError('actual V7 counter original absent or ambiguous')

        _,row=read_bound_authority_graph_attachment_v3(db,table=TABLE,

            columns=('evidence_digest','selector_json','envelope_json'),key_columns=('bot','persona','frame_intent_id'),

            key=(*namespace.as_tuple,identities[0][0]))

        request=(TABLE,('evidence_digest','selector_json','envelope_json'),('bot','persona','frame_intent_id'),

            (*namespace.as_tuple,identities[0][0]))

        from .current_authority_graph_read_v3 import require_current_authority_graph_read_work_v3

        work=require_current_authority_graph_read_work_v3(db,namespace,parent_original_id=c02_operation_id)

        attachment=work.attachments[request]

        if any(attachment.json_columns[name].byte_count>65536 for name in ('selector_json','envelope_json')):

            raise ValueError('actual V7 counter original absent or ambiguous')

    else:

        rows=db.execute(f'SELECT frame_intent_id,length(CAST(selector_json AS BLOB)),length(CAST(envelope_json AS BLOB)) FROM {TABLE} WHERE bot=? AND persona=? AND c02_operation_id=? AND policy_digest=? ORDER BY frame_intent_id LIMIT 2',

            (*namespace.as_tuple,c02_operation_id,policy.policy_digest)).fetchall()

        if not rows:return None

        if len(rows)!=1 or rows[0][1]>65536 or rows[0][2]>65536:raise ValueError('actual V7 counter original absent or ambiguous')

        row=db.execute(f'SELECT evidence_digest,selector_json,envelope_json FROM {TABLE} WHERE bot=? AND persona=? AND frame_intent_id=?',

            (*namespace.as_tuple,rows[0][0])).fetchone()

    digest,selector_json,envelope_json=row

    selector=d13_core_counter_from_wire_v1(json.loads(selector_json),D13CurrentWireCountSelectorV1)

    envelope=d13_core_counter_from_wire_v1(json.loads(envelope_json),D13CoreFullWireEnvelopeV1)

    if (canonical_serialize(asdict(selector))!=selector_json or canonical_serialize(asdict(envelope))!=envelope_json

            or envelope.evidence_digest!=digest or envelope.payload.frame.namespace!=namespace):

        raise ValueError('actual V7 original canonical bytes or namespace differ')

    return selector,envelope





def _check_pair_v7(pair,frame,evidence,policy):

    if type(pair) is not NaturalHistoryPairV7 or type(frame) is not D13CoreFrameIntentHeaderV7:

        raise ValueError('actual V7 current pair and Core fixed frame required')

    if (core_collection_binding_digest_v7(pair.collection,

            snapshot_commitment=pair.raw.input.history_selection.collection_snapshot_commitment,

            frozen_at_utc=frame.frozen_at_utc)!=frame.collection_digest

            or core_paid_blockset_digest_v7([core_paid_block_binding_v7(item) for item in pair.projected_blocks])!=frame.blockset_digest):

        raise ValueError('V7 independent Core collection or full paid blockset binding differs')

    from ..model_broker.d13_provider_http_template_v1 import provider_http_template_v1

    templates=tuple(None if frozen is None else provider_http_template_v1(frozen,

        generation_call_id=frame.generation_call_id,billing_contract_digest=frame.billing_contract_digest,

        serializer_pin=policy.serializer_fingerprint) for frozen in (pair.raw,pair.compressed))

    if ((templates[0].template_digest,templates[0].byte_count)!=

            (evidence.raw_http_template_digest,evidence.raw_http_bytes)

            or (None if templates[1] is None else (templates[1].template_digest,templates[1].byte_count))!=

            (None if evidence.compressed_http_template_digest is None else

                (evidence.compressed_http_template_digest,evidence.compressed_http_bytes))):

        raise ValueError('V7 independent signed complete SDK HTTP template differs')

    variants=(pair.raw,pair.compressed)

    for frozen in variants:

        if frozen is None:continue

        if (type(frozen) is not FrozenNaturalReplyRequestV7 or freeze_natural_reply_request_v7(frozen.input,frozen.installation)!=frozen

                or frozen.input.frozen_at_utc!=frame.frozen_at_utc or frozen.input.expires_at_utc!=frame.expires_at_utc

                or frozen.input.plan.plan_ref!=frame.plan_ref or frozen.input.plan.namespace!=frame.namespace

                or frozen.installation.installation_id!=frame.install_id):

            raise ValueError('V7 actual authority input differs from immutable Core frame')

    if (evidence.raw_authority_digest!=pair.raw.frozen_input_digest or evidence.raw_request_digest!=pair.raw.model_request_digest

            or (pair.compressed is None)!=(evidence.compressed_authority_digest is None)

            or pair.compressed is not None and (evidence.compressed_authority_digest!=pair.compressed.frozen_input_digest

                or evidence.compressed_request_digest!=pair.compressed.model_request_digest)):

        raise ValueError('independent Core evidence changed actual complete V7 pair')





def _verify_reserved_original_predicates_v7(port,*,original,current_collection,now_utc,paid_verifier,_prepared=None):

    if _prepared is not None:

        from ..runtime.installed_d13_natural_frame_v7 import _AuthorityCurrentNaturalFrameV7

        if type(_prepared) is not _AuthorityCurrentNaturalFrameV7:raise ValueError('actual Authority V7 EOF replay required')

        digests,http_bytes,prepared_row=_prepared.require_wire_inputs_v7(port,

            original=original,current_collection=current_collection,now_utc=now_utc)

    if (type(port._budget) is not D13ForegroundBudgetBindingV1 or type(original) is not FrozenNaturalReplyRequestV7

            or _prepared is None and freeze_natural_reply_request_v7(original.input,original.installation)!=original):

        raise ValueError('V7 requires exact saved reserved original, not a new current-epoch freeze')

    selection=original.input.history_selection

    if (canonical_digest(replace(current_collection.window,trusted_utc=original.input.frozen_at_utc))

            if _prepared is None else digests['window_digest'])!=selection.window_digest:

        raise ValueError('V7 original current Source/rights/order/body changed')

    cursors=tuple((page.before_sequence,page.max_slots,page.first_sequence,page.last_sequence) for page in current_collection.pages)

    if cursors!=selection.page_cursors:raise ValueError('V7 original page cursors changed')

    original_row=(read_signed_d13_core_wire_original_v1(port._db,namespace=original.input.plan.namespace,

        c02_operation_id=port._parent,policy=port._policy) if _prepared is None else prepared_row)

    if original_row is None:raise ValueError('V7 independent original Core count unavailable')

    selector,envelope=original_row;frame=envelope.payload.frame

    evidence=verify_signed_d13_core_wire_evidence_v1(port._policy,envelope,selector=selector,frame=frame,now_utc=now_utc)

    selected_raw=evidence.raw_authority_digest==original.frozen_input_digest

    expected_authority=evidence.raw_authority_digest if selected_raw else evidence.compressed_authority_digest

    expected_request=evidence.raw_request_digest if selected_raw else evidence.compressed_request_digest

    if expected_authority!=original.frozen_input_digest or expected_request!=original.model_request_digest:

        raise ValueError('V7 signed original semantic variant differs')

    if (frame.frozen_at_utc,frame.expires_at_utc,frame.namespace,frame.plan_ref)!=(original.input.frozen_at_utc,

            original.input.expires_at_utc,original.input.plan.namespace,original.input.plan.plan_ref):

        raise ValueError('V7 original Core frame identity or lifetime changed')

    if (core_collection_binding_digest_v7(current_collection,

            snapshot_commitment=selection.collection_snapshot_commitment,

            frozen_at_utc=frame.frozen_at_utc) if _prepared is None else digests['collection_digest'])!=frame.collection_digest:

        raise ValueError('V7 immutable collection binding differs from current original Source inventory')

    from ..model_broker.d13_provider_http_template_v1 import provider_http_template_v1

    if _prepared is None:

        template=provider_http_template_v1(original,generation_call_id=frame.generation_call_id,

            billing_contract_digest=frame.billing_contract_digest,serializer_pin=port._policy.serializer_fingerprint)

        template_facts=(template.template_digest,template.byte_count)

    else:template_facts=(digests['template_digest'],http_bytes)

    if template_facts!=(

            evidence.raw_http_template_digest if selected_raw else evidence.compressed_http_template_digest,

            evidence.raw_http_bytes if selected_raw else evidence.compressed_http_bytes):

        raise ValueError('V7 saved original changed its actual signed HTTP template')

    if selection.block_refs:

        from ..runtime.installed_d13_natural_frame_v6 import read_current_derived_blocks_v6

        if paid_verifier is None:raise ValueError('V7 current paid block authority unavailable')

        if _prepared is None:

            blocks=read_current_derived_blocks_v6(port._db,collection=current_collection,question=original.input.question,

                paid_verifier=paid_verifier.for_current_read_v2(now_utc))

        else:

            actual_paid,blocks=_prepared.paid_reader.require_current_v6(_prepared.work)

            if actual_paid is not paid_verifier:raise ValueError('V7 actual paid verifier changed after qualification')

        by_ref={item.ref.ref:item for item in blocks}

        for index,ref in enumerate(selection.block_refs):

            item=by_ref.get(ref.ref)

            if item is None or item.ref!=ref or now_utc>=item.metadata.expires_at_utc:

                raise ValueError('V7 original paid block head or expiry changed')

            part=next((part for part in original.input.stable_history if part.ref==ref),None)

            rows=tuple(turn for turn in original.input.stable_turns if turn.block_index==index)

            actual=tuple((turn.sequence,turn.speaker_ref,turn.text) for turn in item.block.timeline)

            if (part is None or part.dependencies!=item.block.source_dependencies

                    or tuple((turn.sequence,turn.speaker_ref,turn.text) for turn in rows)!=actual):

                raise ValueError('V7 original stable semantics differ from actual paid block body')

    from dataclasses import asdict

    from ..domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_history_v2

    from ..runtime.d11_derived_cache_payload_v1 import require_actual_derived_metadata_activation_v6

    from ..runtime_contracts import VersionedRef

    bindings=[asdict(value) for value in frame.block_bindings]

    if not selected_raw:

        if tuple(row['metadata_ref'] for row in bindings)!=tuple(ref.ref for ref in selection.block_refs):

            raise ValueError('V7 original selected paid block order differs from Core frozen complete set')

        actual_bindings=[]

        for bound,ref in zip(bindings,selection.block_refs):

            item=by_ref[ref.ref]

            from .current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3

            handled,historic=read_bound_authority_graph_attachment_v3(port._db,table='graph_history',

                columns=('value','valid'),key_columns=('token','revision'),

                key=(bound['metadata_ref'],bound['metadata_revision']))

            if not handled:

                historic=port._db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',

                    (bound['metadata_ref'],bound['metadata_revision'])).fetchone()

            if historic is None or historic[1]!=1:raise ValueError('V7 original paid metadata birth unavailable')

            before=decode_derived_block_metadata_history_v2(AtomKey.from_token(bound['metadata_ref']),json.loads(historic[0]))

            before_ref=VersionedRef(bound['metadata_ref'],bound['metadata_revision'])

            actual=core_paid_block_binding_v7(item,metadata=before,metadata_ref=before_ref)

            if actual!=bound:raise ValueError('V7 Core frozen paid/payload/plan/expiry binding differs')

            if before_ref!=item.ref or before!=item.metadata:

                require_actual_derived_metadata_activation_v6(port._db,before,before_ref,item.metadata,item.ref)

            actual_bindings.append(actual)

        if core_paid_blockset_digest_v7(actual_bindings)!=frame.blockset_digest:

            raise ValueError('V7 original full paid blockset root differs')

    upper=evidence.raw_upper_tokens if selected_raw else evidence.compressed_upper_tokens

    if upper>min(port._policy.max_input_tokens,port._policy.context_limit_tokens-port._policy.installation.max_output_tokens-port._policy.tool_reserve_tokens):

        raise ValueError('V7 original complete HTTP cannot fit unchanged model capacity')

    grant=port._issuer.current_budget_grant(port._db,port._budget.lease_id)

    if frame.parent_budget_lease_ref!=port._budget.lease_id or canonical_digest(grant)!=frame.budget_grant_digest:

        raise ValueError('V7 original signed parent grant or lease changed')

    budget=_verify_foreground_budget(port._db,port._policy,port._budget,port._resource,port._issuer,original,upper,now_utc)

    return NaturalHistoryDecisionV7('raw' if selected_raw else 'compressed',evidence.token_evidence,'activation_not_attempted',

        port.policy_digest,original.model_request_digest,canonical_digest({'core_original':envelope.evidence_digest,'budget':budget}),

        budget_state='reserved_original')





class InstalledD13WireEvidencePortV7:

    def __init__(self,db,*,policy,foreground_budget,resource_issuer,budget_issuer,c02_operation_id):

        if type(db) is not sqlite3.Connection or type(policy) is not InstalledD13WirePolicyV7:

            raise ValueError('actual installed V7 policy and Graph reader required')

        self._db,self._policy,self._budget=db,policy,foreground_budget

        self._resource,self._issuer=resource_issuer,budget_issuer

        self._parent=c02_operation_id;self.policy_digest=policy.policy_digest

        self._last_pair=None;self._quote_read_versions=None

    def evaluate_natural_pair_v7(self,*,pair,now_utc):

        original=read_signed_d13_core_wire_original_v1(self._db,namespace=pair.raw.input.plan.namespace,

            c02_operation_id=self._parent,policy=self._policy)

        if original is None:return None

        selector,envelope=original;frame=envelope.payload.frame

        evidence=verify_signed_d13_core_wire_evidence_v1(self._policy,envelope,selector=selector,frame=frame,now_utc=now_utc)

        _check_pair_v7(pair,frame,evidence,self._policy)

        grant=self._issuer.current_budget_grant(self._db,self._budget.lease_id)

        if (frame.parent_budget_lease_ref!=self._budget.lease_id or canonical_digest(grant)!=frame.budget_grant_digest):

            raise ValueError('Core frame count crossed current actual signed parent grant or lease')

        maximum=min(self._policy.max_input_tokens,self._policy.context_limit_tokens-self._policy.installation.max_output_tokens-self._policy.tool_reserve_tokens)

        if evidence.raw_upper_tokens<=maximum:selected='raw';frozen=pair.raw;upper=evidence.raw_upper_tokens

        elif (pair.compressed is not None and evidence.compressed_upper_tokens<=maximum

                and (evidence.raw_lower_tokens>maximum or self._policy.allow_conservative_switch)):

            selected='compressed';frozen=pair.compressed;upper=evidence.compressed_upper_tokens

        else:raise ValueError('V7 signed complete HTTP bounds exceed unchanged installed model capacity')

        budget=_verify_foreground_budget(self._db,self._policy,self._budget,self._resource,self._issuer,frozen,upper,now_utc,

            quote_read_versions=self._quote_read_versions)

        decision=NaturalHistoryDecisionV7(selected,evidence.token_evidence,'activation_prepared' if selected=='compressed' and pair.activation_writes else 'activation_not_attempted',

            self.policy_digest,frozen.model_request_digest,canonical_digest({'core_original':envelope.evidence_digest,'budget':budget}),

            pair.activation_writes if selected=='compressed' else (),pair.activation_reads if selected=='compressed' else (),

            'preparation_only' if type(self._budget) is D13ForegroundBudgetPreparationV1 else 'reserved_original',pair)

        self._last_pair=(pair,decision,envelope.evidence_digest)

        return decision

    def verify_reserved_original_v7(self,*,original,current_collection,now_utc,paid_verifier):

        return _verify_reserved_original_predicates_v7(self,original=original,

            current_collection=current_collection,now_utc=now_utc,paid_verifier=paid_verifier)



    def validate_reserved_selection_v7(self,*,selected,decision,binding,read_versions,now_utc):

        if (not self._db.in_transaction or type(self._budget) is not D13ForegroundBudgetPreparationV1

                or type(binding) is not D13ForegroundBudgetBindingV1 or type(decision) is not NaturalHistoryDecisionV7

                or decision.budget_state!='preparation_only' or self._last_pair is None):

            raise ValueError('V7 exact prior Corecount preparation and reserved secondgate required')

        pair,prior,_digest=self._last_pair

        if decision!=prior or selected!=(pair.raw if decision.selected=='raw' else pair.compressed):

            raise ValueError('V7 selected wire changed between Corecount and reservation')

        if (binding.lease_id,binding.reservation_operation_id)!=(self._budget.lease_id,self._budget.reservation_operation_id):

            raise ValueError('V7 same foreground reservation operation required')

        self._budget=binding;self._quote_read_versions=read_versions

        admitted=self.evaluate_natural_pair_v7(pair=pair,now_utc=now_utc)

        if admitted is None or admitted.selected!=decision.selected or admitted.budget_state!='reserved_original':

            raise ValueError('V7 secondgate did not verify actual reserved original')

        return admitted





def validate_reserved_d13_natural_selection_v7(port,**kwargs):

    if type(port) is not InstalledD13WireEvidencePortV7:raise ValueError('actual V7 installed reservation port required')

    return port.validate_reserved_selection_v7(**kwargs)
