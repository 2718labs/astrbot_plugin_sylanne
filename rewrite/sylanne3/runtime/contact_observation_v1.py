"""Consume the actual Core Contact observation without reopening sent content.

This advances only the original quota/job/outbox observation facts and the
recovery stamp. Platform ACK is a handoff, not delivery; no fee or usage is
invented and the original message budget reservation remains unsettled.
"""
from ..runtime_storage_v3 import read_graph_row_v3,read_graph_rows_v3
from dataclasses import asdict, dataclass, replace
import json

from ..authority_service.contact_p2_contract_v1 import ContactObservationProjectionReadV1
from ..authority_service.v2_contract import canonical_digest as authority_digest
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec, GraphCandidate
from ..contracts import Event, Scope
from ..graph_store import GraphStore
from ..runtime_contracts import NamespaceId, FenceScope, canonical_digest, canonical_serialize, schema_hash
from ..domains.d10.contact_claim_v2 import contact_claim_key_v2, decode_contact_claim_v2
from .d11_types import RuntimeOutboxValue, job_graph_write
from .jobs import get_job, _save_job
from .dispatch_graph_claim import DispatchGraphClaimValueV1, dispatch_claim_key

TYPE = 'runtime.contact_platform_observation.v1'


@dataclass(frozen=True, slots=True)
class ContactPlatformObservationFactV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    activity_id: str
    effect_id: str
    handoff_id: str
    observation_id: str
    outcome: str
    observed_at_utc: str
    platform_message_id: str | None
    observed_receipt_digest: str
    binding_digest: str
    claimed_receipt_digest: str
    graph_claim_digest: str
    authority_after_anchor_digest: str
    schema: str = TYPE

    def __post_init__(self):
        if (self.schema!=TYPE or type(self.namespace) is not NamespaceId or self.outcome not in {'accepted','unknown'}
                or any(type(v) is not str or not v for v in (self.installation_id,self.operation_id,self.activity_id,
                    self.effect_id,self.handoff_id,self.observation_id,self.observed_at_utc))):
            raise ValueError('Contact observation actual finite fact identity differs')
        for value in (self.observed_receipt_digest,self.binding_digest,self.claimed_receipt_digest,
                self.authority_after_anchor_digest):
            if type(value) is not str or len(value)!=71 or not value.startswith('sha256:'):
                raise ValueError('Contact observation Authority original commitment differs')
        if type(self.graph_claim_digest) is not str or len(self.graph_claim_digest)!=64:
            raise ValueError('Contact observation actual Graph claim commitment differs')


def contact_platform_observation_from_wire_v1(raw):
    if type(raw) is not dict or set(raw)!=set(ContactPlatformObservationFactV1.__dataclass_fields__):
        raise ValueError('Contact observation exact metadata fields required')
    value=ContactPlatformObservationFactV1(**{**raw,'namespace':NamespaceId(**raw['namespace'])})
    if asdict(value)!=raw:
        raise ValueError('Contact observation canonical metadata differs')
    return value


def contact_platform_observation_key_v1(value):
    return AtomKey(Owner('activity',*value.namespace.as_tuple,value.activity_id),TYPE,value.observation_id)


def contact_platform_observation_type_spec_v1():
    return TypeSpec(TYPE,('activity',),'state',contact_platform_observation_from_wire_v1,
        immutable=True,writer_domain='d11',schema_hash=schema_hash({'type':TYPE,'version':1,
            'fields':sorted(ContactPlatformObservationFactV1.__dataclass_fields__),
            'authority':'actual Core platform observation; no delivery/read/fee/usage inference'}))


def consume_current_contact_observation_v1(graph, installed, *, operation_id, effect_id):
    from .contact_dispatch_host_v3 import _INSTALLED
    if _INSTALLED.get(id(installed)) is not installed or graph is not installed.graph:
        raise ValueError('Contact observation consumer requires its actual installed private writer')
    from ..graph_coordinator import namespace_ref
    grant=installed.port.installation_grant
    ns=installed.route_port._namespace
    from .contact_continuation_v1 import read_installed_contact_observation_locator_v1
    from ..authority_service.contact_continuation_contract_v1 import (ContactContinuationObservationV1,ContactContinuationObservationProjectionReadV1,contact_continuation_from_wire_v1)
    segment_original=read_installed_contact_observation_locator_v1(graph,installed,operation_id)
    if segment_original is not None and segment_original.segment_index>0:
        from ..host.contact_continuation_port_v1 import install_contact_continuation_port_v1
        observed=contact_continuation_from_wire_v1(segment_original.core_observation,ContactContinuationObservationV1)
        assembly=graph._GraphCoordinator__d04_installed_joint_assembly
        qualified=install_contact_continuation_port_v1(installed.port,assembly.admin_bundle).read_current_contact_continuation_observation_for_projection_v1(
            namespace=ns,authority_namespace=namespace_ref(ns),installation_id=grant.installation_id,holder=grant.administrator_holder,
            effect_id=effect_id,selector=observed.selector)
        if type(qualified)is not ContactContinuationObservationProjectionReadV1 or qualified.continuation!=observed:
            raise ValueError('Contact continuation lost its independent actual typed Core projection')
    else:
        qualified=installed.port.read_current_contact_observation_for_projection_v1(namespace=ns,
            authority_namespace=namespace_ref(ns),installation_id=grant.installation_id,holder=grant.administrator_holder,effect_id=effect_id)
        if type(qualified)is not ContactObservationProjectionReadV1:
            raise ValueError('First Contact observation current independently qualified Core read is absent')
    receipt=qualified.observed_receipt;permit=qualified.observed_permit
    observation=receipt.pending.platform_observation;binding=observation.binding
    if binding != receipt.pending.claimed_receipt.pending.binding:
        raise ValueError("Contact observed original binding differs from its actual claim")
    if (binding.operation_id!=operation_id or binding.origin.effect_id!=effect_id
            or qualified.namespace!=ns or qualified.installation_id!=grant.installation_id
            or binding.origin.proactive_contact is not True):
        raise ValueError('Contact observation actual original differs from requested effect')
    store=graph._GraphCoordinator__store;db=store._db
    with store._lock:
        metadata,epoch=graph._v2_graph_stamp(ns)
        filename=db.execute('PRAGMA database_list').fetchone()[2]
        from pathlib import Path
        file_stat=Path(filename).stat()
        if (Path(filename).resolve()!=Path(qualified.graph_path)
                or (file_stat.st_dev,file_stat.st_ino)!=(qualified.graph_device,qualified.graph_file_id)
                or metadata.requirements.graph_incarnation!=qualified.graph_incarnation
                or metadata.requirements.activation_generation!=permit.generation):
            raise ValueError('Contact observation current connected Graph/C09 identity differs')
        scope=FenceScope(ns,permit.namespace,permit.generation,'dispatch',operation_id,permit,
            permit.pinned_anchor,epoch,metadata.graph_revision)
    if qualified.fence_state=='active' and installed.port.validate_fence(scope)!=permit:
        raise ValueError('Contact observation actual observed dispatch permit changed')
    with store._lock:
        db.execute('BEGIN IMMEDIATE')
        try:
            if graph._v2_graph_stamp(ns)!=(metadata,epoch):
                raise ValueError('Contact observation Graph stamp changed before its CAS')
            from .dispatch_admission import load_request
            request=load_request(db,ns,binding.origin.admission_ref)
            if request is None or request[1].operation_id!=operation_id or request[1].effect_id!=effect_id:
                raise ValueError('Contact observation actual immutable dispatch request is absent')
            command=request[1]
            # Metadata-only scalar selectors; no Source/review/content JSON is loaded.
            row=db.execute("SELECT operation_kind,json_extract(original_payload_json,'$.provenance.job_ref'),"
                "json_extract(original_payload_json,'$.provenance.outbox_ref') FROM graph_domain_production_originals_v1 "
                'WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id)).fetchone()
            if row is None or row[0]!='prepare_contact_dispatch_v3':
                raise ValueError('Contact observation actual Contact adoption locator is absent')
            job_key,outbox_key=AtomKey.from_token(row[1]),AtomKey.from_token(row[2])
            claim_key=dispatch_claim_key(ns,effect_id)
            current_claim=read_graph_row_v3(db,columns=('revision', 'value', 'valid'),where='token=?',parameters=(claim_key.token,),history=False)
            if current_claim is None or current_claim[0]!=1 or current_claim[2]!=1:
                raise ValueError('Contact observation actual P2 Graph claim is absent')
            claim=DispatchGraphClaimValueV1(**json.loads(current_claim[1]))
            if (claim.operation_id!=operation_id or claim.handoff_id!=observation.handoff_id
                    or claim.binding_digest!=authority_digest(binding)
                    or claim.claimed_receipt_digest!=authority_digest(receipt.pending.claimed_receipt)
                    or claim.effect_id!=effect_id):
                raise ValueError('Contact observation actual claim/Authority observation link differs')
            fact=ContactPlatformObservationFactV1(ns,grant.installation_id,operation_id,binding.origin.activity_id,
                effect_id,observation.handoff_id,observation.observation_id,observation.outcome,observation.observed_at_utc,
                observation.platform_message_id,authority_digest(receipt),authority_digest(binding),
                authority_digest(receipt.pending.claimed_receipt),canonical_digest(json.loads(current_claim[1])),
                authority_digest(receipt.after_anchor))
            fact_key=contact_platform_observation_key_v1(fact)
            existing=read_graph_row_v3(db,columns=('revision', 'value', 'valid'),where='token=?',parameters=(fact_key.token,),history=False)
            event_id='contact-observation:'+observation.observation_id
            if existing is not None:
                history=read_graph_row_v3(db,columns=('event_id', 'value', 'valid'),where='token=? AND revision=1',parameters=(fact_key.token,),history=True)
                if (existing!=(1,canonical_serialize(asdict(fact)),1)
                        or history!=(event_id,canonical_serialize(asdict(fact)),1)):
                    raise ValueError('Contact observation replay lacks its exact committed fact')
                db.rollback()
            else:
                if qualified.fence_state!='active':
                    raise ValueError('Finished Contact observation permit cannot write a new projection')
                own_key=contact_claim_key_v2(ns,command.footprint.contact_id)
                own_row=read_graph_row_v3(db,columns=('revision', 'value', 'valid'),where='token=?',parameters=(own_key.token,),history=False)
                if own_row is None or own_row[0]<1 or own_row[2]!=1:
                    raise ValueError('Contact observation original quota claim is absent/invalidated')
                own=decode_contact_claim_v2(json.loads(own_row[1]))
                if (len(own.segment_effects)!=command.segment_count or own.segment_effects[command.segment_index]!=effect_id
                        or own.status in {'released','pending_confirmation'}
                        or dict(own.observations)!={prior:'accepted'for prior in own.segment_effects[:command.segment_index]}
                        or own.communication_action_id!=command.footprint.communication_action):
                    raise ValueError('Contact observation cannot change another quota or predecessor')
                next_own=own.observe(effect_id,observation.outcome)
                if db.execute("SELECT work_kind,continuation_json='{}' FROM runtime_jobs WHERE job_id=?",(job_key.name,)).fetchone()!=('message',1):
                    raise ValueError('Contact observation job is not its bodyless original message job')
                job=get_job(db,job_key.name)
                if (job.phase!='waiting' or job.cancel_epoch!=0 or job.fence!=0
                        or job.operation_id!=operation_id or job.effect_id!=effect_id):
                    raise ValueError('Contact observation original waiting job changed')
                outbox_row=read_graph_row_v3(db,columns=('revision', 'value', 'valid'),where='token=?',parameters=(outbox_key.token,),history=False)
                if outbox_row is None or outbox_row[2]!=1:
                    raise ValueError('Contact observation original outbox is absent')
                outbox=RuntimeOutboxValue(**json.loads(outbox_row[1]))
                if outbox.phase!='pending' or outbox.operation_id!=operation_id or outbox.effect_id!=effect_id:
                    raise ValueError('Contact observation original outbox changed')
                next_job=replace(job,phase='completed' if observation.outcome=='accepted' else 'pending_confirmation',
                    wake_condition=None,result_ref=observation.observation_id)
                next_outbox=replace(outbox,phase='ack' if observation.outcome=='accepted' else 'unknown')
                versions=[]
                for key in (own_key,job_key,outbox_key):
                    head=db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
                    if head is None:raise ValueError('Contact observation exact mutable member is absent')
                    versions.append(GraphVersion(key,head[0]))
                writes=(GraphWrite(own_key,asdict(next_own)),job_graph_write(next_job),
                    GraphWrite(outbox_key,asdict(next_outbox)),GraphWrite(fact_key,asdict(fact)))
                from datetime import datetime
                observed_utc=datetime.fromisoformat(observation.observed_at_utc.replace('Z','+00:00')).timestamp()
                event=Event(Scope(*ns.as_tuple,binding.origin.activity_id),event_id,observed_utc,'contact_platform_observation_v1',
                    {'authority_observation_digest':authority_digest(receipt),'outcome':observation.outcome})
                candidate=GraphCandidate(event,(*versions,GraphVersion(fact_key,0)),writes,(epoch,))
                anchor=receipt.after_anchor
                if not graph._accounting_anchor_covers(metadata.requirements,anchor):
                    raise ValueError('Contact observation recovery stamp cannot cover its actual Core observation')
                replacement=replace(metadata.requirements,deletion_seq=anchor.deletion_seq,deletion_digest=anchor.deletion_digest,
                    execution_seq=anchor.execution_seq,execution_digest=anchor.execution_digest,revocation_epoch=anchor.revocation_epoch)
                def committed(_db,actual):
                    if {v.key for v in actual.revisions}!={w.key for w in writes}:
                        raise ValueError('Contact observation atomic write set differs')
                    _save_job(db,next_job)
                    changed=db.execute('UPDATE graph_bundle_outbox SET phase=? WHERE bot=? AND persona=? AND outbox_ref=? AND operation_id=? AND phase=?',
                        (next_outbox.phase,*ns.as_tuple,outbox_key.token,operation_id,'pending')).rowcount
                    if changed!=1:raise ValueError('Contact observation durable outbox CAS changed')
                    store.cas_graph_recovery_metadata(metadata,replacement,_capability=graph._GraphCoordinator__graph_capability)
                GraphStore._graph_commit_in_transaction(store,candidate,_receipt_hook=committed,
                    _capability=graph._GraphCoordinator__graph_capability)
                db.commit()
        except BaseException:
            db.rollback();raise
    if qualified.fence_state=='active':
        installed.port.finish_fence(scope,request_id='finish:'+operation_id,request_digest='sha256:'+canonical_digest({
            'schema':'contact-observation-finish.v1','operation_id':operation_id,
            'observation_receipt_digest':authority_digest(receipt),'fact_digest':canonical_digest(asdict(fact))}))
    return fact
