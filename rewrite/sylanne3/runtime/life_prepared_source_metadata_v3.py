"""Pure signed Life preparation locators; no Work, Source or WRITE permission.

Each actual caller must bind the returned facts to its own canonical metadata
EOF task, exact row membership, current Owner and private Source registry.
"""
from dataclasses import dataclass,fields
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_serialize


@dataclass(frozen=True,slots=True)
class LifePreparedSourceMetadataV3:
    namespace: NamespaceId
    original_ref: str
    original_digest: str
    producing_operation_id: str
    schema: str
    source_roots: tuple[str,...]
    audiences: tuple[str,...]
    read_versions: tuple[GraphVersion,...]
    prepared_operation_id: str
    execution_id: str
    job_id: str
    job_cancel_epoch: int
    parent_budget_lease_ref: str
    deadline_utc: str


def life_prepared_locator_spec_v3(namespace,original_ref):
    if type(namespace)is not NamespaceId or type(original_ref)is not str or not original_ref:
        raise ValueError('Life preparation metadata requires its exact namespace and immutable reference')
    paths=(('schema',),('binding',),('prepare_operation_id',),('read_rows',),
        ('plan','schema'),('plan','audiences'),('plan','input_source'),('plan','input_access'),
        ('plan','project'),('plan','recipe'),('plan','action_intent'),('plan','parent_budget_lease_ref'),
        ('plan','deadline_utc'))
    return('graph_d11_life_originals_v1','payload_json',('bot','persona','kind','original_ref'),
        (*namespace.as_tuple,'prepared',original_ref),('producing_operation_id','payload_digest','signature'),paths,None)


def retain_life_prepared_locator_path_v3(path):
    if not path:return True
    if path[0]in {'schema','binding','prepare_operation_id'}:return True
    if path[0]=='read_rows':return len(path)<3 or path[2]in {'ref','revision','valid'}
    return path[0]=='plan'and(len(path)<2 or path[1]in {'schema','audiences','input_source','input_access',
        'project','recipe','action_intent','parent_budget_lease_ref','deadline_utc'})


def finish_life_prepared_locator_v3(*,namespace,original_ref,header,projection,fields_seen,
        whole_digest,signer):
    from .d11_life_preparation_v1 import D11LifePreparedV1,D11DraftPreparedV1,SIGN_KIND
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(namespace)is not NamespaceId or type(header)is not tuple or len(header)!=3:
        raise ValueError('Life preparation locator requires its exact signed full key and header')
    producer,payload_digest,signature=header
    if whole_digest!=payload_digest:raise ValueError('Life preparation locator lacks its complete canonical byte EOF')
    schemas={'d11.life-prepared.v1':D11LifePreparedV1,'d11.draft-prepared.v1':D11DraftPreparedV1}
    schema=projection.get('schema')
    if schema not in schemas or set(fields_seen)!={item.name for item in fields(schemas[schema])}:
        raise ValueError('Life preparation metadata changed its exact registered original schema/fields')
    signer.verify(SIGN_KIND,canonical_serialize((namespace,'prepared',original_ref,payload_digest)),signature)
    binding=projection['binding'];plan=projection['plan']
    expected_plan='d10.registered-draft-file-plan.v3'if schema=='d11.draft-prepared.v1'else'd10.registered-life-plan.v2'
    if(binding['namespace']!=plain_v1(namespace)or binding['prepared_original_ref']!=original_ref
            or binding['prepare_operation_id']!=producer or projection['prepare_operation_id']!=producer
            or plan['schema']!=expected_plan or binding['parent_budget_lease_ref']!=plan['parent_budget_lease_ref']
            or binding['deadline_utc']!=plan['deadline_utc']):
        raise ValueError('Life preparation metadata crossed namespace/producer/plan/Root/deadline')
    rows=tuple(projection['read_rows'])
    if not rows or len(rows)>1024 or len({row['ref']for row in rows})!=len(rows):
        raise ValueError('Life preparation locator requires its complete bounded unique actual read set')
    versions=[];roots=[]
    for row in rows:
        key=AtomKey.from_token(row['ref'])
        if(NamespaceId.from_key(key)!=namespace or type(row['revision'])is not int or row['revision']<0
                or type(row['valid'])is not bool):
            raise ValueError('Life preparation read locator has another namespace/revision/validity')
        versions.append(GraphVersion(key,row['revision']))
        if key.type_name=='memory.source':
            if row['revision']<1 or not row['valid']:raise ValueError('Life actual Source locator is not a positive valid original')
            roots.append(key.token)
    source=AtomKey.from_token(plan['input_source']['ref'])
    if source.type_name!='memory.source'or NamespaceId.from_key(source)!=namespace or source.token not in roots:
        raise ValueError('Life plan input Source is absent from the complete actual prepared read set')
    audiences=tuple(plan['audiences'])
    if not audiences or len(set(audiences))!=len(audiences)or any(type(value)is not str or not value or value=='*'for value in audiences):
        raise ValueError('Life prepared audiences must retain their exact finite original values')
    if type(binding['job_cancel_epoch'])is not int or binding['job_cancel_epoch']<0:
        raise ValueError('Life preparation must retain its actual cancellation epoch')
    return LifePreparedSourceMetadataV3(namespace,original_ref,payload_digest,producer,schema,
        tuple(roots),audiences,tuple(versions),producer,binding['execution_id'],binding['job_id'],
        binding['job_cancel_epoch'],binding['parent_budget_lease_ref'],binding['deadline_utc'])


def life_prepared_source_groups_v3(facts):
    if type(facts)is not LifePreparedSourceMetadataV3:raise TypeError('exact completed Life locator facts required')
    return tuple((purpose,(audience,),facts.source_roots)for audience in facts.audiences
        for purpose in ('context','consolidation'))
