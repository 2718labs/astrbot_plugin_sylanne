"""Engineering-only Root forensic channel; no product handler or read permission."""
from dataclasses import asdict,is_dataclass
from pathlib import Path
import hashlib
import json
import os
import socket
import sys
import time

REQUEST_SCHEMA='sylanne.test.beta1.root-forensic-request.v4'
RESPONSE_SCHEMA='sylanne.test.beta1.root-forensic-response.v4'

def _wire(value):
    if is_dataclass(value):return _wire(asdict(value))
    if type(value)is dict:return {k:_wire(v)for k,v in value.items()}
    if type(value)in(tuple,list):return [_wire(v)for v in value]
    if type(value)in(set,frozenset):return sorted(_wire(v)for v in value)
    return value

def _tuples(value):
    if type(value)is list:return tuple(_tuples(v)for v in value)
    if type(value)is dict:return {k:_tuples(v)for k,v in value.items()}
    return value

async def read_root_fixture_metadata_v4(case,request):
    from beta1_fixture_evidence_read_v3 import (Beta1FixtureEvidenceRequestV3,
        Beta1ExactNumericJobMetadataRequestV3,Beta1ExactD13JobMetadataRequestV3,
        Beta1NumericJobAbsenceMetadataRequestV3,Beta1NumericAcceptedMetadataRequestV3,
        Beta1FixtureMetadataEOFV3)
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    kinds={Beta1FixtureEvidenceRequestV3:'versions',Beta1ExactNumericJobMetadataRequestV3:'numeric',
        Beta1ExactD13JobMetadataRequestV3:'d13',Beta1NumericJobAbsenceMetadataRequestV3:'absence',
        Beta1NumericAcceptedMetadataRequestV3:'accepted'}
    selector={'kind':kinds[type(request)],'original_deadline_utc':request.original_deadline_utc}
    if type(request)is Beta1FixtureEvidenceRequestV3:
        selector.update(versions=[(v.key.token,v.revision)for v in request.versions],event_scopes=request.event_scopes)
    elif type(request)is Beta1NumericJobAbsenceMetadataRequestV3:
        work=request.identity_result_reference
        if work.state.result.require_result_v3(work)is not request.identity_value:
            raise ValueError('forensic absence locator did not come from the retained production identity reader')
        selector.update(job_id=request.job_id,identity=plain_v1(request.identity_value))
    else:
        selector.update(job_id=request.job_id,reservation_donor_selector=request.reservation_donor_selector)
        if type(request)is Beta1NumericAcceptedMetadataRequestV3:
            selector.update(adopt_receipt=plain_v1(request.adopt_receipt),expected_before_digest=request.expected_before_digest)
    worker=await case['get_http_worker']()
    def locate(graph):
        if graph is not case['graph']:raise ValueError('actual installed phase Graph required')
        return graph._GraphCoordinator__store._db.execute('PRAGMA database_list').fetchone()[2]
    graph_path=await worker.call(locate)
    payload={'schema':REQUEST_SCHEMA,'command':'snapshot_metadata','phase':os.environ['SYLANNE_QUAL_ROOT_CENSUS_PHASE'],
        'setup_sha256':os.environ['SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP_SHA256'],
        'manifest_sha256':case['policy'].manifest_digest,'graph_path':graph_path,'selector':selector}
    raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
    if len(raw)>65536:raise ValueError('Root forensic selector exceeds fixed channel bound')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)as client:
        client.settimeout(max(.001,min(30,request.original_deadline_utc-time.time())))
        client.connect(os.environ['SYLANNE_QUAL_ROOT_CENSUS_SOCKET']);client.sendall(raw);response=client.recv(65537)
    if len(response)>65536:raise ValueError('Root forensic result exceeds fixed channel bound')
    result=json.loads(response)
    if(result['schema']!=RESPONSE_SCHEMA or result['request_sha256']!=hashlib.sha256(raw).hexdigest()
            or result['manifest_sha256']!=case['policy'].manifest_digest or result['status']!='observed'):
        raise ValueError('actual Root forensic result/source binding differs')
    case.setdefault('beta1_forensic_originals_v4',[]).append({k:result[k]for k in ('snapshot_sha256','evidence_path','request_sha256','observed_at_utc')})
    if selector['kind']=='versions':
        rows=[]
        for row in result['value']:
            row=dict(row);row['event_scope']=tuple(row['event_scope']);row['metadata']=_tuples(row['metadata']);row['fields_seen']=frozenset(row['fields_seen'])
            rows.append(Beta1FixtureMetadataEOFV3(**row))
        return tuple(rows)
    return _tuples(result['value'])

def observe_root_fixture_metadata_v4(channel,request,raw):
    """Runs only inside the already placed, peer-checked engineering Root observer."""
    if os.geteuid()!=0 or channel.held is not None:raise PermissionError('Root forensic request cannot borrow an active C09 census hold')
    spec=channel.spec
    if(request['phase']!=channel.phase or request['setup_sha256']!=spec.phase_fixture_setup_sha256
            or request['manifest_sha256']!=spec.manifest_sha256 or time.monotonic()>=channel.deadline):
        raise ValueError('Root forensic phase/setup/manifest/deadline differs')
    setup=json.loads(Path(spec.phase_fixture_setup).read_bytes())
    graph=Path(request['graph_path']).resolve(strict=True);business=Path(setup['data_dir']).resolve(strict=True)
    if not graph.is_relative_to(business)or graph.is_symlink():raise ValueError('forensic Graph leaves actual isolated fixture data')
    info=graph.stat();held=False
    for fd in Path('/proc/'+str(channel.pid)+'/fd').iterdir():
        try:item=fd.stat()
        except FileNotFoundError:continue
        if(item.st_dev,item.st_ino)==(info.st_dev,info.st_ino):held=True;break
    if not held:raise ValueError('placed phase process does not hold the selected Graph file')
    # Parent observer has the engineering rewrite namespace. Import only the canonical
    # sylanne3 library from the exact extracted installed path; no product alias is added.
    library=Path(spec.installed_root)/'rewrite'
    if str(library)not in sys.path:sys.path.insert(0,str(library))
    from sylanne3.host import authority_profile as profile
    from rewrite.tests.alpha1.integration.beta1_fixture_evidence_read_v3 import (
        backup_artifact_v3_fixture_graph_v1,read_root_snapshot_metadata_v4)
    bundle=profile._load_installation_bundle_from_root(setup['profile_id'],Path(setup['profile_root']),'Linux')
    if bundle.installation_policy.manifest_digest!=spec.manifest_sha256:raise ValueError('Root forensic protected profile differs')
    for name,module in tuple(sys.modules.items()):
        if name.startswith('sylanne3')and getattr(module,'__file__',None)and not Path(module.__file__).resolve().is_relative_to(Path(spec.installed_root)):
            raise ValueError('Root forensic library imported outside selected installation')
    directory=Path(spec.evidence_directory)/'root-forensic';directory.mkdir(mode=0o700,exist_ok=True)
    index=len(tuple(directory.glob('snapshot-*.sqlite3')));snapshot=directory/('snapshot-'+str(index)+'.sqlite3')
    snapshot_pin=backup_artifact_v3_fixture_graph_v1(graph_path=graph,target=snapshot)
    value=read_root_snapshot_metadata_v4(snapshot=snapshot,bundle=bundle,selector=request['selector'],deadline=channel.deadline)
    evidence=directory/('observation-'+str(index)+'.json')
    result={'schema':RESPONSE_SCHEMA,'status':'observed','scope':'Root forensic assertion only; no live Owner/Source/read authority',
        'request_sha256':hashlib.sha256(raw).hexdigest(),'snapshot_sha256':snapshot_pin,
        'manifest_sha256':spec.manifest_sha256,'setup_sha256':spec.phase_fixture_setup_sha256,
        'observed_at_utc':time.time(),'phase':channel.phase,'evidence_path':str(evidence),'value':_wire(value)}
    encoded=json.dumps(result,sort_keys=True,separators=(',',':')).encode()
    if len(encoded)>65536:raise ValueError('Root forensic response exceeds existing fixed channel capacity')
    with evidence.open('xb')as stream:stream.write(encoded);stream.flush();os.fsync(stream.fileno())
    return encoded
