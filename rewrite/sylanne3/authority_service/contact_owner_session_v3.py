"""Closed Contact session observations and scoped Owner-key recovery proof.

No bearer, login request provenance or new grant is stored in these carriers.
Authentication is supplied by the installed RPC route, never by decoding a DTO.
"""
from dataclasses import asdict, dataclass, fields
import hashlib
import json
from .contract import AuthorityUnavailable, identifier
from .v2_owner_contract import OwnerPrincipalV1
from .v2_owner_proof import _time, _verify_signature, _sha256
from .v2_owner_session import AuthorityV2OwnerSessionStore, _canonical, _verifier, from_wire as session_from_wire

PURPOSE = 'contact_saved_owner_recovery_v3'
SCHEMA = 'sylanne3.contact-owner-session.v3'


def digest(value):
    return 'sha256:' + hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class ContactOwnerSessionObservationV3:
    authority_id: str
    authority_namespace: str
    installation_id: str
    principal: OwnerPrincipalV1
    actor: str
    verifier_commitment: str
    request_digest: str
    credential_id: str
    credential_epoch: int
    principal_epoch: int
    boot_commitment: str
    issued_at_utc: str
    expires_at_utc: str
    permit_digest: str
    authority_observation_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        if self.schema != SCHEMA or type(self.principal) is not OwnerPrincipalV1:
            raise ValueError('Contact session observation schema/principal differs')
        for name in ('authority_id','authority_namespace','installation_id','actor','credential_id'):
            identifier(getattr(self,name),name)
        for name in ('verifier_commitment','request_digest','boot_commitment','permit_digest','authority_observation_digest'):
            _sha256(getattr(self,name),name)
        if (type(self.credential_epoch) is not int or self.credential_epoch < 1
                or type(self.principal_epoch) is not int or self.principal_epoch < 0
                or _time(self.expires_at_utc) <= _time(self.issued_at_utc)):
            raise ValueError('Contact session epoch/expiry differs')

    @property
    def commitment(self):
        return digest(asdict(self))


@dataclass(frozen=True, slots=True)
class OwnerContactRecoveryUseV3:
    invocation_digest: str
    original_session_commitment: str
    new_verifier_commitment: str
    principal: OwnerPrincipalV1
    actor: str
    operation_id: str
    permit_digest: str
    deadline_utc: str
    purpose: str = PURPOSE
    schema: str = SCHEMA

    def __post_init__(self):
        if self.schema != SCHEMA or self.purpose != PURPOSE or type(self.principal) is not OwnerPrincipalV1:
            raise ValueError('Contact recovery-use schema/purpose/principal differs')
        for name in ('invocation_digest','original_session_commitment','new_verifier_commitment','permit_digest'):
            _sha256(getattr(self,name),name)
        identifier(self.actor,'actor');identifier(self.operation_id,'operation_id');_time(self.deadline_utc)

    def signed_bytes(self):
        return b'Sylanne3 Owner Contact saved recovery use v3\n' + json.dumps(
            asdict(self),sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def to_wire(value):
    kinds={ContactOwnerSessionObservationV3:'contact_owner_session_observation_v3',
           OwnerContactRecoveryUseV3:'owner_contact_recovery_use_v3'}
    if type(value) not in kinds:raise TypeError('closed Contact Owner carrier required')
    return {'kind':kinds[type(value)],**asdict(value)}


def from_wire(raw):
    kinds={'contact_owner_session_observation_v3':ContactOwnerSessionObservationV3,
           'owner_contact_recovery_use_v3':OwnerContactRecoveryUseV3}
    if type(raw) is not dict or type(raw.get('kind')) is not str or raw['kind'] not in kinds:
        raise ValueError('unknown Contact Owner carrier')
    cls=kinds[raw['kind']]
    if set(raw)!={f.name for f in fields(cls)}|{'kind'} or type(raw['principal']) is not dict or set(raw['principal'])!={f.name for f in fields(OwnerPrincipalV1)}:
        raise ValueError('Contact Owner carrier fields differ')
    parts={k:v for k,v in raw.items() if k!='kind'}
    parts['principal']=OwnerPrincipalV1(**parts['principal'])
    value=cls(**parts)
    if to_wire(value)!=raw:raise ValueError('noncanonical Contact Owner carrier')
    return value


def capture_in_tx(sessions, db, *, token, request, actor, permit_digest, authority_observation_digest):
    if type(sessions) is not AuthorityV2OwnerSessionStore:
        raise TypeError('actual Authority OwnerSessionStore required')
    sessions.require_current_in_tx(db,token=token,request=request)
    row=db.execute('SELECT request_json,principal_epoch,boot_id,issued_at_utc,expires_at_utc,revoked_at_utc '
        'FROM authority_owner_sessions_v1 WHERE verifier=?',(_verifier(token),)).fetchone()
    if row is None or row[0]!=_canonical(request) or row[5] is not None:
        raise AuthorityUnavailable('Contact current Owner session disappeared')
    return ContactOwnerSessionObservationV3(request.authority_id,request.authority_namespace,
        request.installation_id,request.principal,actor,'sha256:'+_verifier(token),
        'sha256:'+hashlib.sha256(row[0]).hexdigest(),request.credential_id,request.credential_epoch,
        row[1],digest(row[2]),row[3],row[4],permit_digest,authority_observation_digest)


def associate_in_tx(sessions, db, *, token, request, actor, original, use, signature,
                    permit_digest, authority_observation_digest):
    """Check actual old/new rows and registered key in the same Authority tx.

    An Authority reboot is intentionally HOLD: no explicit boot continuity or
    migration proof is available here. A Graph/Host restart keeps the Authority
    row and may use a fresh real login with its explicit scoped Owner signature.
    """
    if type(original) is not ContactOwnerSessionObservationV3 or type(use) is not OwnerContactRecoveryUseV3:
        raise AuthorityUnavailable('Contact recovery requires its closed original and use')
    new=capture_in_tx(sessions,db,token=token,request=request,actor=actor,
        permit_digest=permit_digest,authority_observation_digest=authority_observation_digest)
    if (use.original_session_commitment!=original.commitment
            or use.new_verifier_commitment!=new.verifier_commitment
            or use.principal!=original.principal or use.principal!=new.principal
            or use.actor!=original.actor or use.actor!=new.actor
            or use.permit_digest!=permit_digest or original.permit_digest!=permit_digest
            or original.authority_observation_digest!=authority_observation_digest
            or (original.authority_id,original.authority_namespace,original.installation_id,
                original.credential_id,original.credential_epoch,original.principal_epoch,original.boot_commitment)
            !=(new.authority_id,new.authority_namespace,new.installation_id,
                new.credential_id,new.credential_epoch,new.principal_epoch,new.boot_commitment)):
        raise AuthorityUnavailable('Contact recovery Owner/session/permit/continuity differs; HOLD')
    old=db.execute('SELECT request_json,principal_epoch,boot_id,issued_at_utc,expires_at_utc,revoked_at_utc '
        'FROM authority_owner_sessions_v1 WHERE verifier=?',(original.verifier_commitment[7:],)).fetchone()
    if (old is None or old[5] is not None or old[1]!=original.principal_epoch
            or digest(old[2])!=original.boot_commitment or old[2]!=sessions._boot_id
            or old[3:5]!=(original.issued_at_utc,original.expires_at_utc)
            or 'sha256:'+hashlib.sha256(old[0]).hexdigest()!=original.request_digest
            or sessions._now()>=min(_time(original.expires_at_utc),_time(use.deadline_utc))):
        raise AuthorityUnavailable('Contact original Owner session expired/revoked/unknown; HOLD')
    old_request=session_from_wire({'kind':'owner_session_login_request_v1',**json.loads(old[0])})
    if (old_request.principal!=request.principal or old_request.credential_id!=request.credential_id
            or old_request.credential_epoch!=request.credential_epoch
            or old_request.authority_namespace!=request.authority_namespace
            or old_request.installation_id!=request.installation_id
            or old_request.authority_id!=request.authority_id):
        raise AuthorityUnavailable('Contact original Owner login identity differs')
    sessions._current_key(db,old_request)
    key=sessions._current_key(db,request)
    if type(signature) is not bytes or len(signature)!=64:
        raise AuthorityUnavailable('Contact recovery-use Ed25519 signature required')
    _verify_signature(key,signature,use.signed_bytes(),'Contact recovery-use signature denied')
    return {'schema':SCHEMA,'kind':'contact_owner_session_association_v3',
        'original':to_wire(original),'current':to_wire(new),'use':to_wire(use),
        'association_digest':digest({'original':original.commitment,'current':new.commitment,'use':to_wire(use)})}


def validate_association_v3(raw,*,original,use,authority_observation_digest):
    """Closed authenticated-response decoder; parsing itself confers no rights."""
    expected={'schema','kind','original','current','use','association_digest'}
    if type(raw) is not dict or set(raw)!=expected or raw['schema']!=SCHEMA or raw['kind']!='contact_owner_session_association_v3':
        raise ValueError('Contact association closed fields/schema differ')
    if type(original) is not ContactOwnerSessionObservationV3 or type(use) is not OwnerContactRecoveryUseV3:
        raise TypeError('Contact association original/use concrete types required')
    current=from_wire(raw['current'])
    if (type(current) is not ContactOwnerSessionObservationV3 or raw['original']!=to_wire(original)
            or raw['use']!=to_wire(use) or original.commitment!=use.original_session_commitment
            or current.verifier_commitment!=use.new_verifier_commitment
            or current.principal!=use.principal or current.actor!=use.actor
            or current.permit_digest!=use.permit_digest
            or current.authority_observation_digest!=authority_observation_digest
            or original.authority_observation_digest!=authority_observation_digest
            or raw['association_digest']!=digest({'original':original.commitment,'current':current.commitment,'use':to_wire(use)})):
        raise ValueError('Contact association original/current/use commitments differ')
    return current
