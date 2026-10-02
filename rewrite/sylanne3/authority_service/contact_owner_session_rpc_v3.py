"""Installed current-session observation and explicit recovery association RPC."""
from .contract import AuthorityUnavailable
from .contact_owner_session_v3 import capture_in_tx, associate_in_tx, from_wire, to_wire, digest
from .d12_target_owner_rpc_v1 import dispatch_d12_target_owner_v1, METHOD as OWNER_METHOD

CAPTURE='capture_current_contact_owner_session_v3'
ASSOCIATE='associate_contact_owner_recovery_v3'
BASE={'namespace','permit','owner_actor_id','owner_session_token','owner_session_request'}


def dispatch_contact_owner_session_v3(server,method,credential,profile_id,manifest_digest,command):
    if method not in {CAPTURE,ASSOCIATE}:return None
    expected=BASE if method==CAPTURE else BASE|{'original','use','signature'}
    if type(command) is not dict or set(command)!=expected:
        raise AuthorityUnavailable('Contact Owner RPC closed fields differ')
    base={key:command[key] for key in BASE}
    # This installed path validates transport/profile, original content permit,
    # pairing, actual current Owner guard and target/storage admission.
    observed=dispatch_d12_target_owner_v1(server,OWNER_METHOD,credential,profile_id,manifest_digest,base)
    sessions=server._v2_owner_sessions
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    namespace=command['namespace']
    if sessions is None or sessions._core is not server._core:
        raise AuthorityUnavailable('Contact original OwnerSessionStore unavailable')
    server._core._require(credential,'owner_session',namespace)
    kwargs=server._owner_session_kwargs(command,namespace,installed.installation_id)
    with server._core._tx() as db:
        common=dict(token=kwargs['session_token'],request=kwargs['session_request'],
            actor=command['owner_actor_id'],permit_digest=digest(command['permit']),
            authority_observation_digest=digest(observed))
        if method==CAPTURE:
            result=to_wire(capture_in_tx(sessions,db,**common))
        else:
            try:signature=bytes.fromhex(command['signature'])
            except (ValueError,TypeError) as exc:raise AuthorityUnavailable('Contact signature encoding differs') from exc
            if signature.hex()!=command['signature']:raise AuthorityUnavailable('Contact signature is not canonical hex')
            result=associate_in_tx(sessions,db,original=from_wire(command['original']),
                use=from_wire(command['use']),signature=signature,**common)
    # Authentication is still current on return; equality prevents a stale
    # target/storage/Owner guard from spanning the session read transaction.
    after=dispatch_d12_target_owner_v1(server,OWNER_METHOD,credential,profile_id,manifest_digest,base)
    if after!=observed:raise AuthorityUnavailable('Contact Owner authority drifted across observation')
    return {'observation':result,'authority':observed}
