"""Actual Authority session rows and temporary registered Ed25519 recovery use.

This service-level acceptance does not claim mTLS/Graph/Host restart coverage.
"""
from dataclasses import replace
from datetime import timedelta
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.contact_owner_session_v3 import (
    capture_in_tx,associate_in_tx,OwnerContactRecoveryUseV3,to_wire,from_wire,digest,
)
from test_owner_session import setup,login


@pytest.fixture
def live(tmp_path):
    core,clock,key,proof,request,sessions=setup(tmp_path/'contact-owner.db')
    try:
        _,old_token=login(sessions,key,request)
        with core._tx() as db:
            original=capture_in_tx(sessions,db,token=old_token,request=request,actor='owner',
                permit_digest=digest('original-permit'),authority_observation_digest=digest('actual-guard'))
        _,new_token=login(sessions,key,request)
        with core._tx() as db:
            current=capture_in_tx(sessions,db,token=new_token,request=request,actor='owner',
                permit_digest=original.permit_digest,authority_observation_digest=original.authority_observation_digest)
        use=OwnerContactRecoveryUseV3(digest('invocation'),original.commitment,current.verifier_commitment,
            request.principal,'owner','contact-operation',original.permit_digest,'2029-01-01T00:10:00Z')
        yield core,clock,key,request,sessions,old_token,new_token,original,use
    finally:core.close()


def associate(live,**overrides):
    core,_,key,request,sessions,_,token,original,use=live
    kwargs=dict(token=token,request=request,actor='owner',original=original,use=use,
        signature=key.sign(use.signed_bytes()),permit_digest=original.permit_digest,
        authority_observation_digest=original.authority_observation_digest)
    kwargs.update(overrides)
    with core._tx() as db:return associate_in_tx(sessions,db,**kwargs)


def test_explicit_scoped_signature_associates_and_repeats_without_new_rows(live):
    core,_,_,_,_,old,new,original,use=live
    before=core._db.total_changes
    first=associate(live)
    assert associate(live)==first
    assert core._db.total_changes==before
    encoded=json.dumps(first)
    assert old not in encoded and new not in encoded and 'dashboard_origin' not in encoded
    assert from_wire(to_wire(original))==original
    assert from_wire(to_wire(use))==use
    from sylanne3.authority_service.contact_owner_session_v3 import validate_association_v3
    validate_association_v3(first,original=original,use=use,authority_observation_digest=original.authority_observation_digest)
    with pytest.raises(ValueError):validate_association_v3({**first,'extra':None},original=original,use=use,authority_observation_digest=original.authority_observation_digest)


@pytest.mark.parametrize('case',('wrong_key','login_signature','wrong_actor','wrong_principal',
    'wrong_session','wrong_permit','wrong_guard','changed_original','revoked_old','expired_old','expired_use'))
def test_actual_session_or_signed_scope_mismatch_holds(live,case):
    core,clock,key,request,sessions,old,new,original,use=live
    overrides={}
    if case=='wrong_key':overrides['signature']=Ed25519PrivateKey.generate().sign(use.signed_bytes())
    elif case=='login_signature':
        challenge=sessions.begin_login(transport_credential='installed-peer',request=request)
        overrides['signature']=key.sign(challenge.signed_bytes())
    elif case=='wrong_actor':overrides['actor']='other-owner'
    elif case=='wrong_principal':overrides['request']=replace(request,principal=replace(request.principal,account_ref='other'))
    elif case=='wrong_session':overrides['token']=old
    elif case=='wrong_permit':overrides['permit_digest']=digest('other-permit')
    elif case=='wrong_guard':overrides['authority_observation_digest']=digest('other-guard')
    elif case=='changed_original':overrides['original']=replace(original,request_digest=digest('other-request'))
    elif case=='revoked_old':sessions.logout(transport_credential='installed-peer',token=old,request=request)
    elif case=='expired_old':
        clock.now+=timedelta(hours=1)
        _,fresh=login(sessions,key,request)
        overrides['token']=fresh
        from sylanne3.authority_service.v2_owner_session import _verifier
        revised=replace(use,new_verifier_commitment='sha256:'+_verifier(fresh),deadline_utc='2029-01-01T02:00:00Z')
        overrides.update(use=revised,signature=key.sign(revised.signed_bytes()))
    elif case=='expired_use':clock.now+=timedelta(minutes=10)
    with pytest.raises((AuthorityUnavailable,ValueError)):associate(live,**overrides)


def test_recovery_purpose_cannot_be_replaced_by_login_audience(live):
    use=live[-1]
    with pytest.raises(ValueError):replace(use,purpose='sylanne-owner-console')
    for value in (to_wire(live[-2]),to_wire(use)):
        with pytest.raises(ValueError):from_wire({**value,'bearer':'forbidden'})
