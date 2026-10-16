"""Pure Contact two-purpose Source recipe; every issuer and Scope remains caller-specific."""
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..memory_types import source_key


def contact_plan_source_purpose_groups_v3(work,locator,roots):
    locator.require_v3(work)
    roots=tuple(sorted(set(roots)))
    if locator.source_purposes is not None:
        groups=dict(locator.source_purposes)
        if set(roots)!=set(groups):
            raise AuthorityUnavailable('Contact protected Plan/frozen roots escape signed per-ref purpose coverage')
    else:
        # Legacy Plan2 bytes remain unchanged. Only authenticated current metadata
        # can recover its exact two-use recipe; unknown embedded uses remain held.
        groups=dict(derive_contact_source_purpose_groups_metadata_v3(work.namespace,locator.plan_metadata,
            {ref:dict(witness.metadata)for ref,witness in work.sources.items()},
            {atom.key.token:atom.value for atom in work.atoms if atom.valid}))
        if set(roots)!=set(groups):
            raise AuthorityUnavailable('Contact Plan2 protected historical/frozen use has no exact actual metadata purpose')
    return tuple((ref,tuple(sorted(values)))for ref,values in sorted(groups.items()))


def require_contact_source_purpose_groups_v3(selection,work):
    from .contact_domain_source_v3 import ContactDomainSourceSelectionV3
    from .contact_host_source_v3 import ContactHostSourceSelectionV3
    from ..authority_service.contact_background_graph_v3 import ContactAuthoritySourceSelectionV3
    if type(selection)not in (ContactDomainSourceSelectionV3,ContactHostSourceSelectionV3,ContactAuthoritySourceSelectionV3):
        return None
    selection.require_v3(work)
    groups=dict(selection.purpose_groups)
    if set(groups)!=set(selection.roots) or any(not purposes or not set(purposes)<={'expression','context'}for purposes in groups.values()):
        raise AuthorityUnavailable('Contact Source purpose groups lost their exact private registered selection')
    return groups


def derive_contact_source_purpose_groups_metadata_v3(namespace,plan,sources,atoms):
    """Only data derivation. Registered callers independently prove all metadata EOF/rights."""
    route_ref=plan['route_account_ref']['ref']
    account=atoms.get(route_ref)
    if account is None or account['entity_id']!=plan['target_entity_ref']:
        raise AuthorityUnavailable('Contact purpose recipe has no exact actual route account metadata')
    evidence_ref=account['verification_ref'];evidence=atoms.get(evidence_ref)
    if (evidence is None or AtomKey.from_token(evidence_ref).type_name!='d03.world_event'
            or evidence['kind']!='message_received' or evidence['reality']!='host_observed'
            or len(evidence['source_refs'])!=1):
        raise AuthorityUnavailable('Contact purpose recipe has no unique actual observed route Source')
    expression={plan['source_ref']['ref']}
    for ref,value in atoms.items():
        if AtomKey.from_token(ref).type_name=='d05.boundary_rule' and value['target_entity_ref']==plan['target_entity_ref']:
            expression.update(value['source_refs'])
    groups,active,seen={},set(),set()
    def visit(ref,purpose):
        if (ref,purpose)in active:
            raise AuthorityUnavailable('Contact purpose Source ancestry is cyclic')
        if (ref,purpose)in seen:return
        if len(groups)>=256 and ref not in groups:
            raise AuthorityUnavailable('Contact purpose Source ancestry exceeds the original bound')
        key=AtomKey.from_token(ref);metadata=sources.get(ref)
        if key!=source_key(*namespace.as_tuple,key.owner.subject) or metadata is None:
            raise AuthorityUnavailable('Contact purpose recipe lacks an actual complete Source metadata ref')
        active.add((ref,purpose));groups.setdefault(ref,set()).add(purpose)
        for parent in metadata['parent_source_ids']:visit(source_key(*namespace.as_tuple,parent).token,purpose)
        active.remove((ref,purpose));seen.add((ref,purpose))
    for ref in sorted(expression):visit(ref,'expression')
    for ref in evidence['source_refs']:visit(ref,'context')
    return tuple((ref,tuple(sorted(values)))for ref,values in sorted(groups.items()))
