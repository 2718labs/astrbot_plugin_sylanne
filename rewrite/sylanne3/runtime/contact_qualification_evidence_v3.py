"""Closed Contact qualification originals and independent SQL verification.

The evidence is recorded only by the installed post-CAS stage. Decoding or
recomputing it never issues permission, a provider check, or a sender handle.
"""
from dataclasses import dataclass
import json

from ..authority_service.d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1
from ..authority_service.v2_contract import AuthorityCurrentEffectSnapshotV2
from ..authority_service.v2_execution_bridge import CurrentEffectReadV2
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d06 import source_correction_head_key
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contact_final_action_v1 import CONTACT_REQUIRED_PROVIDERS_V1
from .contact_qualification_v3 import CurrentContactQualificationV3
from .contact_route_binding_v1 import CurrentContactRouteBindingV1, contact_route_semantic_digest_v1
from .d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from .domain_production_contracts_v1 import ProductionOwnerGuardV1, ProductionQueryCoverageV1

CONTACT_FINAL_QUERY_TYPES_V3 = (
    'd03.account_binding', 'd03.entity_anchor', 'd03.role_binding', 'd05.boundary_rule',
    'd10.contact_policy.v1', 'd10.proactive_opportunity.v1', 'd10.contact_claim.v1', 'd10.contact_claim.v2',
    'd08.contact_expression_plan.v2', 'd08.contact_expression_plan_provenance.v2', 'd08.contact_expression_plan_eligibility.v2',
    'd08.commitment.v1', 'd08.action_intent.v1', 'd08.action_outcome.v1', 'd08.action_cancellation.v1',
)


@dataclass(frozen=True, slots=True)
class ContactQualificationEvidenceV3:
    namespace: NamespaceId
    operation_id: str
    activation_generation: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    now_utc: float
    deadline_utc: float
    audience: str
    expression_roots: tuple[str, ...]
    context_roots: tuple[str, ...]
    structural_roots: tuple[str, ...]
    route: CurrentContactRouteBindingV1
    qualification: CurrentContactQualificationV3
    members: tuple[OfflineTickGraphReadV1, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    owner_guard: ProductionOwnerGuardV1
    owner_policy: D10ContactPolicyOriginalV1
    current_effect: CurrentEffectReadV2
    effect_snapshot: AuthorityCurrentEffectSnapshotV2
    schema: str = 'd08.contact-final-qualification-evidence.v3'

    def __post_init__(self):
        if (self.schema != 'd08.contact-final-qualification-evidence.v3'
                or type(self.namespace) is not NamespaceId or type(self.operation_id) is not str or not self.operation_id
                or any(type(getattr(self, field)) is not int or getattr(self, field) < 0 for field in
                    ('activation_generation','graph_epoch','access_epoch','delete_epoch'))
                or self.activation_generation < 1 or self.graph_epoch < 1
                or type(self.qualification) is not CurrentContactQualificationV3
                or type(self.route) is not CurrentContactRouteBindingV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.owner_policy) is not D10ContactPolicyOriginalV1
                or type(self.current_effect) is not CurrentEffectReadV2
                or type(self.effect_snapshot) is not AuthorityCurrentEffectSnapshotV2
                or type(self.members) is not tuple or not 1 <= len(self.members) <= 1024
                or any(type(row) is not OfflineTickGraphReadV1 for row in self.members)
                or len({row.ref for row in self.members}) != len(self.members)
                or type(self.query_coverage) is not tuple
                or any(type(page) is not ProductionQueryCoverageV1 for page in self.query_coverage)):
            raise ValueError('Contact qualification evidence is not the closed installed type')
        self.validate_structure()

    def validate_structure(self):
        q, ns = self.qualification, self.namespace
        versions = q.check_versions
        if (versions.namespace != ns or versions.graph_epoch != self.graph_epoch
                or len(q.checks) != 6 or len(versions.sets) != 6
                or tuple((check.check_kind,check.issuer) for check in q.checks) != CONTACT_REQUIRED_PROVIDERS_V1
                or len({row.kind for row in versions.sets}) != 6
                or {row.kind for row in versions.sets} != {kind for kind,_ in CONTACT_REQUIRED_PROVIDERS_V1}
                or not self.now_utc < self.deadline_utc
                or any(check.coverage != 'full' or check.result != 'pass'
                    or check.purpose != 'expression' or check.subject_ref != 'persona:'+ns.persona_id
                    or check.action_ref != q.d08_scope.action_id or check.valid_until <= self.now_utc
                    or check.valid_until > self.deadline_utc for check in q.checks)):
            raise ValueError('Contact qualification lacks its six complete provider/version closures')
        sets = {row.kind:row for row in versions.sets}
        for check in q.checks:
            row = sets[check.check_kind]
            if (check.input_versions != row.versions or not row.versions
                    or len({v.ref for v in row.versions}) != len(row.versions)
                    or row.criteria_ref not in {v.ref for v in row.versions}):
                raise ValueError('Contact qualification provider criterion/input versions differ')
        rows = {row.ref:row for row in self.members}
        actions=tuple(AtomKey.from_token(row.ref).name for row in self.members if row.valid
            and AtomKey.from_token(row.ref).type_name == 'd08.action_intent.v1'
            and AtomKey.from_token(row.ref).name == q.d08_scope.action_id)
        if actions != (q.d08_scope.action_id,):
            raise ValueError('Contact qualification action identity has no unique actual Graph member')
        from ..domains.d08.execution import GoalExecutionProvider
        action_validator = next(spec.validator for spec in GoalExecutionProvider().register_types()
            if spec.name == 'd08.action_intent.v1')
        action_member = next(row for row in self.members if row.valid
            and AtomKey.from_token(row.ref).type_name == 'd08.action_intent.v1'
            and AtomKey.from_token(row.ref).name == q.d08_scope.action_id)
        action = action_validator(json.loads(action_member.value_json))
        from .contact_policy_bound_v3 import validate_contact_policy_bound_members_v3
        validate_contact_policy_bound_members_v3(q.contact_policy_bound,
            members=self.members, namespace=ns, owner_policy=self.owner_policy,
            action=action, now_utc=self.now_utc, deadline_utc=self.deadline_utc)
        if canonical_serialize(q.checks[5]) != canonical_serialize(q.contact_policy_bound.bounded_receipt):
            raise ValueError('Contact qualification substituted its native bounded policy receipt')
        for row in self.members:
            key = AtomKey.from_token(row.ref)
            if NamespaceId.from_key(key) != ns or row.revision == 0 and (row.valid or row.value_json != '{}'):
                raise ValueError('Contact qualification member namespace/absence differs')
        actual_positive = tuple(sorted((GraphVersion(AtomKey.from_token(row.ref),row.revision)
            for row in self.members if row.valid),key=lambda v:v.key.token))
        if versions.read_versions != actual_positive or any(
                rows.get(v.key.token) is None or rows[v.key.token].revision != v.revision or not rows[v.key.token].valid
                for v in q.positive_reads):
            raise ValueError('Contact qualification full positive read inventory differs')
        route=self.route
        if (route.namespace != ns or route.query.namespace != ns or route.query.revision != self.graph_epoch
                or route.conversation_ref != self.audience or self.context_roots != (route.source_ref,)
                or q.route_semantic_digest != contact_route_semantic_digest_v1(route)
                or any(rows.get(v.key.token) is None or rows[v.key.token].revision != v.revision or not rows[v.key.token].valid
                    for v in (route.account_version,route.entity_version,route.evidence_version))):
            raise ValueError('Contact qualification actual route binding differs')
        account=json.loads(rows[route.account_version.key.token].value_json)
        entity=json.loads(rows[route.entity_version.key.token].value_json)
        event=json.loads(rows[route.evidence_version.key.token].value_json)
        if (account.get('verification_ref') != route.evidence_version.key.token or account.get('entity_id') != route.target_entity_ref
                or (account.get('platform_namespace'),account.get('platform_identifier')) != (route.platform_ref,route.sender_ref)
                or entity.get('entity_id') != route.target_entity_ref or event.get('source_refs') != [route.source_ref]):
            raise ValueError('Contact qualification route SQL member joins differ')
        if (len(self.query_coverage) != len(CONTACT_FINAL_QUERY_TYPES_V3)
                or {page.type_id for page in self.query_coverage} != set(CONTACT_FINAL_QUERY_TYPES_V3)):
            raise ValueError('Contact qualification required negative query inventory differs')
        for page in self.query_coverage:
            expected = tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in sorted(
                self.members,key=lambda item:item.ref) if row.revision and AtomKey.from_token(row.ref).type_name == page.type_id)
            if (not page.complete or page.continuation_ref is not None
                    or page.epoch.namespace != ns or page.epoch.revision != self.graph_epoch
                    or page.row_versions != expected):
                raise ValueError('Contact qualification complete query coverage differs')
        owner = rows.get(self.owner_guard.grant_ref)
        if (owner is None or not owner.valid or owner.revision != self.owner_guard.grant_revision
                or canonical_digest(json.loads(owner.value_json)) != self.owner_guard.grant_digest
                or self.owner_policy.namespace != ns or self.owner_policy.action != 'issue'
                or self.owner_policy.original_ref != versions.owner_policy_ref
                or self.owner_policy.digest != versions.owner_policy_digest
                or self.owner_policy.owner_head_digest.removeprefix('sha256:') != self.owner_guard.owner_head_digest
                or q.owner_policy_digest != versions.owner_policy_digest):
            raise ValueError('Contact qualification current Owner policy/SQL grant differs')
        snapshot, effect, d08 = self.effect_snapshot, self.current_effect, q.d08_scope
        from ..authority_service.v2_contract import canonical_digest as authority_digest
        if (snapshot.anchor.activation_generation != self.activation_generation
                or snapshot.authority_id != effect.authority_id or snapshot.namespace != effect.namespace
                or effect.activation_generation != self.activation_generation or effect.state != 'absent'
                or (effect.execution_head_seq,effect.execution_head_digest) !=
                    (snapshot.execution_head_seq,snapshot.execution_head_digest)
                or d08.authority_head != snapshot.anchor or d08.authority_snapshot_digest != authority_digest(snapshot)
                or d08.graph_query.namespace != ns or d08.graph_query.revision != self.graph_epoch
                or d08.receipt != q.checks[3]
                or any(negative.query != d08.graph_query or negative.matching_refs for negative in d08.negative_queries)):
            raise ValueError('Contact qualification actual Authority/D08 negative closure differs')
        inventories = {
            'd08.same_target_unfinished_commitments.v1': {'d08.commitment.v1'},
            'd08.same_target_unfinished_actions.v1': {'d08.action_intent.v1','d08.action_outcome.v1'},
        }
        if len(d08.negative_queries) != 2 or {item.predicate_ref for item in d08.negative_queries} != set(inventories):
            raise ValueError('Contact qualification D08 full negative query predicates differ')
        from ..runtime_contracts import VersionedRef
        for negative in d08.negative_queries:
            actual = tuple(VersionedRef(row.ref,row.revision) for row in sorted(self.members,key=lambda item:item.ref)
                if row.valid and AtomKey.from_token(row.ref).type_name in inventories[negative.predicate_ref])
            if negative.scanned_versions != actual:
                raise ValueError('Contact qualification D08 full scanned inventory differs')
        if any(rows.get(item.ref) is None or rows[item.ref].revision != item.version or not rows[item.ref].valid
                for item in d08.positive_reads):
            raise ValueError('Contact qualification D08 positive input versions differ')
        structural_heads=set()
        expression_closure=set()
        for roots,purpose in ((self.expression_roots,'expression'),(self.context_roots,'context'),(self.structural_roots,'structural')):
            if type(roots) is not tuple or not roots and purpose != 'structural' or len(roots) > 32 or len(set(roots)) != len(roots):
                raise ValueError('Contact qualification Source roots are incomplete')
            active,done = set(),set()
            def visit(ref):
                key = AtomKey.from_token(ref)
                if key != source_key(*ns.as_tuple,key.owner.subject or '') or ref in active:
                    raise ValueError('Contact qualification Source family identity/cycle differs')
                if ref in done:return
                source = rows.get(ref); access = rows.get(access_key(*ns.as_tuple,key.owner.subject).token)
                correction = rows.get(source_correction_head_key(ns,key.owner.subject).token)
                if source is None or access is None or not source.valid or not access.valid or correction is None:
                    raise ValueError('Contact qualification Source/access/correction inventory is incomplete')
                record = SourceRecord.from_dict(json.loads(source.value_json)); rights=json.loads(access.value_json)
                validate_access(rights)
                audience = 'owner' if purpose == 'structural' else self.audience
                allowed = (set(record.purposes) & set(rights['purposes']) & {'context','audit'}
                    if purpose == 'structural' else purpose in record.purposes and purpose in rights['purposes'])
                if (record.source_id != key.owner.subject or rights['source_id'] != record.source_id
                        or rights['status'] != 'active' or not allowed
                        or audience not in record.audiences or audience not in rights['audiences']
                        or correction.valid or correction.revision != 0):
                    raise ValueError('Contact qualification current Source purpose/access/correction differs')
                active.add(ref)
                for parent in record.parent_source_ids:visit(source_key(*ns.as_tuple,parent).token)
                active.remove(ref);done.add(ref)
                if purpose == 'structural':structural_heads.add(correction.ref)
            for ref in roots:visit(ref)
            if purpose == 'expression':expression_closure=done
        structural_expected=tuple(sorted({ref for row in self.members
            if row.valid and AtomKey.from_token(row.ref).type_name in ('d03.role_binding','d05.boundary_rule')
            for ref in json.loads(row.value_json)['source_refs']} - expression_closure))
        if self.structural_roots != structural_expected:
            raise ValueError('Contact qualification structural Source roots differ from the complete actual inventory')
        predicates=(*sorted(structural_heads),'d03.role_binding:all_valid','d05.boundary_rule:all_valid',
            'd10.contact_policy.v1:all','d10.proactive_opportunity.v1:all','d10.contact_claim.v1:all','d10.contact_claim.v2:all')
        if q.negative_predicates != predicates:
            raise ValueError('Contact qualification complete negative predicate inventory differs')
        source_versions=sets['source_grant'].versions
        if any(rows.get(v.ref) is None or rows[v.ref].revision != v.version or not rows[v.ref].valid for v in source_versions):
            raise ValueError('Contact qualification Source criterion/input has no actual Graph version')
        expected_sources={ref for root in expression_closure for ref in (root,access_key(*ns.as_tuple,AtomKey.from_token(root).owner.subject).token)}
        if not expected_sources <= {v.ref for v in source_versions}:
            raise ValueError('Contact qualification Source provider dropped an expression ancestor/access input')
        return self


def decode_contact_qualification_evidence_v3(raw, *, expected_digest):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value = decode_typed_production_value_v1(raw,ContactQualificationEvidenceV3)
    if canonical_serialize(plain_v1(value)) != canonical_serialize(raw) or value.qualification.digest != expected_digest:
        raise ValueError('Contact qualification independent canonical digest differs')
    return value


def issue_contact_qualification_evidence_v3(material, db, read, qualification, route):
    from .contact_final_projection_v3 import require_contact_projection_read_v3
    require_contact_projection_read_v3(read,db,phases=('post_cas_e_plus_1',))
    frame = read.frame
    expression = set(read.source_family(db,frame.envelope.source_qualification.source_refs,
        purpose='expression',audience=material.content.audience_id))
    structural = tuple(sorted({ref for atom in frame.snapshot.atoms
        if atom.valid and atom.key.type_name in ('d03.role_binding','d05.boundary_rule')
        for ref in atom.value['source_refs']} - expression))
    proof = ContactQualificationEvidenceV3(material.scope.namespace,frame.envelope.identity.operation_id,
        material.scope.generation,frame.snapshot.epochs[0].revision,
        frame.envelope.version_guard.access_epoch,frame.envelope.version_guard.delete_epoch,
        float(frame.now_utc),float(frame.envelope.deadline_utc),material.content.audience_id,
        frame.envelope.source_qualification.source_refs,(route.source_ref,),structural,route,qualification,
        tuple(OfflineTickGraphReadV1(a.key.token,a.revision,canonical_serialize(a.value),a.valid) for a in frame.snapshot.atoms),
        frame.query_coverage,frame.owner_guard,material.current_policy.original,material.current_effect,material.effect_snapshot)
    # Always roundtrip through the same closed decoder used for cold recovery.
    return decode_contact_qualification_evidence_v3(plain_v1(proof),expected_digest=qualification.digest)


def verify_contact_qualification_sql_v3(db, evidence, *, registry):
    if not db.in_transaction:
        raise ValueError('Contact qualification SQL verification requires readonly pinned SQL')
    evidence.validate_structure()
    ns=evidence.namespace
    if db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone() != (
            evidence.access_epoch,evidence.delete_epoch):
        raise ValueError('Contact qualification current access/delete barrier drifted')
    for member in evidence.members:
        key=AtomKey.from_token(member.ref)
        row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
            (member.ref,*ns.as_tuple)).fetchone()
        if row != (member.revision,member.value_json,int(member.valid)) and not (member.revision == 0 and row is None):
            raise ValueError('Contact qualification actual full SQL member drifted or was deleted')
        if member.valid:registry.validate(key,json.loads(member.value_json))
    for page in evidence.query_coverage:
        rows=db.execute('SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129',
            (*ns.as_tuple,page.type_id)).fetchall()
        if rows != [(v.key.token,v.revision) for v in page.row_versions]:
            raise ValueError('Contact qualification actual full negative query inventory drifted')
    from .ingress_observation import read_committed_ingress_identity
    source_id=AtomKey.from_token(evidence.route.source_ref).owner.subject
    ingress=read_committed_ingress_identity(db,ns,source_id)
    if ingress is None or canonical_digest(ingress) != evidence.route.ingress_digest:
        raise ValueError('Contact qualification actual committed private ingress differs')
    identity=json.loads(ingress.identity_json)
    if (identity.get('platform_ref'),identity.get('sender_ref'),identity.get('conversation_ref'),identity.get('visibility')) != (
            evidence.route.platform_ref,evidence.route.sender_ref,evidence.audience,'private'):
        raise ValueError('Contact qualification committed route is not the actual private ingress')
    return evidence


def verify_historical_contact_qualification_sql_v3(db, evidence, *, registry):
    """C09 authenticates historical SQL evidence; it grants no current rights.

    Current Source revocation may be the reason for erasure. Match the actual
    historical snapshot at its recorded namespace epoch rather than accepting
    fabricated rows or demanding current expression permission during deletion.
    """
    evidence.validate_structure()
    if not db.in_transaction:
        raise ValueError('Contact historical qualification requires pinned SQL')
    ns=evidence.namespace
    refs=tuple(member.ref for member in evidence.members)
    kinds=CONTACT_FINAL_QUERY_TYPES_V3
    # Limit the complete latest-head result, never the historical prefix.
    # All fixed query families plus every exact proof member remain present;
    # unrelated namespace history does not enter this provider closure.
    rows=db.execute('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision FROM graph_history h '
        'JOIN graph_events e ON (h.event_bot,h.event_persona,h.event_session,h.event_id)='
        '(e.bot,e.persona,e.session,e.event_id) WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? '
        f"AND (h.token IN ({','.join('?' for _ in refs)}) OR json_extract(h.token,'$[4]') IN ({','.join('?' for _ in kinds)})) "
        'GROUP BY h.token) SELECT h.token,h.revision,h.value,h.valid FROM latest l '
        'JOIN graph_history h ON h.token=l.token AND h.revision=l.revision ORDER BY h.token LIMIT 1025',
        (*ns.as_tuple,evidence.graph_epoch,*refs,*kinds)).fetchall()
    if len(rows)>1024:
        raise ValueError('Contact complete historical latest-head inventory exceeds bound; HOLD')
    heads={ref:(revision,value,valid) for ref,revision,value,valid in rows}
    for member in evidence.members:
        key=AtomKey.from_token(member.ref)
        expected=(member.revision,member.value_json,int(member.valid)) if member.revision else None
        if heads.get(member.ref) != expected:
            raise ValueError('Contact qualification historical SQL member/absence differs')
        if member.valid:registry.validate(key,json.loads(member.value_json))
    for page in evidence.query_coverage:
        actual=tuple((ref,row[0]) for ref,row in sorted(heads.items()) if AtomKey.from_token(ref).type_name == page.type_id)
        if actual != tuple((item.key.token,item.revision) for item in page.row_versions):
            raise ValueError('Contact qualification historical full query inventory differs')
    return evidence
