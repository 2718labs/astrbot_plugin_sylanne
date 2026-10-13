"""Life-only historical occurrence and episode, with separate current use.

Decoding these closed facts grants no authority. Issuance requires the private
identity of an activity just authenticated against the actual SQL/frame.
"""
from dataclasses import dataclass
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .d06_life_activity_lineage_v1 import QualifiedLifeActivityV1

from ..graph_types import AtomKey, GraphWrite, Owner, TypeSpec, OWNER_GRANT_TYPE, owner_grant_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, schema_hash
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from .domain_production_contracts_v1 import ProductionQueryCoverageV1

EVENT = 'd06.internal_life_event.v1'
EPISODE = 'memory.episode.v2'
PROVENANCE = 'memory.episode_provenance.v2'
ELIGIBILITY = 'memory.episode_eligibility.v2'
KINDS = (EVENT, EPISODE, PROVENANCE, ELIGIBILITY)
PROPOSAL_SCHEMA = 'd06.internal-life-episode-proposal.v2'
PROPOSAL_HASH = schema_hash({'schema':PROPOSAL_SCHEMA, 'writes':KINDS,
    'issuer':'installed-current-life-qualification', 'reality':'internal_life',
    'authority':'exact-current-production-witness'})
def _require_qualified_activity_v1(activity, *, db, frame):
    from .d06_life_activity_lineage_v1 import _QUALIFIED_INTERNAL_LIFE
    issued = _QUALIFIED_INTERNAL_LIFE.get(id(activity))
    if (issued is None or issued[0]() is not activity or issued[1] is not db
            or issued[2] is not frame or not db.in_transaction):
        raise ValueError('external/internal DTO is not this SQL-qualified Life activity')
    from .d01_production_operations_v1 import CurrentDomainReadV1
    CurrentDomainReadV1(frame).check(db)


def internal_life_episode_keys_v2(namespace, source_ref):
    source = AtomKey.from_token(source_ref)
    if source.type_name != 'memory.source' or NamespaceId.from_key(source) != namespace:
        raise ValueError('internal Life episode source scope differs')
    suffix = canonical_digest((namespace, source_ref))[:48]
    event = AtomKey(Owner('event', *namespace.as_tuple, 'internal-life:' + suffix), EVENT, 'record')
    owner = Owner('event', *namespace.as_tuple, 'episode:internal-life:' + suffix)
    return (event, *(AtomKey(owner, kind, 'record') for kind in (EPISODE, PROVENANCE, ELIGIBILITY)))


def _sha(value):
    if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('internal Life original digest differs')


@dataclass(frozen=True, slots=True)
class InternalLifeEventV1:
    event_ref: str
    namespace: NamespaceId
    activation_generation: int
    graph_incarnation: str
    causal_operation_id: str
    activity: 'QualifiedLifeActivityV1'
    self_mapping_ref: str
    perspective_ref: str
    scene_ref: str
    reality: str = 'internal_life'
    assertion_scope: str = 'activity_occurred_only'
    schema: str = EVENT

    def __post_init__(self):
        from .d06_life_activity_lineage_v1 import QualifiedLifeActivityV1
        if (type(self.activity) is not QualifiedLifeActivityV1 or type(self.namespace) is not NamespaceId
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or self.event_ref != internal_life_episode_keys_v2(self.namespace, self.activity.source_ref)[0].token
                or self.schema != EVENT or self.reality != 'internal_life'
                or self.assertion_scope != 'activity_occurred_only'
                or self.activity.reality != 'real_execution' or self.activity.purposes != ('context', 'consolidation')
                or self.activity.started_at > self.activity.completed_at
                or not self.graph_incarnation or not self.causal_operation_id):
            raise ValueError('internal Life event promotes text facts or changes occurrence identity')
        for ref, kind in ((self.self_mapping_ref, 'd03.self_identity_mapping.v1'),
                          (self.perspective_ref, 'd03.self_perspective.v1')):
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != self.namespace or key.type_name != kind:
                raise ValueError('internal Life event context scope differs')
        _sha(self.activity.qualification_digest)


@dataclass(frozen=True, slots=True)
class InternalLifeEpisodeV2:
    episode_ref: str
    source_refs: tuple[str, ...]
    event_ref: str
    schema: str = EPISODE

    def __post_init__(self):
        if type(self.source_refs) is not tuple or len(self.source_refs) != 1:
            raise ValueError('Life episode requires its one authenticated experience root')
        keys = internal_life_episode_keys_v2(NamespaceId.from_key(AtomKey.from_token(self.event_ref)), self.source_refs[0])
        if self.schema != EPISODE or (self.event_ref, self.episode_ref) != (keys[0].token, keys[1].token):
            raise ValueError('Life episode exact identities differ')


@dataclass(frozen=True, slots=True)
class EpisodeReadV2:
    ref: str
    revision: int
    digest: str
    valid: bool

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool:
            raise ValueError('Life episode read identity differs')
        _sha(self.digest)


@dataclass(frozen=True, slots=True)
class InternalLifeEpisodeProvenanceV2:
    event: InternalLifeEventV1
    episode: InternalLifeEpisodeV2
    producing_operation_id: str
    owner_head_digest: str
    historical_reads: tuple[EpisodeReadV2, ...]
    current_reads: tuple[EpisodeReadV2, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    schema: str = PROVENANCE

    def __post_init__(self):
        if (type(self.event) is not InternalLifeEventV1 or type(self.episode) is not InternalLifeEpisodeV2
                or self.event.event_ref != self.episode.event_ref
                or self.episode.source_refs != (self.event.activity.source_ref,)
                or self.schema != PROVENANCE or not self.producing_operation_id):
            raise ValueError('Life episode provenance causal identities differ')
        _sha(self.owner_head_digest)
        for rows in (self.historical_reads, self.current_reads):
            if (type(rows) is not tuple or not 1 <= len(rows) <= 1024
                    or any(type(row) is not EpisodeReadV2 or NamespaceId.from_key(AtomKey.from_token(row.ref)) != self.event.namespace for row in rows)
                    or tuple(row.ref for row in rows) != tuple(sorted({row.ref for row in rows}))):
                raise ValueError('Life episode provenance lacks closed unique bounded reads')
        if not set(self.current_reads) <= set(self.historical_reads):
            raise ValueError('Life current qualification lacks its historical provenance')
        if self.current_reads != tuple(row for row in self.historical_reads if AtomKey.from_token(row.ref).type_name in _CURRENT_TYPES):
            raise ValueError('Life episode current closure is not its complete finite projection')
        if (type(self.query_coverage) is not tuple or not self.query_coverage
                or any(type(row) is not ProductionQueryCoverageV1 or not row.complete for row in self.query_coverage)):
            raise ValueError('Life episode requires complete actual inventory coverage')
        refs = {row.ref for row in self.current_reads}
        if not {self.event.activity.source_ref, self.event.self_mapping_ref, self.event.perspective_ref,
                owner_grant_key(*self.event.namespace.as_tuple).token} <= refs:
            raise ValueError('Life episode current Source/mapping/perspective closure is missing')
        from ..memory_types import SourceRecord, access_key, source_key
        from ..domains.d06 import source_correction_head_key
        # Source bodies are in actual historical/current SQL, not duplicated in
        # this content-minimized proof. Exact typed heads/negative heads must
        # nonetheless be explicitly guarded for every Source in that closure.
        for row in self.current_reads:
            key = AtomKey.from_token(row.ref)
            if key.type_name == 'memory.source' and (row.revision < 1 or not row.valid or not {
                    access_key(*self.event.namespace.as_tuple, key.owner.subject).token,
                    source_correction_head_key(self.event.namespace, key.owner.subject).token} <= refs):
                raise ValueError('Life episode Source lacks complete Access/Correction qualification')


@dataclass(frozen=True, slots=True)
class InternalLifeEpisodeEligibilityV2:
    episode_ref: str
    event_ref: str
    provenance_ref: str
    provenance_digest: str
    producing_operation_id: str
    schema: str = ELIGIBILITY

    def __post_init__(self):
        key = AtomKey.from_token(self.episode_ref)
        if (key.type_name != EPISODE or self.schema != ELIGIBILITY or not self.producing_operation_id
                or AtomKey.from_token(self.provenance_ref) != AtomKey(key.owner, PROVENANCE, 'record')
                or NamespaceId.from_key(AtomKey.from_token(self.event_ref)) != NamespaceId.from_key(key)):
            raise ValueError('Life episode eligibility scope differs')
        _sha(self.provenance_digest)


def decode_internal_life_value_v2(kind, value):
    from .d06_life_activity_lineage_v1 import QualifiedLifeActivityV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    # Resolve the deliberately lazy annotation only after D06 has loaded.
    InternalLifeEventV1.__annotations__['activity'] = QualifiedLifeActivityV1
    cls = dict(zip(KINDS, (InternalLifeEventV1, InternalLifeEpisodeV2,
                          InternalLifeEpisodeProvenanceV2, InternalLifeEpisodeEligibilityV2))).get(kind)
    if cls is None: raise ValueError('unknown internal Life episode family')
    return decode_typed_production_value_v1(value, cls)


def internal_life_episode_type_specs_v2():
    return tuple(TypeSpec(kind, ('event',), 'projection' if kind == ELIGIBILITY else 'state',
        lambda value, kind=kind: decode_internal_life_value_v2(kind, value), immutable=kind != ELIGIBILITY,
        writer_domain='d06', schema_version=2 if kind != EVENT else 1,
        schema_hash=schema_hash({'type':kind, 'fields':tuple(cls.__dataclass_fields__)}))
        for kind, cls in zip(KINDS, (InternalLifeEventV1, InternalLifeEpisodeV2,
            InternalLifeEpisodeProvenanceV2, InternalLifeEpisodeEligibilityV2)))


@dataclass(frozen=True, slots=True)
class InternalLifeEpisodeStageV2:
    stage: object
    episode_refs: tuple[str, ...]


_CURRENT_TYPES = frozenset({'memory.source', 'memory.access', 'd06.source_correction_head.v1',
    'd01.persona_activation.v1', 'd01.persona_plan.v1', 'd03.self_identity_mapping.v1',
    'd03.self_perspective.v1', 'd03.entity_anchor', 'd03.role_binding', 'd05.boundary_rule',
    'd12.active_scheme_head.v1', OWNER_GRANT_TYPE, 'd11.life_fact_eligibility.v1',
    'd11.life_outcome_eligibility.v1', 'd10.life_progress_eligibility.v1'})


def compile_internal_life_episode_v2(db, *, frame, request, activity, mapping, perspective,
                                     mapping_ref, perspective_ref):
    _require_qualified_activity_v1(activity, db=db, frame=frame)
    keys = internal_life_episode_keys_v2(frame.envelope.authority.namespace, request.source_ref)
    if any(frame.snapshot.get(key) is None or frame.snapshot.get(key).revision != 0 for key in keys):
        raise ValueError('internal Life episode output is not an actual absence read')
    event = InternalLifeEventV1(keys[0].token, frame.envelope.authority.namespace,
        frame.envelope.authority.activation_generation, mapping.graph_incarnation,
        request.causal_operation_id, activity, mapping_ref, perspective_ref, perspective.scene_ref)
    episode = InternalLifeEpisodeV2(keys[1].token, (request.source_ref,), keys[0].token)
    historical = tuple(sorted((EpisodeReadV2(atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
        for atom in frame.snapshot.atoms if atom.key not in keys), key=lambda row: row.ref))
    current = tuple(row for row in historical if AtomKey.from_token(row.ref).type_name in _CURRENT_TYPES)
    proof = InternalLifeEpisodeProvenanceV2(event, episode, frame.envelope.identity.operation_id,
        frame.owner_guard.owner_head_digest, historical, current, frame.query_coverage)
    eligibility = InternalLifeEpisodeEligibilityV2(keys[1].token, keys[0].token, keys[2].token,
        canonical_digest(plain_v1(proof)), proof.producing_operation_id)
    writes = (GraphWrite(keys[0], plain_v1(event)), GraphWrite(keys[1], plain_v1(episode)),
        GraphWrite(keys[2], plain_v1(proof)), GraphWrite(keys[3], plain_v1(eligibility),
            (*keys[:3], *(AtomKey.from_token(row.ref) for row in current))))
    stage = stage_result_v1(frame, 'd06', 'encode_structured_experience', request, writes=writes,
        provenance={'schema':'d06.internal-life-episode-original.v2', 'proof':proof,
                    'encoding_status':'encoding_pending'}, coverage='partial',
        missing=('actual_d04_then_feeling_and_d06_subjective_trace_encoding',),
        continuation='internal-life-encoding:' + canonical_digest(keys[1].token)[:48],
        proposal_schema=PROPOSAL_SCHEMA, proposal_hash=PROPOSAL_HASH)
    for proposal in stage.proposals: validate_internal_life_proposal_v2(proposal, frame.snapshot)
    return InternalLifeEpisodeStageV2(stage, (keys[1].token,))


def validate_internal_life_proposal_v2(proposal, snapshot):
    if (proposal.domain != 'd06' or proposal.envelope.identity.phase != 'encode_structured_experience'
            or (proposal.proposal_schema, proposal.proposal_schema_hash) != (PROPOSAL_SCHEMA, PROPOSAL_HASH)):
        raise ValueError('internal Life episode phase/writer differs')
    writes = proposal.typed_writes
    if len(writes) != 4 or tuple(write.key.type_name for write in writes) != KINDS:
        raise ValueError('internal Life episode requires four complete typed members')
    event, episode, proof, eligibility = (decode_internal_life_value_v2(write.key.type_name, write.value) for write in writes)
    keys = internal_life_episode_keys_v2(proposal.envelope.authority.namespace, episode.source_refs[0])
    if (tuple(write.key for write in writes) != keys or proof.event != event or proof.episode != episode
            or proof.producing_operation_id != proposal.envelope.identity.operation_id
            or event.activation_generation != proposal.envelope.authority.activation_generation
            or eligibility != InternalLifeEpisodeEligibilityV2(keys[1].token, keys[0].token, keys[2].token,
                canonical_digest(plain_v1(proof)), proof.producing_operation_id)
            or any(write.dependencies for write in writes[:3])
            or writes[3].dependencies != (*keys[:3], *(AtomKey.from_token(row.ref) for row in proof.current_reads))):
        raise ValueError('internal Life episode complete causal/write/projection binding differs')
    reads = {atom.key.token: atom for atom in snapshot.atoms}
    if tuple(row.ref for row in proof.historical_reads) != tuple(sorted(ref for ref in reads if ref not in {key.token for key in keys})):
        raise ValueError('internal Life episode historical inventory is incomplete')
    for row in proof.historical_reads:
        atom = reads.get(row.ref)
        if atom is None or (atom.revision, canonical_digest(atom.value), atom.valid) != (row.revision, row.digest, row.valid):
            raise ValueError('internal Life episode provenance is not its actual full snapshot')
    if any(reads.get(key.token) is None or reads[key.token].revision != 0 for key in keys):
        raise ValueError('internal Life episode has no exact guarded output absence')
    return proposal


def require_exact_internal_life_issuance_v2(witness, graph, bundle):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1, _ACTIVE
    if (type(witness) is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness)) is not witness
            or witness.graph is not graph or witness.runtime.graph is not graph
            or type(witness.stage) is not InternalLifeEpisodeStageV2 or witness.bundle is not bundle
            or witness.stage.stage.proposals != bundle.proposals):
        raise ValueError('internal Life event requires its actual active installed composite witness')
    return witness


def internal_life_writes_from_proof_v2(proof):
    keys = internal_life_episode_keys_v2(proof.event.namespace, proof.event.activity.source_ref)
    eligibility = InternalLifeEpisodeEligibilityV2(keys[1].token, keys[0].token, keys[2].token,
        canonical_digest(plain_v1(proof)), proof.producing_operation_id)
    return (GraphWrite(keys[0], plain_v1(proof.event)), GraphWrite(keys[1], plain_v1(proof.episode)),
        GraphWrite(keys[2], plain_v1(proof)), GraphWrite(keys[3], plain_v1(eligibility),
            (*keys[:3], *(AtomKey.from_token(row.ref) for row in proof.current_reads))))


def validate_internal_life_episode_history_v2(db, proof):
    """Exact actual D06 bundle/event/history join, without current permission."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if not db.in_transaction: raise ValueError('Life episode history requires actual SQL snapshot')
    production = read_adopted_domain_operation_v1(db, proof.event.namespace, proof.producing_operation_id)
    expected = internal_life_writes_from_proof_v2(proof)
    if (production is None or production['domain'] != 'd06'
            or production['operation_kind'] != 'encode_structured_experience'
            or production['payload']['authority']['activation_generation'] != proof.event.activation_generation
            or canonical_serialize(production['payload']['writes']) != canonical_serialize(plain_v1(expected))
            or canonical_serialize(production['payload']['provenance']) != canonical_serialize(
                {'schema':'d06.internal-life-episode-original.v2', 'proof':plain_v1(proof), 'encoding_status':'encoding_pending'})):
        raise ValueError('Life episode is not its actual closed D06 committed original')
    reads = {version.key.token: version.revision for version in production['receipt'].read_versions}
    keys = internal_life_episode_keys_v2(proof.event.namespace, proof.event.activity.source_ref)
    planned = {row['key']:row['revision'] for row in production['payload']['read_versions']}
    if ({row.ref:row.revision for row in proof.historical_reads} != {ref:rev for ref,rev in planned.items() if ref not in {key.token for key in keys}}
            or canonical_serialize(production['payload']['query_coverage']) != canonical_serialize(plain_v1(proof.query_coverage))):
        raise ValueError('Life episode historical read/query inventory differs from actual D06 original')
    versions = {version.key.token: version.revision for version in production['receipt'].write_versions}
    for frozen in proof.historical_reads:
        if reads.get(frozen.ref) != frozen.revision:
            raise ValueError('Life historical provenance is outside its actual committed readset')
        if frozen.revision:
            actual = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
                (frozen.ref, frozen.revision)).fetchone()
            if actual is None or (canonical_digest(json.loads(actual[0])), bool(actual[1])) != (frozen.digest, frozen.valid):
                raise ValueError('Life episode historical Source/qualification original changed or deleted')
    current = {row.ref:row.revision for row in proof.current_reads}
    produced = {write.key.token for write in expected}
    for write in expected:
        deps = tuple(sorted((key.token, 1 if key.token in produced else current[key.token]) for key in write.dependencies))
        row = db.execute('SELECT value,valid,event_bot,event_persona,event_id,dependencies FROM graph_history '
            'WHERE token=? AND revision=1', (write.key.token,)).fetchone()
        if (versions.get(write.key.token) != 1 or row is None or row[:5] !=
                (canonical_serialize(write.value), 1, *proof.event.namespace.as_tuple, proof.producing_operation_id)
                or tuple(sorted(tuple(item) for item in json.loads(row[5]))) != deps):
            raise ValueError('Life episode actual committed membership/projection edges differ')
    return production


def internal_life_episode_read_inputs_v2(db, namespace, episode_ref):
    episode = AtomKey.from_token(episode_ref)
    if episode.type_name != EPISODE or NamespaceId.from_key(episode) != namespace:
        raise ValueError('Life episode read scope differs')
    key = AtomKey(episode.owner, PROVENANCE, 'record')
    row = db.execute('SELECT value FROM graph_atoms WHERE token=?', (key.token,)).fetchone()
    if row is None: raise ValueError('Life episode lacks actual typed provenance; HOLD')
    proof = decode_internal_life_value_v2(PROVENANCE, json.loads(row[0]))
    keys = internal_life_episode_keys_v2(namespace, proof.event.activity.source_ref)
    if keys[1] != episode: raise ValueError('Life episode provenance locator differs')
    from .d06_life_activity_lineage_v1 import life_activity_read_inputs_v1
    lineage, originals = life_activity_read_inputs_v1(db, namespace, proof.event.activity.source_ref)
    return tuple(dict.fromkeys((*keys, *(AtomKey.from_token(row.ref) for row in proof.current_reads), *lineage))), tuple(
        row.ref for row in proof.current_reads if AtomKey.from_token(row.ref).type_name == 'memory.source'), tuple(
        dict.fromkeys((proof.producing_operation_id, proof.event.causal_operation_id, *originals)))


def require_internal_life_episode_locator_v2(namespace, episode_ref, proof=None):
    key=AtomKey.from_token(episode_ref)
    if key.type_name!=EPISODE or NamespaceId.from_key(key)!=namespace:
        raise ValueError('Life episode current locator type/namespace differs; HOLD')
    if proof is not None and (proof.event.namespace!=namespace or proof.episode.episode_ref!=episode_ref):
        raise ValueError('Life episode current locator is not its exact provenance member; HOLD')
    return key


def require_current_internal_life_episode_v2(db, *, frame, episode_ref, installed_readers):
    """Current use additionally requalifies actual Life/Owner/Source under CAS."""
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from ..graph_store import GraphStore
    from ..domains.d03.self_perspective import SelfIdentityMapping, SelfPerspective
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    from .d06_life_activity_lineage_v1 import qualify_current_life_activity_v1
    ns = frame.envelope.authority.namespace
    key = require_internal_life_episode_locator_v2(ns,episode_ref)
    read = CurrentDomainReadV1(frame); read.check(db)
    proof_atom = read.head(db, AtomKey(key.owner, PROVENANCE, 'record'), required=True)
    proof = decode_internal_life_value_v2(PROVENANCE, proof_atom.value)
    require_internal_life_episode_locator_v2(ns,episode_ref,proof)
    metadata = GraphStore._decode_recovery(db.execute('SELECT schema,requirements_json,graph_revision '
        'FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?', ns.as_tuple).fetchone(), ns)
    if (metadata is None or metadata.requirements.activation_generation != proof.event.activation_generation
            or metadata.requirements.graph_incarnation != proof.event.graph_incarnation
            or frame.envelope.authority.activation_generation != metadata.requirements.activation_generation
            or frame.owner_guard.owner_head_digest != proof.owner_head_digest):
        raise ValueError('Life episode current activation/incarnation/Owner differs; HOLD')
    validate_internal_life_episode_history_v2(db, proof)
    writes = internal_life_writes_from_proof_v2(proof)
    for write in writes:
        atom = read.head(db, write.key, required=True)
        if atom.revision != 1 or canonical_serialize(atom.value) != canonical_serialize(write.value):
            raise ValueError('Life episode current fact/provenance/projection differs')
    expected = tuple(sorted((dep.token, 1 if dep in {write.key for write in writes} else next(
        row.revision for row in proof.current_reads if row.ref == dep.token)) for dep in writes[-1].dependencies))
    if tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies '
            'WHERE dependent_token=? ORDER BY dependency_token', (writes[-1].key.token,))) != expected:
        raise ValueError('Life episode actual invalidation edges changed')
    for frozen in proof.current_reads:
        atom = read.head(db, frozen.ref)
        if (atom.revision, canonical_digest(atom.value), atom.valid) != (frozen.revision, frozen.digest, frozen.valid):
            raise ValueError('Life episode Source/Owner/mapping/perspective current state changed')
    roots = tuple(row.ref for row in proof.current_reads if AtomKey.from_token(row.ref).type_name == 'memory.source')
    # Current use is separately qualified for this real consumer, even when
    # the occurrence producer was authenticated for consolidation.
    read.source_family(db, roots, purpose=frame.envelope.authority.purpose)
    read.source_family(db, roots, purpose='consolidation')
    adopted = read_adopted_domain_operation_v1(db, ns, proof.event.causal_operation_id)
    if adopted is None: raise ValueError('Life episode actual causal D10 original is missing')
    progress = decode_typed_production_value_v1(adopted['payload']['provenance']['actual_progress'], LifeProgressHeadV1)
    source = read.head(db, proof.event.activity.source_ref, required=True)
    activity = qualify_current_life_activity_v1(db, frame=frame, source_atom=source,
        adopted=adopted, progress=progress, installed_readers=installed_readers)
    # Qualification read_versions belong to each consumer's complete CAS frame;
    # occurrence identities and all actual original commitments remain exact.
    if canonical_serialize({k:v for k,v in plain_v1(activity).items() if k != 'read_versions'}) != canonical_serialize(
            {k:v for k,v in plain_v1(proof.event.activity).items() if k != 'read_versions'}):
        raise ValueError('Life episode actual requalified activity differs')
    mapping = decode_typed_production_value_v1(read.head(db, proof.event.self_mapping_ref, required=True).value, SelfIdentityMapping)
    perspective = decode_typed_production_value_v1(read.head(db, proof.event.perspective_ref, required=True).value, SelfPerspective)
    if (mapping.status != 'active' or mapping.graph_incarnation != metadata.requirements.graph_incarnation
            or perspective.identity_mapping_ref != proof.event.self_mapping_ref
            or perspective.role_head_id != mapping.role_head_id or perspective.self_entity_ref != mapping.self_entity_ref
            or perspective.scene_ref != proof.event.scene_ref):
        raise ValueError('Life episode current self context is no longer certified')
    return proof
