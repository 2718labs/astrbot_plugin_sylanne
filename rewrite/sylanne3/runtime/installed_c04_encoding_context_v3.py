"""Fixed current post-joint encoding read plan and same-SQL baseline issuer.

No C02 timestamp is backfilled. The concrete Graph wrapper owns the actual
Owner/write fence and commits the returned zero-write event before calling the
issuer in that same transaction. This module issues no Graph write capability.
"""
from dataclasses import asdict, dataclass
import json
from weakref import WeakValueDictionary

from ..contracts import Event, Scope, canonical_json
from ..graph_types import AtomKey, GraphCandidate, GraphVersion, owner_grant_key
from ..runtime_contracts import AuthorityContext, FenceScope, NamespaceId, canonical_digest
from ..memory_types import SourceRecord, source_key, access_key
from ..domains.d06 import source_correction_head_key

ACTIVITY = "c04.encoding_context.v3"
_ENVIRONMENTS = WeakValueDictionary()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class C04EncodingEnvironmentV3:
    graph: object
    namespace: NamespaceId
    clock: object
    as_known_at: float
    asset: object
    policy: object
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class C04EncodingContextStageV3:
    namespace: NamespaceId
    encoding_operation_id: str
    joint_operation_id: str
    source_ref: str
    source_refs: tuple[str, ...]
    perspective_ref: str
    baseline_id: str
    owner_fence_digest: str
    owner_epoch: int
    access_epoch: int
    delete_epoch: int
    as_known_at: float
    joint_output_digest: str
    source_closure_digest: str
    candidate: GraphCandidate
    read_rows: tuple
    asset: object
    policy: object

    @property
    def reads(self):
        return self.candidate.reads


def encoding_context_operation_id_v3(namespace, joint_operation_id, source_ref):
    return "c04-encoding:" + canonical_digest((ACTIVITY, namespace, joint_operation_id, source_ref))[:48]


def observe_installed_c04_encoding_environment_v3(graph, bootstrap, namespace):
    """Real paired clock and installed assets; call before entering Graph SQL."""
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort, VerifiedIngressClockV2
    from ..domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
    from .first_ingress_v2 import trusted_upper
    if (type(graph) is not GraphCoordinator or bootstrap is not graph._GraphCoordinator__bootstrap
            or type(namespace) is not NamespaceId or graph._GraphCoordinator__store._db.in_transaction):
        raise ValueError("installed encoding observation must run outside Graph SQL")
    port = graph._GraphCoordinator__content_fence_v2
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(port) is not V2FencePort or assembly is None or assembly.installation_policy.namespace != namespace
            or port.installation_grant.installation_id != assembly.installation_policy.installation_id
            or port.installation_grant.manifest_digest != assembly.installation_policy.manifest_digest):
        raise ValueError("encoding observation lacks its actual paired installation")
    clock = port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    if type(clock) is not VerifiedIngressClockV2:
        raise ValueError("actual paired encoding clock required")
    policy, asset = load_installed_d04_projection_assets_v2(assembly.package_root,
        assembly.installation_policy.manifest_digest, assembly.available_cpu_features)
    result = C04EncodingEnvironmentV3(graph, namespace, clock, trusted_upper(clock), asset, policy,
        assembly.installation_policy.manifest_digest)
    _ENVIRONMENTS[id(result)] = result
    return result


def stage_current_c04_encoding_context_v3(graph, db, *, namespace, joint_operation_id,
        source_ref, authority, current_owner, scope, environment):
    """Read a complete bounded plan; no event or baseline is written here."""
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    from ..domains.d04.affect import _decode_appraisal, decode_encoding_baseline
    from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1, joint_state_payload_v1
    from .d04_joint_output_original_store_v1 import read_d04_joint_output_original_v1
    from .c04_current_projection_service_v3 import _source_closure_digest
    if (type(graph) is not GraphCoordinator or db is not graph._GraphCoordinator__store._db
            or not db.in_transaction or not graph._GraphCoordinator__store._lock._is_owned()
            or type(authority) is not AuthorityContext or type(current_owner) is not OwnerLeaseBindingV1
            or type(scope) is not FenceScope or type(environment) is not C04EncodingEnvironmentV3
            or _ENVIRONMENTS.get(id(environment)) is not environment or environment.graph is not graph
            or environment.namespace != namespace or authority.namespace != namespace or current_owner.namespace != namespace
            or authority.actor != current_owner.actor or authority.purpose != current_owner.purpose
            or authority.audience != (current_owner.audience,)):
        raise ValueError("encoding stage needs actual current installed Owner/clock/Graph")
    metadata, epoch = graph._v2_graph_stamp(namespace)
    if (scope.namespace != namespace or scope.operation != "write" or scope.graph_epoch != epoch
            or scope.graph_revision != metadata.graph_revision or scope.generation != authority.activation_generation
            or not graph._anchor_matches(metadata.requirements, scope.pinned_anchor)):
        raise ValueError("encoding current write fence and Graph differ")
    output = read_d04_joint_output_original_v1(db, namespace, joint_operation_id)
    if output is None or output.namespace != namespace:
        raise ValueError("encoding requires an actually adopted joint output")
    rows = {}
    def load(ref, *, absent=False):
        key = AtomKey.from_token(ref)
        if NamespaceId.from_key(key) != namespace:
            raise ValueError("encoding read crossed namespace")
        if ref in rows:
            return rows[ref]
        if len(rows) >= 512:
            raise ValueError("complete encoding read exceeds installed bound")
        raw = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
        if raw is None:
            if not absent:
                raise ValueError("encoding current original is absent")
            result = (ref, 0, {}, False)
        else:
            value = json.loads(raw[1])
            if canonical_json(value) != raw[1] or raw[0] < 1 or not raw[2] and not absent:
                raise ValueError("encoding current original is invalid")
            graph._GraphCoordinator__store._registry.validate(key, value)
            result = (ref, raw[0], value, bool(raw[2]))
        rows[ref] = result
        return result
    owner = load(owner_grant_key(*namespace.as_tuple).token)
    if (owner[1] != current_owner.grant_revision
            or canonical_digest(owner[2]) != current_owner.grant_digest.removeprefix("sha256:")):
        raise ValueError("encoding current Owner original changed")
    closure = _source_closure_digest(db, namespace, (source_ref,), authority.audience[0], authority.purpose)
    visiting, seen = set(), set()
    def source_closure(ref):
        if ref in visiting:
            raise ValueError("encoding source ancestry cycles")
        if ref in seen:
            return
        if len(seen) + len(visiting) >= 256:
            raise ValueError("encoding source ancestry exceeds bound")
        visiting.add(ref)
        item = load(ref); key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("encoding source is not a canonical D06 identity")
        source = SourceRecord.from_dict(item[2])
        load(access_key(*namespace.as_tuple, key.owner.subject).token)
        load(source_correction_head_key(namespace, key.owner.subject).token, absent=True)
        for parent in source.parent_source_ids:
            source_closure(source_key(*namespace.as_tuple, parent).token)
        visiting.remove(ref); seen.add(ref)
    source_closure(source_ref)
    source = SourceRecord.from_dict(rows[source_ref][2])
    # The earlier C02 baseline is only an actual perspective locator. Its
    # unknown intervals or timestamp never become this certified baseline.
    baselines = []
    for (ref,) in db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d04.encoding_baseline.v1' "
            "AND EXISTS (SELECT 1 FROM json_each(graph_atoms.value,'$.source_refs') AS j WHERE j.value=?) ORDER BY token",
            (*namespace.as_tuple, source_ref)):
        item = load(ref)
        baseline = decode_encoding_baseline(item[2])
        if source_ref in baseline.source_refs:
            baselines.append((ref, baseline))
    if len(baselines) != 1:
        raise ValueError("source requires its unique actual C02 perspective locator")
    perspective_ref = baselines[0][1].perspective_ref
    load(perspective_ref)
    if AtomKey.from_token(perspective_ref).type_name not in {"d03.entity_anchor", "d03.role_binding", "d03.self_perspective.v1"}:
        raise ValueError("encoding perspective type differs")
    interpretations, facets = set(), set()
    known_times = [source.recorded_at]
    for (ref,) in db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d04.appraisal_bundle.v1' "
            "AND EXISTS (SELECT 1 FROM json_each(graph_atoms.value,'$.source_refs') AS j WHERE j.value=?) ORDER BY token",
            (*namespace.as_tuple, source_ref)):
        item = load(ref); appraisal = _decode_appraisal(item[2])
        selected = tuple(facet for facet in appraisal.meaning_facets if source_ref in facet.source_refs)
        if not selected:
            continue
        known_times.append(appraisal.learned_at)
        for facet in selected:
            if facet.facet_id in facets:
                raise ValueError("encoding source MeaningFacet identity is ambiguous")
            facets.add(facet.facet_id); interpretations.add(facet.interpretation_ref)
    if not facets or environment.as_known_at < max(known_times):
        raise ValueError("encoding actual appraisal or current clock is unavailable")
    for ref in sorted(interpretations):
        load(ref)
        if AtomKey.from_token(ref).type_name not in {"d07.current_interpretation.v1", "d07.belief_revision.v1"}:
            raise ValueError("encoding MeaningFacet interpretation type differs")
    expected_members = set()
    for member in output.members:
        for ref, version, value in ((member.checkpoint_ref, member.predecessor_checkpoint_revision + 1,
                joint_checkpoint_payload_v1(member.next_checkpoint)),
                (member.predecessor_state_ref, member.predecessor_state_revision + 1, joint_state_payload_v1(member.next_state))):
            actual = load(ref)
            if actual[1:] != (version, value, True):
                raise ValueError("encoding member no longer equals its actual adopted joint output")
            expected_members.add(ref)
    types = ("d04.numeric_checkpoint.v1", "d04.numeric_checkpoint.v2", "d04.feeling_state.v1", "d04.mood_field.v1",
        "d04.authored_feeling_state.v1", "d04.authored_mood_state.v1")
    actual_members = {ref for ref, in db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name IN (?,?,?,?,?,?)",
        (*namespace.as_tuple, *types))}
    if actual_members != expected_members:
        raise ValueError("encoding complete current component differs from adopted output")
    rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if rights != (current_owner.access_epoch, current_owner.delete_epoch):
        raise ValueError("encoding current Owner/source rights changed")
    operation = encoding_context_operation_id_v3(namespace, joint_operation_id, source_ref)
    ordered = tuple(rows[key] for key in sorted(rows))
    reads = tuple(GraphVersion(AtomKey.from_token(ref), revision) for ref, revision, _, _ in ordered)
    fence_digest = canonical_digest(asdict(scope.permit))
    candidate = GraphCandidate(Event(Scope(*namespace.as_tuple, ACTIVITY), operation, environment.as_known_at,
        ACTIVITY, {"source_ref": source_ref, "joint_operation_id": joint_operation_id,
            "joint_output_digest": output.original_digest, "read_set_digest": canonical_digest(ordered),
            "clock_digest": canonical_digest(asdict(environment.clock)), "owner_fence_digest": fence_digest}),
        reads, (), (epoch,))
    return C04EncodingContextStageV3(namespace, operation, joint_operation_id, source_ref, (source_ref,),
        perspective_ref, "d04-encoding-baseline:" + operation, fence_digest, current_owner.authorization_revision,
        rights[0], rights[1], environment.as_known_at, output.original_digest, closure, candidate, ordered,
        environment.asset, environment.policy)


def issue_committed_c04_encoding_baseline_v3(db, stage, *, actual_receipt):
    """Call after the real zero-write bundle receipt was stored in this SQL tx."""
    from .c04_encoding_baseline_store_v3 import _receipt
    from .c04_encoding_baseline_service_v3 import issue_and_record_c04_encoding_baseline_v3
    if type(stage) is not C04EncodingContextStageV3 or not db.in_transaction:
        raise ValueError("actual current encoding stage and transaction required")
    receipt = _receipt(db, stage.namespace, stage.encoding_operation_id)
    if (receipt != actual_receipt or receipt.read_versions != stage.reads or receipt.write_versions
            or receipt.activity_id != ACTIVITY):
        raise ValueError("actual encoding read event/receipt differs from fixed stage")
    return issue_and_record_c04_encoding_baseline_v3(db, namespace=stage.namespace,
        encoding_operation_id=stage.encoding_operation_id, joint_operation_id=stage.joint_operation_id,
        source_ref=stage.source_ref, perspective_ref=stage.perspective_ref, baseline_id=stage.baseline_id,
        owner_fence_digest=stage.owner_fence_digest, as_known_at=stage.as_known_at,
        owner_epoch=stage.owner_epoch, access_epoch=stage.access_epoch, delete_epoch=stage.delete_epoch,
        asset=stage.asset, policy=stage.policy)
