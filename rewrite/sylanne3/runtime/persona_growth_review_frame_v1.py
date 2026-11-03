"""Private metadata CAS composition for the actual growth-review Source Work."""
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import GraphVersion

_FRAMES_V1 = {}


def _optional_owner_v1(db):
    from .domain_background_read_v3 import _active_v3
    from .current_method_learning_read_v3 import _method_active
    background, method = _active_v3(db), _method_active(db)
    if background is not None and method is not None:
        raise AuthorityUnavailable("growth metadata CAS has two unrelated active Work owners")
    return background if background is not None else method


def compose_growth_review_metadata_cas_v1(db, *, snapshot, read_versions, limits):
    owner = _optional_owner_v1(db)
    if owner is None or not getattr(owner, "growth_review_metadata_v1", None):
        return read_versions
    from .persona_growth_review_metadata_v1 import growth_metadata_cas_versions_v1
    full = {version.key: version.revision for version in read_versions}
    for version in growth_metadata_cas_versions_v1(db):
        if version.key in full and full[version.key] != version.revision:
            raise AuthorityUnavailable("growth metadata CAS differs from an actual current Body version")
        full[version.key] = version.revision
    if len(full) > limits.max_graph_heads:
        raise AuthorityUnavailable("growth metadata CAS exceeds the existing current-head bound")
    return tuple(GraphVersion(key, revision) for key, revision in sorted(full.items(),
        key=lambda item: item[0].token))


def register_growth_review_frame_v1(db, frame, scope):
    from .persona_growth_birth_v1 import require_persona_birth_frame_v1
    require_persona_birth_frame_v1(db, frame)
    owner = _optional_owner_v1(db)
    if owner is None or not getattr(owner, "growth_review_metadata_v1", None):
        return frame
    from .persona_growth_review_metadata_v1 import _current_v1, growth_metadata_cas_versions_v1
    _current_v1(owner)
    expected = dict((version.key, version.revision) for version in frame.envelope.version_guard.read_versions)
    if (scope.namespace != owner.namespace
            or frame.envelope.authority.namespace != owner.namespace
            or frame.snapshot.epochs != (owner.graph_stamp[1],)
            or any(expected.get(version.key) != version.revision
                for version in growth_metadata_cas_versions_v1(db))):
        raise AuthorityUnavailable("growth frame lost its actual metadata EOF/CAS namespace and epoch")
    ids = getattr(owner, "growth_review_frame_ids_v1", None)
    if ids is None:
        ids = []
        owner.growth_review_frame_ids_v1 = ids
    from sys import getsizeof
    owner.operation.retain(getsizeof(frame) + getsizeof(frame.snapshot)
        + getsizeof(frame.snapshot.atoms) + getsizeof(frame.envelope.version_guard.read_versions)
        + getsizeof((frame, owner, frame.envelope.version_guard.read_versions)) + 256)
    ids.append(id(frame))
    _FRAMES_V1[id(frame)] = (frame, owner, frame.envelope.version_guard.read_versions)
    return frame


def growth_review_frame_read_versions_v1(frame):
    record = _FRAMES_V1.get(id(frame))
    if record is None:
        return None
    if record[0] is not frame or id(frame) not in record[1].growth_review_frame_ids_v1:
        raise AuthorityUnavailable("growth frame has another actual Source Work lifetime")
    if record[1].operation.closed:
        raise AuthorityUnavailable("growth frame Source Work has ended")
    return record[2]


def release_growth_review_frames_v1(owner):
    ids = getattr(owner, "growth_review_frame_ids_v1", None)
    if ids is not None:
        for identity in ids:
            record = _FRAMES_V1.get(identity)
            if record is not None and record[1] is owner:
                del _FRAMES_V1[identity]
        ids.clear()
