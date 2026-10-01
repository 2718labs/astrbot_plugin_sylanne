"""Canonical D06 source IDs for the identifier-only Authority model contract."""
from ..graph_types import AtomKey
from ..memory_types import source_key, access_key
from .contract import identifier


def d13_original_source_identity_v1(frozen):
    """Keep graph tokens in frozen source closure; expose only original IDs."""
    namespace = frozen.window.namespace
    sources, revisions, accesses = [], {}, {}
    for turn in frozen.turns:
        key = AtomKey.from_token(turn.source_ref.ref)
        source_id = key.owner.subject
        identifier(source_id, "D13 source ID")
        if (key != source_key(*namespace.as_tuple, source_id)
                or AtomKey.from_token(turn.access_ref.ref) != access_key(*namespace.as_tuple, source_id)):
            raise ValueError("D13 original source/access key identity differs")
        if source_id in revisions and (revisions[source_id], accesses[source_id]) != (
                turn.source_ref.version, turn.access_ref.version):
            raise ValueError("D13 duplicate source has inconsistent original revisions")
        if source_id not in revisions:
            sources.append(source_id)
            revisions[source_id] = turn.source_ref.version
            accesses[source_id] = turn.access_ref.version
    if not sources:
        raise ValueError("D13 original needs at least one source")
    return tuple(sources), tuple(revisions.items()), tuple(accesses.items())
