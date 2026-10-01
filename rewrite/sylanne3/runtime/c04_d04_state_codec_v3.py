"""Exact D04 state dispatch for current C04 authored joint continuations."""

from ..domains.d04.affect import _decode_mood
from ..domains.d04.authored_lineage_v3 import decode_authored_mood_state_v1
from ..graph_types import AtomKey


def decode_c04_mood_v3(ref: str, value):
    key = AtomKey.from_token(ref)
    if key.type_name == "d04.authored_mood_state.v1":
        state = decode_authored_mood_state_v1(value)
        if state.block_id != key.name:
            raise ValueError("authored current Mood identity differs")
    elif key.type_name == "d04.mood_field.v1":
        state = _decode_mood(value)
        if state.mood_id != ref:
            raise ValueError("current Mood identity differs")
    else:
        raise ValueError("current C04 Mood has no registered D04 codec")
    if key.owner.kind != "persona":
        raise ValueError("current Mood must be a persona state")
    return state


__all__ = ["decode_c04_mood_v3"]
