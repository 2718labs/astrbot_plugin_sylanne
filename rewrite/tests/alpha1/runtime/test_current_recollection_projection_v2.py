"""D06 subjective sidecar reads share the current Owner V2 graph snapshot."""

from dataclasses import fields
import json

import pytest

from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.contracts import canonical_json
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import source_key

from test_current_recollection_read_v2 import _fixture


def _read(case, projection):
    _, _, port, coordinator, namespace, principal = case
    anchor = port.anchors[namespace]
    login = OwnerSessionLoginRequestV1(
        anchor.authority_id, anchor.namespace,
        port.installation_grant.installation_id, principal,
        "credential:owner", 1, "owner", "http://localhost",
    )
    return coordinator.read_current_recollection_projection_v1(
        namespace=namespace, operation_id="operation-c04",
        projection_ref=projection.token, actor_id="paired-owner",
        principal=principal, owner_session_token="A" * 43,
        owner_session_request=login,
    )


def test_current_d06_projection_uses_same_fenced_source_and_c04_receipt(tmp_path):
    case, experience, ancestor_access = _fixture(tmp_path)
    store, authority_db, _, _, namespace, _ = case
    projection = AtomKey(
        Owner("activity", *namespace.as_tuple, "activity-c04"),
        "d06.recollection_projection.v1", "projection-1",
    )
    mood = AtomKey(Owner("persona", *namespace.as_tuple),
                   "d04.mood_field.v1", "current")
    source = source_key(*namespace.as_tuple, "source-1")
    experience_value = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE token=?", (experience.token,),
    ).fetchone()[0])
    value = {
        "projection_id": "projection-1", "activity_id": "activity-c04",
        "recollection_ref": experience_value["recollection_ref"],
        "experience_ref": experience.token, "source_ref": source.token,
        "source_revision": 1, "mood_ref": mood.token, "mood_revision": 1,
        "coupling_version": "coupling-1",
        "projection_version": "d06.affective_projection.v1",
        "state": "committed_subjective_projection",
        "evidence_eligibility": "subjective_only", "details": [],
        "subjective_weight": [0.2, 0.4], "subjective_tone": [-0.2, 0.1],
        "duration_interval": None, "encoding_trace_ref": None,
        "baseline_status": "not_read",
    }
    try:
        store._db.execute(
            "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
            "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (projection.token, *namespace.as_tuple, projection.owner.kind,
             projection.owner.subject, projection.type_name, projection.name,
             1, canonical_json(value)),
        )
        original_revisions = store._db.execute(
            "SELECT revisions FROM graph_events WHERE event_id='operation-c04'",
        ).fetchone()[0]
        store._db.execute(
            "UPDATE graph_events SET revisions=? WHERE event_id='operation-c04'",
            (canonical_json([*json.loads(original_revisions),
                             [projection.token, 1]]),),
        )
        current = _read(case, projection)
        assert current.projection_ref == projection.token
        assert current.subjective_tone == current.experience.tone_interval
        assert current.read_status == "hold_uncertified_c02_baseline"
        assert current.encoding_baseline_certified is False
        assert any(item.key == projection for item in current.read_versions)
        assert "details" not in {field.name for field in fields(current)}
        assert "private source literal" not in repr(current)
        assert "private ancestor literal" not in repr(current)
        assert not store._db.in_transaction

        store._db.execute(
            "UPDATE graph_events SET revisions=? WHERE event_id='operation-c04'",
            (original_revisions,),
        )
        with pytest.raises(UnavailableGuard, match="current recollection source"):
            _read(case, projection)
        store._db.execute(
            "UPDATE graph_events SET revisions=? WHERE event_id='operation-c04'",
            (canonical_json([*json.loads(original_revisions),
                             [projection.token, 1]]),),
        )
        row = store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?",
            (ancestor_access.token,),
        ).fetchone()
        store._db.execute(
            "UPDATE graph_atoms SET value=?,revision=revision+1 WHERE token=?",
            (canonical_json({**json.loads(row[0]), "status": "withdrawn"}),
             ancestor_access.token),
        )
        with pytest.raises(UnavailableGuard, match="current recollection source"):
            _read(case, projection)
    finally:
        store.close()
        authority_db.close()
