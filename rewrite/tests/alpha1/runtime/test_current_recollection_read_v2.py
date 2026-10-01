"""Production V2 read admission over a fixture representing a prior C04 commit."""

from dataclasses import asdict, fields
import json

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, canonical_digest as owner_contract_digest,
)
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.contracts import canonical_json
from sylanne3.domains.d04 import AffectAxis, AffectProvider, AffectScheme, MoodField
from sylanne3.domains.d04.affect import RecollectionExperience
from sylanne3.domains.d06 import source_correction_head_key
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key

from test_graph_v2_provisioning import _owner_issue_case


def _fixture(tmp_path, *, extra_specs=()):
    scheme = AffectScheme(
        "d04.affect.scheme.v1", "scheme-1", "operator-1", "parameter-1",
        "coupling-1", (AffectAxis("care", "normalized", "care"),), (),
    )
    provider = AffectProvider(active_scheme=scheme)
    (store, authority_db, port, coordinator, policy, operation,
     pending, grant_value, bootstrap) = _owner_issue_case(
         tmp_path, first_ingress=True, return_bootstrap=True,
         extra_specs=(*provider.type_specs(), *extra_specs),
     )
    namespace = policy.namespace
    port.pending_owner = pending
    proof = coordinator.commit_first_owner_grant_v2(
        bootstrap, namespace=namespace, operation_id=operation.operation_id,
        grant_value=grant_value,
    )
    guard = OwnerAuthorizationGuardV1(
        operation.authority_id, operation.installation_id, namespace,
        1, owner_contract_digest(proof), 0, 0,
    )

    def guarded(*, namespace, authority_namespace, permit, **session_kwargs):
        port.outside_graph_lock()
        assert authority_namespace == "opaque:" + namespace.persona_id
        assert port.fences.validate_fence(
            permit, subject="subject", current_anchor=port.anchors[namespace]
        ) == permit
        assert session_kwargs["owner_actor_id"] == "paired-owner"
        assert session_kwargs["owner_session_token"] == "A" * 43
        assert session_kwargs["owner_session_request"].principal == operation.principal
        return guard, permit

    port.get_current_owner_guard_for_fence = guarded
    coordinator._GraphCoordinator__owner_principal_resolver = (
        lambda actor, current_namespace: operation.principal
        if (actor, current_namespace) == ("paired-owner", namespace) else None
    )
    coordinator.register_provider(
        bootstrap, "d04", provider, "d04.proposal.v1",
        provider.descriptor.request_schema_hash,
    )
    assert isinstance(store, ProductionGraphStore)
    owner = Owner("activity", *namespace.as_tuple, "activity-c04")
    source = source_key(*namespace.as_tuple, "source-1")
    access = access_key(*namespace.as_tuple, "source-1")
    ancestor = source_key(*namespace.as_tuple, "ancestor-1")
    ancestor_access = access_key(*namespace.as_tuple, "ancestor-1")
    recollection = AtomKey(owner, "d06.recollection.v1", "recollection-1")
    experience = AtomKey(owner, "d04.recollection_experience.v1", "experience-1")
    mood = AtomKey(Owner("persona", *namespace.as_tuple),
                   "d04.mood_field.v1", "current")
    record = SourceRecord(
        "source-1", "private source literal", "alice", "observed", "confirmed",
        1.0, 2.0, "family-1", ("owner",), ("context",),
        ("ancestor-1",),
    )
    parent = SourceRecord(
        "ancestor-1", "private ancestor literal", "alice", "observed",
        "confirmed", 0.5, 1.0, "family-1", ("owner",), ("context",),
    )
    mood_value = MoodField(
        "mood-1", "scheme-1", (("care", 0.4),), (source.token,),
        "parameter-1", "coupling-1", 3.0,
    )
    experience_value = RecollectionExperience(
        "experience-1", "activity-c04", recollection.token, source.token,
        (source.token,), "mood-1", (source.token,), (0.2, 0.4),
        (-0.2, 0.1), "coupling-1", "coupling-1",
    )
    values = {
        source: asdict(record),
        ancestor: asdict(parent),
        access: {"source_id": "source-1", "audiences": ["owner"],
                 "purposes": ["context"], "status": "active", "recorded_at": 2.0},
        ancestor_access: {
            "source_id": "ancestor-1", "audiences": ["owner"],
            "purposes": ["context"], "status": "active", "recorded_at": 1.0,
        },
        mood: asdict(mood_value),
        recollection: {
            "recollection_id": "recollection-1", "activity_id": "activity-c04",
            "content_refs": ["source-1"], "feeling_experience_refs": [experience.token],
            "provenance_eligibility": ["observed"],
        },
        experience: asdict(experience_value),
    }
    # The test installs a historical C04 fixture; the method under test must
    # independently read current business heads through its V2 Authority fence.
    with store._lock:
        db = store._db
        epoch = GraphStore.graph_epoch(
            store, *namespace.as_tuple,
            _capability=coordinator._GraphCoordinator__graph_capability,
        )
        db.execute("BEGIN IMMEDIATE")
        try:
            for key, value in values.items():
                db.execute(
                    "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                    "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
                    (key.token, *namespace.as_tuple, key.owner.kind,
                     key.owner.subject, key.type_name, key.name, 1,
                     canonical_json(json.loads(json.dumps(value)))),
                )
            db.execute(
                "INSERT INTO graph_bundle_operations"
                "(bot,persona,operation_id,digest,activity_id,effect_id,"
                "commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
                (*namespace.as_tuple, "operation-c04", "a" * 64,
                 "activity-c04", None, 1, canonical_json({
                     "commit_seq": 1, "ledger_refs": [recollection.token],
                     "outbox_refs": ["outbox-c04"],
                 })),
            )
            db.execute(
                "INSERT INTO graph_bundle_refs"
                "(bot,persona,operation_id,ref_kind,ref) VALUES(?,?,?,?,?)",
                (*namespace.as_tuple, "operation-c04", "experience",
                 recollection.token),
            )
            db.execute(
                "INSERT INTO graph_events"
                "(bot,persona,session,event_id,digest,reads,epoch_reads,revisions,"
                "invalidated,epoch_revision) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (*namespace.as_tuple, "activity-c04", "operation-c04",
                 "event-c04", "[]", "[]",
                 canonical_json([[recollection.token, 1], [experience.token, 1]]),
                 "[]", epoch.revision),
            )
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    return (store, authority_db, port, coordinator, namespace,
            operation.principal), experience, ancestor_access


def _read(case, experience):
    _, _, port, coordinator, namespace, principal = case
    anchor = port.anchors[namespace]
    request = OwnerSessionLoginRequestV1(
        anchor.authority_id, anchor.namespace,
        port.installation_grant.installation_id, principal,
        "credential:owner", 1, "owner", "http://localhost",
    )
    return coordinator.read_current_recollection_experience_v1(
        namespace=namespace, operation_id="operation-c04",
        experience_ref=experience.token, actor_id="paired-owner",
        principal=principal, owner_session_token="A" * 43,
        owner_session_request=request,
    )


def test_current_experience_holds_on_pending_ancestor_correction(tmp_path):
    case, experience, _ = _fixture(tmp_path)
    store, authority_db, _, _, namespace, _ = case
    try:
        assert _read(case, experience).status == "current_authorized_read"
        head = source_correction_head_key(namespace, "ancestor-1")
        source = source_key(*namespace.as_tuple, "ancestor-1")
        correction = source_key(*namespace.as_tuple, "correction-1")
        target = AtomKey(Owner("event", *namespace.as_tuple, "meaning-1"),
                         "memory.interpretation", "current")
        store._db.execute(
            "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
            "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1)",
            (head.token, *namespace.as_tuple, head.owner.kind,
             head.owner.subject, head.type_name, head.name, 1,
             canonical_json({
                 "source_ref": source.token, "source_revision": 1,
                 "correction_source_ref": correction.token,
                 "target_refs": [target.token], "operation_id": "correction-1",
                 "state": "pending_reevaluation", "access_epoch": 0,
                 "deletion_epoch": 0,
             })),
        )
        assert store._db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?",
            (source.token,)).fetchone() == (1,)
        with pytest.raises(UnavailableGuard, match="awaits reevaluation"):
            _read(case, experience)
    finally:
        store.close()
        authority_db.close()


def test_current_recollection_rechecks_receipt_and_revoked_source(tmp_path):
    case, experience, ancestor_access = _fixture(tmp_path)
    store, authority_db = case[:2]
    try:
        result = _read(case, experience)
        assert result.status == "current_authorized_read"
        assert result.encoding_baseline_certified is False
        assert result.experience.experience_id == "experience-1"
        assert result.source_kind == result.provenance_eligibility == "observed"
        assert any(item.key == source_correction_head_key(
            case[4], "ancestor-1") and item.revision == 0
            for item in result.read_versions)
        assert "text" not in {field.name for field in fields(result)}
        assert "private source literal" not in repr(result)
        assert "private ancestor literal" not in repr(result)
        assert not store._db.in_transaction

        # A durable operation with a stale write receipt cannot authorize the
        # current experience, even while its atom is still present.
        original = store._db.execute(
            "SELECT revisions FROM graph_events WHERE event_id='operation-c04'"
        ).fetchone()[0]
        store._db.execute(
            "UPDATE graph_events SET revisions=? WHERE event_id='operation-c04'",
            (json.dumps([[experience.token, 0]]),),
        )
        with pytest.raises(UnavailableGuard, match="current recollection source"):
            _read(case, experience)
        store._db.execute(
            "UPDATE graph_events SET revisions=? WHERE event_id='operation-c04'",
            (original,),
        )

        row = store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (ancestor_access.token,),
        ).fetchone()
        store._db.execute(
            "UPDATE graph_atoms SET value=?,revision=revision+1 WHERE token=?",
            (canonical_json({**json.loads(row[0]), "status": "withdrawn"}),
             ancestor_access.token),
        )
        with pytest.raises(UnavailableGuard, match="current recollection source"):
            _read(case, experience)
    finally:
        store.close()
        authority_db.close()
