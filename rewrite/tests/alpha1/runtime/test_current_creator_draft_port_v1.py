"""W01 returns D12's current draft only through the signed Owner read fence."""

from dataclasses import asdict

import pytest

from sylanne3.authority_service.v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_contract_digest,
)
from sylanne3.contracts import canonical_json
from sylanne3.domains.d12.types import (
    ActiveSchemeHeadV1, CharacterDraft, D12DomainProvider, active_scheme_head_key,
    character_draft_key, graph_type_specs,
)
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.runtime_contracts import canonical_digest
from tests.alpha1.d12.test_owner_graph_lease import (
    NAMESPACE, OWNER_REQUEST, OWNER_TOKEN, owner_graph,
)


def _creator_case(owner_graph, *, capabilities=None, fields=None):
    graph, coordinator, bootstrap, port, grant_key, _ = owner_graph
    for spec in graph_type_specs():
        graph._registry.register(spec)
    provider = D12DomainProvider()
    coordinator.register_provider(
        bootstrap, "d12", provider, "d12.proposal.v1",
        provider.descriptor.request_schema_hash,
    )
    # The imported fixture's grant is a signed read-only grant. Reissue its
    # test proof with the real creator capability before minting this lease.
    with graph._lock:
        db = graph._db
        row = db.execute("SELECT value FROM graph_atoms WHERE token=?", (grant_key.token,)).fetchone()
        import json
        grant = json.loads(row[0])
        grant["capabilities"] = sorted(capabilities or [
            "workbench.create", "workbench.read"])
        grant["purposes"] = ["workbench_user_action"]
        proof_row = db.execute(
            "SELECT request_digest,graph_receipt_digest FROM graph_owner_issue_operations_v1 "
            "WHERE bot=? AND persona=?", NAMESPACE.as_tuple,
        ).fetchone()
        proof = OwnerGraphCommitProofV1(
            NAMESPACE, "issue-1", proof_row[0], grant["grant_id"],
            "sha256:" + canonical_digest(grant), "graph-incarnation",
            1, 1, 1, proof_row[1],
        )
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (canonical_json(grant), grant_key.token))
        db.execute(
            "UPDATE graph_owner_issue_operations_v1 SET grant_digest=?,proof_json=? "
            "WHERE bot=? AND persona=?",
            (proof.grant_digest, canonical_json(asdict(proof)), *NAMESPACE.as_tuple),
        )
        draft_fields = fields or {"d01.voice": "clear"}
        draft = CharacterDraft("persona", 1, draft_fields,
                               {name: "creator" for name in draft_fields})
        head = ActiveSchemeHeadV1(
            "persona", 1, "a" * 64, character_draft_key(NAMESPACE).token,
            1, "b" * 64, None, "adopt-1", "initial",
        )
        for key, value in ((character_draft_key(NAMESPACE), draft),
                           (active_scheme_head_key(NAMESPACE), head)):
            db.execute(
                "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,"
                "type_name,name,revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (key.token, *NAMESPACE.as_tuple, "persona", None, key.type_name,
                 key.name, 1, canonical_json({"schema": key.type_name, **asdict(value)}), 1),
            )
    port.guard = OwnerAuthorizationGuardV1(
        "authority", "installation", NAMESPACE, 1,
        owner_contract_digest(proof), 0, 0,
    )
    authority, lease, _ = coordinator.grant_current_owner(
        bootstrap, actor="owner-session", namespace=NAMESPACE,
        domains=("d12", "d11"), purpose="workbench_user_action",
        audience="owner", activation_generation=1,
        owner_session_token=OWNER_TOKEN, owner_session_request=OWNER_REQUEST,
    )
    return graph, coordinator, port, authority, lease


def test_creator_draft_reads_current_draft_and_head_with_signed_session(owner_graph):
    graph, coordinator, port, authority, lease = _creator_case(owner_graph)
    key = character_draft_key(NAMESPACE)

    def read():
        return coordinator.with_current_creator_draft_v1(
            authority, lease, draft_ref=key.token,
            required_capability="workbench.create", project=lambda frame: frame,
        )

    frame = read()
    assert frame.creator_authorized is True
    assert (frame.draft_revision, frame.active_head_revision) == (1, 1)
    assert frame.draft.fields == {"d01.voice": "clear"}
    assert frame.graph_revision >= 1
    assert port.guard_reads >= 3  # one for grant and two around current read

    with pytest.raises(AuthorityDenied):
        coordinator.with_current_creator_draft_v1(
            authority, lease, draft_ref=key.token,
            required_capability="workbench.read", project=lambda frame: frame,
        )
    with pytest.raises(AuthorityDenied):
        coordinator.with_current_creator_draft_v1(
            authority, lease, draft_ref="wrong",
            required_capability="workbench.create", project=lambda frame: frame,
        )
    port.session_current = False
    with pytest.raises(UnavailableGuard):
        read()


def test_creator_draft_requires_local_session_proof_and_current_head(owner_graph):
    graph, coordinator, _, authority, lease = _creator_case(owner_graph)
    key = character_draft_key(NAMESPACE)

    def read():
        return coordinator.with_current_creator_draft_v1(
            authority, lease, draft_ref=key.token,
            required_capability="workbench.create", project=lambda frame: frame,
        )

    proofs = coordinator._GraphCoordinator__owner_session_proofs
    proof = proofs.pop(lease)
    with pytest.raises(UnavailableGuard):
        read()
    proofs[lease] = proof
    with graph._lock:
        graph._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?",
            (active_scheme_head_key(NAMESPACE).token,),
        )
    with pytest.raises(UnavailableGuard):
        read()
