"""Current Owner adoption of one static D03 catalogue with a real preview."""
from dataclasses import asdict, replace
import json
from uuid import UUID

from ..contracts import Event, Scope, canonical_json
from ..domains.d03.context import ContextProvider, RoleBinding, _tuple_payload
from ..domains.d12.scheme_command import D12CompiledSchemeV1, compiled_scheme_digest_v1
from ..domains.d12.types import ActiveSchemeHeadV1, CharacterDraft, active_scheme_head_key, character_draft_key
from ..graph_store import GraphStore, ProductionGraphStore
from ..graph_types import AtomKey, GraphCandidate, GraphVersion, GraphWrite, owner_grant_key
from ..runtime_contracts import AuthorityContext, canonical_digest, canonical_serialize
from .budget import get_budget_lease, require_budget_family_admissible
from .d12_compiled_candidate_store_v1 import install_d12_compiled_candidate_store_v1, record_d12_domain_candidate_v1
from .d12_domain_scheme_compile_v1 import CONTEXT_SCHEME_FIELD, D12ContextSchemeCandidateV1, compile_d12_domain_scheme_candidate_v1
from .scheme_original_store_v1 import CompilationOriginalV1, install_scheme_original_store_v1, record_compilation_original_for_operation_v1


SCHEMA = "d12.owner-context-catalogue-original.v1"


def adopt_current_context_catalogue_v1(c, authority, lease, *, operation_id, roles, norms, budget_ref):
    """Add/edit only the catalogue field; in-use names cannot be removed.

    The deterministic compatibility preview and typed compilation are saved
    with the actual Owner receipt. This administrative command performs no
    experiment, model request or artificial paid-cost settlement.
    """
    from ..graph_coordinator import GraphCoordinator
    parsed = UUID(operation_id)
    if parsed.version != 4 or str(parsed) != operation_id:
        raise ValueError("context adoption requires a canonical Owner UUID4")
    if (type(c) is not GraphCoordinator or type(authority) is not AuthorityContext
            or authority.issuer_domain != "d12" or "persona" not in authority.owner_scope
            or not isinstance(c._GraphCoordinator__store, ProductionGraphStore)
            or c._GraphCoordinator__content_fence_v2 is None):
        raise ValueError("installed D12 Owner catalogue producer is unavailable")
    field = ContextProvider().compile_scheme({"schema": "d03.context.scheme.v1", "roles": roles, "norms": norms}, None)
    field = json.loads(canonical_serialize(field))
    ns, store = authority.namespace, c._GraphCoordinator__store
    request_digest = canonical_digest((SCHEMA, ns, operation_id, field, budget_ref))

    def commit(db, metadata, epoch, now, owner, scope):
        def head(key):
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (key.token, *ns.as_tuple)).fetchone()
            if row is None or row[0] < 1 or row[2] != 1:
                raise ValueError("context adoption requires an actual current draft, head and Owner")
            value = json.loads(row[1])
            if canonical_json(value) != row[1]:
                raise ValueError("context adoption prerequisite bytes differ")
            store._registry.validate(key, value)
            history = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                (key.token, row[0])).fetchone()
            if history != (row[1], 1):
                raise ValueError("context adoption prerequisite has no immutable adopted history")
            return row[0], value

        draft_key, head_key, owner_key = character_draft_key(ns), active_scheme_head_key(ns), owner_grant_key(*ns.as_tuple)
        draft_revision, prior_value = head(draft_key)
        head_revision, head_value = head(head_key)
        owner_revision, _ = head(owner_key)
        prior = CharacterDraft(**{k: v for k, v in prior_value.items() if k != "schema"})
        active = ActiveSchemeHeadV1(**{k: v for k, v in head_value.items() if k != "schema"})
        if (prior.scope != ns.persona_id or prior.revision != draft_revision
                or active.scope != ns.persona_id or active.generation != head_revision
                or active.draft_ref != draft_key.token):
            raise ValueError("context adoption current draft/head identity differs")
        if prior.fields.get(CONTEXT_SCHEME_FIELD) == field:
            raise ValueError("context catalogue intent has no field change")
        draft = CharacterDraft(ns.persona_id, draft_revision + 1,
            {**prior.fields, CONTEXT_SCHEME_FIELD: field}, {**prior.field_sources, CONTEXT_SCHEME_FIELD: "owner"})
        roles_set, norms_set = set(field["roles"]), set(field["norms"])
        from .d12_current_domain_selection_v1 import read_current_domain_selection_v1
        _, _, previous_selection = read_current_domain_selection_v1(db, ns, domain="d03", field_name=CONTEXT_SCHEME_FIELD)
        previous_roles, previous_norms = None, None
        if previous_selection is not None:
            row = db.execute("SELECT candidate_json,candidate_sha256 FROM graph_d12_domain_candidates_v1 "
                "WHERE bot=? AND persona=? AND candidate_ref=?", (*ns.as_tuple, previous_selection.candidate_ref)).fetchone()
            import hashlib
            if row is None or hashlib.sha256(row[0].encode()).hexdigest() != row[1]:
                raise ValueError("previous adopted Context candidate bytes differ")
            previous_candidate = json.loads(row[0])
            if (previous_candidate.get("$type") != D12ContextSchemeCandidateV1.__module__ + "." + D12ContextSchemeCandidateV1.__qualname__
                    or previous_candidate["namespace"] != {"$type": "sylanne3.runtime_contracts.NamespaceId",
                        "bot_id": ns.bot_id, "persona_id": ns.persona_id}
                    or previous_candidate["field_names"] != [CONTEXT_SCHEME_FIELD]):
                raise ValueError("previous adopted Context catalogue identity differs")
            previous_roles, previous_norms = previous_candidate["roles"], previous_candidate["norms"]
        rows = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.role_binding' ORDER BY token LIMIT 129", ns.as_tuple).fetchall()
        if len(rows) > 128:
            raise ValueError("context compatibility requires the complete bounded role inventory")
        read_versions = [GraphVersion(draft_key, draft_revision), GraphVersion(head_key, head_revision), GraphVersion(owner_key, owner_revision)]
        compatibility, changed_bindings = [], []
        for ref, revision, encoded, valid in rows:
            key = AtomKey.from_token(ref)
            read_versions.append(GraphVersion(key, revision))
            if not valid:
                continue
            store._registry.validate(key, json.loads(encoded))
            role = RoleBinding(**_tuple_payload(json.loads(encoded), "norm_refs", "source_refs"))
            used = role.status == "active" and (role.effective_until is None or role.effective_until > now)
            missing = tuple(sorted(({role.social_role} - roles_set) | (set(role.norm_refs) - norms_set))) if used else ()
            if missing:
                raise ValueError("context edit removes an in-use role or norm: " + ref)
            compatibility.append([ref, revision, canonical_digest(json.loads(encoded)), used, list(missing)])
            previous_resolved = (previous_roles is not None and role.social_role in previous_roles
                and set(role.norm_refs) <= set(previous_norms))
            next_resolved = role.social_role in roles_set and set(role.norm_refs) <= norms_set
            if used and previous_resolved != next_resolved:
                changed_bindings.append(ref)
        budget = get_budget_lease(db, budget_ref)
        issuer = c._GraphCoordinator__d11_issuer
        grant = issuer.current_budget_grant(db, budget_ref)
        if (budget.state != "active" or (budget.bot_id, budget.persona_id) != ns.as_tuple
                or (grant.bot_id, grant.persona_id, grant.lease_id) != (*ns.as_tuple, budget_ref)
                or "scheme_compile" not in grant.allowed_work_kinds or grant.valid_until_utc <= now):
            raise ValueError("context compilation requires its current signed budget authorization")
        require_budget_family_admissible(db, budget_ref)
        budget_digest = canonical_digest({"kind": "signed_budget_authorization_no_paid_cost",
            "budget_ref": budget_ref, "lease_version": budget.version, "grant": grant})
        draft_digest = canonical_digest(draft)
        frozen_fields = ((CONTEXT_SCHEME_FIELD, field, "owner"),)
        candidate = compile_d12_domain_scheme_candidate_v1(namespace=ns, draft_digest=draft_digest, domain="d03",
            fields=frozen_fields, field_input_digest=canonical_digest((draft_digest, "d03", frozen_fields)))
        if type(candidate) is not D12ContextSchemeCandidateV1:
            raise ValueError("actual D03 static compiler rejected the Owner catalogue")
        install_d12_compiled_candidate_store_v1(db)
        install_scheme_original_store_v1(db)
        domain_receipt = record_d12_domain_candidate_v1(db, ns, candidate)
        access_epoch, delete_epoch = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
        compiled = D12CompiledSchemeV1(ns, draft_key.token, draft.revision, draft_digest, head_key.token,
            head_revision, metadata.graph_revision, access_epoch, delete_epoch, (domain_receipt,), "", "")
        digest = compiled_scheme_digest_v1(compiled)
        compiled = replace(compiled, compiled_digest=digest, issuer_seal="w01:" + canonical_digest(
            (operation_id, digest, owner.authorization_head, budget_digest)))
        preview = {"schema": "d12.static-context-compatibility.v1", "draft_ref": draft_key.token,
            "previous_draft_revision": draft_revision, "draft_revision": draft.revision,
            "draft_digest": draft_digest, "field_name": CONTEXT_SCHEME_FIELD, "field_source": "owner",
            "previous_head_ref": head_key.token, "previous_head_revision": head_revision,
            "previous_compiled_digest": active.compiled_digest, "candidate_ref": domain_receipt.candidate_ref,
            "candidate_digest": candidate.candidate_digest, "role_inventory": compatibility,
            "previous_roles": previous_roles, "previous_norms": previous_norms,
            "roles": field["roles"], "norms": field["norms"],
            "affected_refs": [head_key.token, *changed_bindings], "historical_refs_preserved": [active.compiled_digest],
            "pending_reevaluation_refs": changed_bindings, "status": "compatible_static_catalogue"}
        original = CompilationOriginalV1(operation_id, compiled,
            canonical_digest((ns, operation_id, draft, active, preview, scope.pinned_anchor)), budget_digest)
        record_compilation_original_for_operation_v1(db, original)
        next_head = ActiveSchemeHeadV1(ns.persona_id, head_revision + 1, digest, draft_key.token, draft.revision,
            draft_digest, active.compiled_digest, operation_id, "administrative_edit")
        writes = (GraphWrite(draft_key, {"schema": draft_key.type_name, **asdict(draft)}),
            GraphWrite(head_key, {"schema": head_key.type_name, **asdict(next_head)}))
        event = Event(Scope(*ns.as_tuple, "d12.context_catalogue.v1"), operation_id, now,
            "d12.context_catalogue.v1", {"request_digest": request_digest, "compatibility_digest": canonical_digest(preview)})
        receipt = GraphStore._graph_commit_in_transaction(store, GraphCandidate(event,
            tuple(sorted(read_versions, key=lambda v: v.key.token)), writes, (epoch,)),
            _capability=c._GraphCoordinator__graph_capability)
        expected = {GraphVersion(draft_key, draft.revision), GraphVersion(head_key, next_head.generation)}
        if receipt.status != "committed" or set(receipt.revisions) != expected or receipt.invalidated:
            raise ValueError("context catalogue actual draft/head CAS differs")
        store.cas_graph_recovery_metadata(metadata, metadata.requirements, _capability=c._GraphCoordinator__graph_capability)
        return {"schema": SCHEMA, "operation_id": operation_id, "draft_ref": draft_key.token,
            "draft_revision": draft.revision, "compiled_digest": digest, "candidate_ref": domain_receipt.candidate_ref,
            "compatibility": preview, "compatibility_digest": canonical_digest(preview),
            "head_ref": head_key.token, "head_revision": next_head.generation,
            "graph_receipt": {"status": receipt.status, "revisions": [[v.key.token, v.revision] for v in receipt.revisions],
                "invalidated": [], "epoch": asdict(receipt.epoch)}}

    return c._owner_domain_write_v3(authority, lease, operation_id=operation_id, request_digest=request_digest,
        domains=("d03", "d11", "d12"), capability="workbench.activate", commit=commit)
