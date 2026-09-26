"""Installed outbound admission seam with transaction-backed D06 inspection.

This issuer remains HOLD until each required provider and the independent
deletion/Authority barriers are installed.  A caller's receipt, boolean, or
snapshot cannot turn a partial inspection into a dispatch admission.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
import sqlite3

from ..domains.d06 import SourceGrantRead, provide_source_grant_check
from ..domains.d03 import ContextProvider, RoleBindingRequest
from ..domains.d05 import RelationshipProvider
from ..domains.d08 import (
    ActionIntent, ActionSchema, ActionSchemaRecord, GoalExecutionProvider,
    RequiredCheckSpec,
)
from ..domains.d09 import D09ExpressionProvider
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from ..runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from ..runtime_contracts import CheckReceipt, NamespaceId, QueryEpoch, canonical_digest
from .budget import BudgetError, get_budget_lease, require_budget_family_admissible
from .dispatch_budget_check import provide_dispatch_budget_check
from .dispatch_current_projection import (
    derive_current_domain_reads, read_current_dispatch_projection,
)
from .dispatch_current_commitments import read_current_d08_conflict_facts
from .issuers import D02ResourceIssuer, D11BudgetGrantIssuer, IssuerAuthorityDenied


_MISSING_PROVIDER_PORTS = (
    "d11.execution_journal_current_constraints",
    "d11.command_provenance.current_provider",
    "d11.domain_context.current_provider",
    "d06.independent_deletion_authority_barrier",
)


@dataclass(frozen=True)
class DispatchSourceInspectionV1:
    status: str
    missing: tuple[str, ...]
    observed_versions: tuple[tuple[str, int], ...]
    provider_result: str | None


@dataclass(frozen=True)
class DispatchSocialInspectionV1:
    status: str
    missing: tuple[str, ...]
    role_receipt: CheckReceipt | None
    boundary_receipt: CheckReceipt | None
    graph_epoch: int | None


@dataclass(frozen=True)
class DispatchBudgetInspectionV1:
    status: str
    missing: tuple[str, ...]
    receipt: CheckReceipt | None
    lease_id: str | None
    quote_id: str | None


@dataclass(frozen=True)
class DispatchCommitmentInspectionV1:
    status: str
    missing: tuple[str, ...]
    graph_epoch: int | None
    commitment_refs: tuple[str, ...]
    action_refs: tuple[str, ...]


class DispatchAdmissionHold(RuntimeError):
    def __init__(self, missing: tuple[str, ...]):
        self.missing = tuple(dict.fromkeys(missing))
        super().__init__("dispatch admission HOLD: " + ", ".join(self.missing))


def inspect_current_d06_source_grant(
    db, intent: ActionIntent, spec: RequiredCheckSpec,
    candidate: DispatchCandidateEvidenceV1, *, audience: tuple[str, ...],
) -> DispatchSourceInspectionV1:
    """Read D06 inputs from the caller-held graph transaction; never issue PASS.

    The graph rows and namespace epoch are read afresh. The independent
    deletion/Authority barrier is not derivable from this SQLite snapshot, so
    D06 receives an unconfirmed barrier and cannot issue a passing receipt.
    """
    if not getattr(db, "in_transaction", False):
        raise DispatchAdmissionHold(("graph.current_write_transaction",))
    if (type(intent) is not ActionIntent or type(spec) is not RequiredCheckSpec
            or type(candidate) is not DispatchCandidateEvidenceV1
            or type(audience) is not tuple):
        raise DispatchAdmissionHold(("d06.typed_action_spec_candidate_audience",))
    if (spec.check_kind, spec.provider_id) != ("source_grant", "d06.source_grant"):
        raise DispatchAdmissionHold(("d06.source_grant_spec",))
    if (candidate.status != "source_qualified"
            or candidate.action_digest != canonical_digest(intent)
            or candidate.source_refs != intent.source_refs
            or candidate.source_audience != audience
            or spec not in intent.required_checks):
        raise DispatchAdmissionHold(("d06.qualified_candidate_identity",))
    try:
        source_key = AtomKey.from_token(intent.source_refs[0])
        namespace = NamespaceId(source_key.owner.bot, source_key.owner.persona)
    except (IndexError, TypeError, ValueError) as exc:
        raise DispatchAdmissionHold(("d06.canonical_source_namespace",)) from exc
    if (spec.subject_ref != f"persona:{namespace.persona_id}"
            or spec.action_ref != intent.action_id
            or spec.purpose != "expression"):
        raise DispatchAdmissionHold(("d06.source_grant_scope",))
    epoch_row = db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch_row is None or epoch_row[0] != candidate.query_epoch:
        raise DispatchAdmissionHold(("d06.current_graph_epoch",))
    guard_row = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if guard_row != (candidate.access_epoch, candidate.delete_epoch):
        raise DispatchAdmissionHold(("d06.current_access_delete_epochs",))
    required = candidate.source_proof_versions
    if (not required or len(required) != len(set(ref for ref, _ in required))
            or set(required) != set(candidate.source_read_versions +
                                    candidate.access_read_versions)):
        raise DispatchAdmissionHold(("d06.complete_source_access_read_set",))
    atoms = []
    proof = []
    for ref, revision in required:
        try:
            key = AtomKey.from_token(ref)
        except (TypeError, ValueError) as exc:
            raise DispatchAdmissionHold(("d06.canonical_graph_ref",)) from exc
        if ((key.owner.bot, key.owner.persona) != namespace.as_tuple
                or key.type_name not in {"memory.source", "memory.access"}):
            raise DispatchAdmissionHold(("d06.source_access_namespace",))
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
        ).fetchone()
        if row is None or row[0] != revision or row[2] != 1:
            raise DispatchAdmissionHold(("d06.current_source_access_versions",))
        try:
            value = json.loads(row[1])
            atom = GraphAtom(key, revision, value, True)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DispatchAdmissionHold(("d06.current_source_access_values",)) from exc
        atoms.append(atom)
        proof.append((ref, revision, canonical_digest(atom.value)))
    if canonical_digest(proof) != candidate.source_proof_digest:
        raise DispatchAdmissionHold(("d06.current_source_access_content",))
    snapshot = GraphSnapshot(tuple(atoms), (
        NamespaceEpoch(*namespace.as_tuple, candidate.query_epoch),
    ))
    try:
        receipt = provide_source_grant_check(
            intent, SourceGrantRead(snapshot, audience, "expression", True, False),
            valid_until=0.0,
        )
    except (TypeError, ValueError) as exc:
        raise DispatchAdmissionHold(("d06.provider_recomputation",)) from exc
    return DispatchSourceInspectionV1(
        "hold", ("d06.independent_deletion_authority_barrier",),
        required, receipt.result,
    )


def _current_atom(db, namespace: NamespaceId, ref: str, expected_type: str,
                  expected_digest: str | None = None) -> GraphAtom:
    key = AtomKey.from_token(ref)
    if (key.type_name != expected_type
            or (key.owner.bot, key.owner.persona) != namespace.as_tuple):
        raise ValueError("graph atom scope differs")
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
        "AND bot=? AND persona=?", (ref, *namespace.as_tuple),
    ).fetchone()
    if row is None or row[2] != 1:
        raise ValueError("current graph atom unavailable")
    value = json.loads(row[1])
    atom = GraphAtom(key, row[0], value, True)
    if expected_digest is not None and canonical_digest(atom.value) != expected_digest:
        raise ValueError("current graph atom content differs")
    return atom


def inspect_current_d03_d05(
    db, candidate: DispatchCandidateEvidenceV1, *,
    context: ContextProvider, now_utc: float,
) -> DispatchSocialInspectionV1:
    """Issue scoped D03/D05 candidates from a complete current namespace read.

    The installed ContextProvider must carry the trusted active D03 catalogue.
    The D09 audience is read from the graph; an ambiguous audience mapping
    stays HOLD rather than selecting a convenient D05 boundary scope.
    """
    def hold(*missing: str, role=None, boundary=None, epoch=None):
        return DispatchSocialInspectionV1("hold", tuple(dict.fromkeys(missing)),
                                          role, boundary, epoch)

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if (type(candidate) is not DispatchCandidateEvidenceV1
            or type(context) is not ContextProvider
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return hold("social.typed_installed_context_and_time")
    try:
        key = AtomKey.from_token(candidate.action_ref)
        namespace = NamespaceId(key.owner.bot, key.owner.persona)
        epoch_row = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        if epoch_row is None or epoch_row[0] != candidate.query_epoch:
            return hold("social.current_graph_epoch")
        epoch = epoch_row[0]
        action_atom = _current_atom(db, namespace, candidate.action_ref,
                                    "d08.action_intent.v1")
        schema_atom = _current_atom(db, namespace, candidate.schema_ref,
                                    "d08.action_schema.v1")
        batch_atom = _current_atom(db, namespace, candidate.batch_ref,
                                   "d09.verified_segment_batch.v1")
        d08 = {item.name: item for item in GoalExecutionProvider().register_types()}
        intent = d08["d08.action_intent.v1"].validator(action_atom.value)
        record = d08["d08.action_schema.v1"].validator(schema_atom.value)
        next(item for item in D09ExpressionProvider.register_types()
             if item.name == "d09.verified_segment_batch.v1").validator(batch_atom.value)
        batch = batch_atom.value
        frozen = ActionSchema(record.schema_id, record.action_kind,
                              record.proactive, record.required_checks)
        expected_activity = intent.identity.activity_id
        if (candidate.action_digest != canonical_digest(intent)
                or candidate.schema_digest != canonical_digest(record)
                or candidate.batch_digest != batch["batch_digest"]
                or record != ActionSchemaRecord.bind(intent, frozen)
                or intent.identity.operation_id != candidate.operation_id
                or any(atom.key.owner.kind != "activity"
                       or atom.key.owner.subject != expected_activity
                       for atom in (action_atom, schema_atom, batch_atom))
                or action_atom.key.name != intent.action_id
                or schema_atom.key.name != record.schema_ref
                or batch_atom.key.name != batch["batch_id"]
                or batch["action_id"] != intent.action_id
                or batch["target_ref"] != intent.target_ref
                or batch["scene_ref"][:6] != "scene:"):
            return hold("social.current_action_schema_batch_identity")
        audience = tuple(batch["audiences"])
        if len(audience) != 1 or audience != candidate.source_audience:
            return hold("social.current_d09_audience_scope")
        scene = batch["scene_ref"]
        rows = db.execute(
            "SELECT token,revision,value,type_name FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name IN "
            "('d03.role_binding','d05.boundary_rule') AND valid=1 ORDER BY token",
            namespace.as_tuple,
        ).fetchall()
        atoms = tuple(GraphAtom(AtomKey.from_token(token), revision,
                                json.loads(raw), True)
                      for token, revision, raw, _ in rows)
        snapshot = GraphSnapshot(atoms, (NamespaceEpoch(*namespace.as_tuple, epoch),))
        projection = read_current_dispatch_projection(
            db, namespace, snapshot, QueryEpoch(namespace, "all", epoch),
        )
        request = RoleBindingRequest(
            f"persona:{namespace.persona_id}", intent.target_ref, None,
            scene, intent.action_kind, intent.purpose, now_utc, True,
        )
        role_read, boundary_read = derive_current_domain_reads(
            db, projection, request, context,
        )
        specs = {item.check_kind: item for item in intent.required_checks
                 if item.check_kind in {"role_binding", "boundary"}}
        if (len(specs) != 2 or specs["role_binding"].provider_id != "d03.role_binding"
                or specs["boundary"].provider_id != "d05.boundary"):
            return hold("social.frozen_required_check_specs", epoch=epoch)
        for spec in specs.values():
            criteria = next(item for item in spec.required_input_versions
                            if item.ref == spec.criteria_version)
            criterion = _current_atom(
                db, namespace, criteria.ref,
                AtomKey.from_token(criteria.ref).type_name,
            )
            if criterion.revision != criteria.version:
                return hold("social.current_criteria_version", epoch=epoch)
        role = context.provide_required_check(
            intent, role_read, valid_until=now_utc + 1.0,
        )
        boundary_criteria = next(item for item in specs["boundary"].required_input_versions
                                 if item.ref == specs["boundary"].criteria_version)
        from dataclasses import replace
        boundary_read = replace(
            boundary_read, input_versions=boundary_read.input_versions +
            (boundary_criteria,),
        )
        boundary = RelationshipProvider(
            boundary_read_verifier=lambda read: read == boundary_read,
        ).boundary_required_check(
            intent, frozen, boundary_read, audience_scope=audience[0],
            scene_ref=scene, at_time=now_utc, valid_until=now_utc + 1.0,
        )
    except (TypeError, ValueError, KeyError, StopIteration, json.JSONDecodeError):
        return hold("social.current_graph_provider_read_unavailable")
    missing = []
    if any(rule.subject_persona_ref == f"persona:{namespace.persona_id}"
           and rule.target_entity_ref == intent.target_ref
           and rule.action_kind == intent.action_kind
           and (rule.scene_ref is None or rule.scene_ref == scene)
           and rule.audience_scope != audience[0]
           for rule in boundary_read.rules):
        missing.append("d05.audience_scope_mapping_unavailable")
    if role.result != "pass" or role.coverage != "full":
        missing.append("d03.current_role_binding_not_pass")
    if boundary.result != "pass" or boundary.coverage != "full":
        missing.append("d05.current_boundary_not_pass")
    if projection.coverage != "full":
        missing.extend(projection.missing_sources)
    return DispatchSocialInspectionV1(
        "hold" if missing else "checks_pass", tuple(dict.fromkeys(missing)),
        role, boundary, epoch,
    )


def inspect_current_d11_dispatch_budget(
    db, intent: ActionIntent, *, d11_issuer: D11BudgetGrantIssuer | None,
    d02_issuer: D02ResourceIssuer | None, now_utc: float,
) -> DispatchBudgetInspectionV1:
    """Recompute one scoped D11 budget check from signed and durable state.

    The frozen RequiredCheckSpec uses the signed D02 quote VersionedRef as its
    criteria_version. The existing D11 provider excludes only that criteria
    ref while recomputing the exact lease/grant/reservation read set. This
    seam verifies that the excluded ref really names the active signed quote
    bound to the action and held reservation.
    The independent execution journal is a separate, still required gate.
    """
    def hold(*missing: str, lease_id=None, quote_id=None):
        return DispatchBudgetInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), None, lease_id, quote_id,
        )

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if type(intent) is not ActionIntent or type(now_utc) not in (int, float) or not math.isfinite(now_utc):
        return hold("d11.typed_current_action_and_time")
    if not isinstance(d11_issuer, D11BudgetGrantIssuer):
        return hold("d11.installed_signed_budget_grant_issuer")
    if not isinstance(d02_issuer, D02ResourceIssuer):
        return hold("d11.installed_signed_d02_quote_issuer")
    specs = tuple(spec for spec in intent.required_checks
                  if spec.check_kind == "dispatch_budget")
    if len(specs) != 1 or specs[0].provider_id != "d11.dispatch_budget":
        return hold("d11.unique_frozen_dispatch_budget_spec")
    spec = specs[0]
    if (spec.subject_ref != "persona:" + spec.subject_ref.removeprefix("persona:")
            or spec.action_ref != intent.action_id or spec.purpose != intent.purpose):
        return hold("d11.frozen_budget_scope")
    versions = spec.required_input_versions
    by_ref = {item.ref: item.version for item in versions}
    if len(by_ref) != len(versions):
        return hold("d11.duplicate_frozen_budget_refs")
    lease_refs = tuple(ref for ref in by_ref if ref.startswith("d11.budget.grant:"))
    if len(lease_refs) != 1:
        return hold("d11.frozen_spec_missing_signed_grant_version")
    lease_id = lease_refs[0].removeprefix("d11.budget.grant:")
    quote_refs = tuple(ref for ref in by_ref if ref.startswith("d02.resource_quote:"))
    if len(quote_refs) != 1:
        return hold("d11.frozen_spec_missing_signed_d02_quote_version", lease_id=lease_id)
    quote_id = quote_refs[0].removeprefix("d02.resource_quote:")
    if spec.criteria_version != quote_refs[0]:
        return hold("d11.criteria_not_signed_d02_quote_ref", lease_id=lease_id,
                    quote_id=quote_id)
    try:
        quote = d02_issuer._load_quote(db, quote_id, by_ref[quote_refs[0]])
        grant = d11_issuer.current_budget_grant(db, lease_id)
        lease = get_budget_lease(db, lease_id)
        require_budget_family_admissible(db, lease_id)
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease_id, intent.identity.operation_id),
        ).fetchone()
    except (IssuerAuthorityDenied, BudgetError, ValueError, TypeError):
        return hold("d11.current_signed_quote_grant_or_lease_unavailable",
                    lease_id=lease_id, quote_id=quote_id)
    if (reservation is None or reservation[2] != "reserved"):
        return hold("d11.current_operation_reservation_unavailable",
                    lease_id=lease_id, quote_id=quote_id)
    try:
        ceiling = json.loads(reservation[1])
    except (TypeError, ValueError, json.JSONDecodeError):
        return hold("d11.current_reservation_ceiling_invalid",
                    lease_id=lease_id, quote_id=quote_id)
    if (quote.quote_id != quote_id or quote.version != by_ref[quote_refs[0]]
            or quote.persona_id != spec.subject_ref.removeprefix("persona:")
            or (quote.activity_id, quote.effect_id, quote.operation_id) != (
                intent.identity.activity_id, intent.identity.effect_id,
                intent.identity.operation_id)
            or quote.work_kind != intent.action_kind
            or quote.parent_budget_lease_ref != lease_id
            or quote.valid_until_utc <= now_utc
            or quote.deadline_utc <= now_utc
            or dict(quote.ceiling) != ceiling
            or (lease.bot_id, lease.persona_id, lease.currency) != (
                quote.bot_id, quote.persona_id, grant.currency)
            or grant.valid_until_utc <= now_utc):
        return hold("d11.signed_quote_reservation_scope_or_ceiling_differs",
                    lease_id=lease_id, quote_id=quote_id)
    reservation_ref = (
        f"d11.budget.reservation:{lease_id}:{intent.identity.operation_id}:"
        f"{reservation[0]}"
    )
    if by_ref.get(reservation_ref) != 1:
        return hold("d11.frozen_spec_reservation_digest_differs",
                    lease_id=lease_id, quote_id=quote_id)
    try:
        ledger = provide_dispatch_budget_check(
            intent, db, d11_issuer,
            namespace=NamespaceId(quote.bot_id, quote.persona_id),
            lease_id=lease_id,
            reservation_operation_id=intent.identity.operation_id,
            reservation_digest=reservation[0], required_ceiling=quote.ceiling,
            work_kind=quote.work_kind, policy_ref=grant.policy_ref,
            now_utc=now_utc,
            valid_until=min(quote.valid_until_utc, grant.valid_until_utc),
        )
    except (TypeError, ValueError, BudgetError, IssuerAuthorityDenied):
        return hold("d11.current_budget_provider_unavailable",
                    lease_id=lease_id, quote_id=quote_id)
    if ledger.result != "pass" or ledger.coverage != "full":
        return hold("d11.current_budget_provider_not_pass",
                    lease_id=lease_id, quote_id=quote_id)
    return DispatchBudgetInspectionV1("check_pass", (), ledger, lease_id, quote_id)


def inspect_current_d08_commitments(
    db, candidate: DispatchCandidateEvidenceV1,
) -> DispatchCommitmentInspectionV1:
    """Inventory all current D08 conflict rows under the graph transaction.

    This can veto stale identity or shared effects. It cannot issue D08 PASS:
    the criteria issuer, semantic conflict policy and authenticated P2 effect
    and cancellation reads are not installed at this admission seam.
    """
    def hold(*missing: str, epoch=None, commitments=(), actions=()):
        return DispatchCommitmentInspectionV1(
            "hold", tuple(dict.fromkeys(missing)), epoch,
            tuple(commitments), tuple(actions),
        )

    if not getattr(db, "in_transaction", False):
        return hold("graph.current_write_transaction")
    if type(candidate) is not DispatchCandidateEvidenceV1:
        return hold("d08.typed_dispatch_candidate")
    try:
        action_key = AtomKey.from_token(candidate.action_ref)
        namespace = NamespaceId(action_key.owner.bot, action_key.owner.persona)
        epoch_row = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()
        if epoch_row is None or epoch_row[0] != candidate.query_epoch:
            return hold("d08.current_graph_epoch_differs")
        epoch = epoch_row[0]
        rows = db.execute(
            "SELECT token,revision,value,type_name FROM graph_atoms "
            "WHERE bot=? AND persona=? AND type_name IN "
            "('d08.commitment.v1','d08.action_intent.v1',"
            "'d08.action_outcome.v1') AND valid=1 ORDER BY token",
            namespace.as_tuple,
        ).fetchall()
        atoms = tuple(GraphAtom(
            AtomKey.from_token(token), revision, json.loads(raw), True,
        ) for token, revision, raw, _ in rows)
        snapshot = GraphSnapshot(
            atoms, (NamespaceEpoch(*namespace.as_tuple, epoch),),
        )
        facts = read_current_d08_conflict_facts(
            db, namespace, snapshot, QueryEpoch(namespace, "all", epoch),
        )
    except sqlite3.OperationalError:
        return hold("d08.current_graph_schema_unavailable")
    except (TypeError, ValueError, KeyError, json.JSONDecodeError):
        return hold("d08.current_complete_graph_inventory_unavailable")
    actions = tuple(item.action_id for item in facts.action_intents)
    commitments = tuple(item.commitment_id for item in facts.commitments)
    current = tuple(item for item in facts.action_intents
                    if item.action_id == action_key.name
                    and item.identity.operation_id == candidate.operation_id)
    missing = list(facts.missing_sources)
    if (len(current) != 1 or action_key.type_name != "d08.action_intent.v1"
            or candidate.action_digest != canonical_digest(current[0])):
        missing.append("d08.current_action_identity_differs")
    else:
        intent = current[0]
        specs = tuple(item for item in intent.required_checks
                      if item.check_kind == "commitment_conflict")
        if len(specs) != 1 or specs[0].provider_id != "d08.commitment_conflict":
            missing.append("d08.frozen_commitment_check_missing")
        elif specs[0].criteria_version.startswith("criteria:"):
            missing.append("d08.criteria_ref_has_no_authoritative_issuer")
        if any(other.action_id != intent.action_id
               and other.identity.effect_id == intent.identity.effect_id
               for other in facts.action_intents):
            missing.append("d08.current_effect_shared_by_actions")
    missing.extend((
        "d08.criteria_issuer_unavailable",
        "d08.semantic_conflict_policy_unavailable",
        "d08.authenticated_p2_effect_and_post_graph_cas_unavailable",
    ))
    return DispatchCommitmentInspectionV1(
        "hold", tuple(dict.fromkeys(missing)), epoch, commitments, actions,
    )


class InstalledDispatchAdmissionIssuer:
    """The only production integration shape; all incomplete paths HOLD."""

    def __init__(self, *, context: ContextProvider | None = None,
                 d11_issuer: D11BudgetGrantIssuer | None = None,
                 d02_issuer: D02ResourceIssuer | None = None):
        self._context = context
        self._d11 = d11_issuer
        self._d02 = d02_issuer

    def issue_dispatch_admission(self, bundle, snapshot, candidate, db, *,
                                 graph_incarnation: str, now_utc: float):
        if not getattr(db, "in_transaction", False):
            raise DispatchAdmissionHold(("graph.current_write_transaction",))
        if type(candidate) is not DispatchCandidateEvidenceV1:
            raise DispatchAdmissionHold(("d08.typed_dispatch_candidate",))
        try:
            action_key = AtomKey.from_token(candidate.action_ref)
        except (TypeError, ValueError) as exc:
            raise DispatchAdmissionHold(("d08.canonical_action_ref",)) from exc
        if action_key.type_name != "d08.action_intent.v1":
            raise DispatchAdmissionHold(("d08.action_intent_ref",))
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? "
            "AND bot=? AND persona=?", (candidate.action_ref,
                                        action_key.owner.bot, action_key.owner.persona),
        ).fetchone()
        if row is None or row[2] != 1:
            raise DispatchAdmissionHold(("d08.current_action_intent",))
        try:
            action = next(item for item in GoalExecutionProvider().register_types()
                          if item.name == "d08.action_intent.v1").validator(
                              json.loads(row[1]))
        except (StopIteration, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DispatchAdmissionHold(("d08.valid_current_action_intent",)) from exc
        if (candidate.action_digest != canonical_digest(action)
                or candidate.operation_id != action.identity.operation_id):
            raise DispatchAdmissionHold(("d08.current_action_identity",))
        specs = tuple(item for item in action.required_checks
                      if item.check_kind == "source_grant")
        if len(specs) != 1:
            raise DispatchAdmissionHold(("d06.unique_source_grant_spec",))
        inspection = inspect_current_d06_source_grant(
            db, action, specs[0], candidate, audience=candidate.source_audience,
        )
        social_missing = ("d03.d05.installed_context_provider",)
        if self._context is not None:
            social = inspect_current_d03_d05(
                db, candidate, context=self._context, now_utc=now_utc,
            )
            social_missing = social.missing
        budget = inspect_current_d11_dispatch_budget(
            db, action, d11_issuer=self._d11, d02_issuer=self._d02,
            now_utc=now_utc,
        )
        commitments = inspect_current_d08_commitments(db, candidate)
        raise DispatchAdmissionHold((
            *inspection.missing, *social_missing, *budget.missing,
            *commitments.missing,
            *_MISSING_PROVIDER_PORTS,
        ))

    def verify_required_check(self, spec, receipt, snapshot, db) -> bool:
        return False

    def verify_domain_context(self, admission, snapshot, db) -> bool:
        return False

    def verify_command_provenance(self, request, admission, db) -> bool:
        return False

    def verify_journal_constraints(self, request, admission) -> bool:
        return False


__all__ = [
    "DispatchAdmissionHold", "DispatchSourceInspectionV1",
    "InstalledDispatchAdmissionIssuer", "inspect_current_d06_source_grant",
    "DispatchSocialInspectionV1", "inspect_current_d03_d05",
    "DispatchBudgetInspectionV1",
    "inspect_current_d11_dispatch_budget",
    "DispatchCommitmentInspectionV1", "inspect_current_d08_commitments",
]
