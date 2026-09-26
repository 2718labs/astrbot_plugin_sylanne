"""Installed outbound admission seam with transaction-backed D06 inspection.

This issuer remains HOLD until each required provider and the independent
deletion/Authority barriers are installed.  A caller's receipt, boolean, or
snapshot cannot turn a partial inspection into a dispatch admission.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d06 import SourceGrantRead, provide_source_grant_check
from ..domains.d08 import ActionIntent, GoalExecutionProvider, RequiredCheckSpec
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch
from ..runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from ..runtime_contracts import CheckReceipt, NamespaceId, canonical_digest


_MISSING_PROVIDER_PORTS = (
    "d03.role_binding.current_provider",
    "d05.boundary.current_provider",
    "d08.commitment_conflict.current_provider",
    "d11.dispatch_budget.current_grant_and_journal",
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


class InstalledDispatchAdmissionIssuer:
    """The only production integration shape; all incomplete paths HOLD."""

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
        raise DispatchAdmissionHold((
            *inspection.missing, "d08.d09.current_graph_command_reader",
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
]
