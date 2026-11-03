"""Selected Owner growth review controls on the existing formal readonly Work.

The profile opens no target semantic body and carries no Source roots. Mark and
confirm remain separate Source ALL business Works with fresh Owner authority.
"""
from dataclasses import dataclass
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, owner_grant_key
from ..domains.d01 import PersonaDomain, _activation_key
from ..domains.d01.production_operations_v1 import plain_v1
from .persona_growth_review_contract_v1 import (
    MARK_OPERATIONS_V1, CONFIRM_OPERATIONS_V1,
    growth_review_key_v1, target_domain_v1)
from .persona_growth_review_metadata_v1 import (
    growth_metadata_head_v1, growth_target_control_v1, read_growth_review_metadata_v1,
    require_growth_control_metadata_point_v1)
from .persona_growth_review_v1 import qualify_growth_metadata_v1

DOMAIN = "growth_review"
FIELDS = ("schema", "namespace", "target_version", "activation_version",
    "persona_head_version", "persona_head_id", "growth_operation_id",
    "growth_original_digest", "graph_incarnation", "state", "review_operation_id", "owner_grant")


def is_growth_owner_read_v1(reader):
    return getattr(reader, "operation_kind", None) == "read_beta1_owner_state_v1" and reader.request.domain == DOMAIN


def growth_owner_metadata_spec_v1(reader, identity):
    if not is_growth_owner_read_v1(reader):
        return None
    kind, ref = identity
    if kind == "growth_owner_receipt":
        from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
        state = require_owner_state_reader_v3(reader)
        if ref not in state.growth_receipt_selections:
            raise AuthorityUnavailable("Growth receipt selector lacks its exact metadata issuance")
        operation_id, members = ref
        return ("graph_domain_production_originals_v1", "receipt_json",
            ("bot", "persona", "operation_id"), (*reader.namespace.as_tuple, operation_id),
            ("domain", "operation_kind", "original_digest", "bundle_digest", "receipt_digest"),
            tuple((name,) for name in RECEIPT_FIELDS), None)
    if kind != "growth_owner_review" or ref not in {
            growth_review_key_v1(reader.namespace, target).token for target in reader.request.refs}:
        raise AuthorityUnavailable("Owner growth metadata is outside its explicitly selected targets")
    return ("graph_atoms", "value", ("token", "bot", "persona"),
        (ref, *reader.namespace.as_tuple), ("revision", "valid", "value_cell_id"),
        tuple((name,) for name in FIELDS), None)


def finish_growth_owner_metadata_v1(task, value):
    if not is_growth_owner_read_v1(task.reader):
        return False, None
    if task.identity[0] == "growth_owner_receipt":
        if (value is None or set(value) != set(RECEIPT_FIELDS)
                or task.column.canonical_digest != task.metadata[4]
                or value["status"] != "committed" or value["operation_id"] != task.identity[1][0]
                or value["operation_digest"] != task.metadata[3]
                or type(value["activity_id"]) is not str or not value["activity_id"]
                or type(value["commit_seq"]) is not int or value["commit_seq"] < 1
                or set(task.growth_receipt_members) != {key for key, _ in task.identity[1][1]}):
            raise AuthorityUnavailable("Growth receipt metadata lost exact original EOF/membership")
        receipt = GrowthOwnerReceiptV1(value["status"], value["operation_id"],
            value["operation_digest"], value["activity_id"], value["commit_seq"],
            tuple(GraphVersion(AtomKey.from_token(key), revision)
                for key, revision in sorted(task.growth_receipt_members.items())))
        return True, {"domain": task.metadata[0], "operation_kind": task.metadata[1],
            "original_digest": task.metadata[2], "receipt": receipt}
    if task.identity[0] != "growth_owner_review":
        raise AuthorityUnavailable("Owner growth metadata changed its fixed selected shape")
    if value is not None and (set(value) != set(FIELDS)
            or task.metadata != task.reader.heads.get(task.identity[1])
            or task.metadata[0] < 1):
        raise AuthorityUnavailable("Owner growth metadata changed its actual census Head")
    return True, value


def growth_owner_point_v1(reader, request):
    if not is_growth_owner_read_v1(reader):
        return False
    if request[0] == "graph_domain_production_originals_v1":
        raise AuthorityUnavailable("Growth READ cannot open a whole receipt or read-version list")
    if require_growth_control_metadata_point_v1(reader, request):
        # This helper permits only activation/history for this READ. Review
        # controls are selected by the streaming fixed-field profile instead.
        key = AtomKey.from_token(request[3][0])
        if key.type_name == "d01.persona_activation.v1":
            return True
    from .current_beta1_source_read_v3 import require_beta1_source_control_point_v3
    if require_beta1_source_control_point_v3(reader, request):
        return True
    if request == ("graph_atoms", ("revision", "value", "valid"), ("token", "bot", "persona"),
            (_activation_key(reader.namespace).token, *reader.namespace.as_tuple)):
        return reader.general_owner_entry is not None
    raise AuthorityUnavailable("Owner growth READ cannot open a target, review or Source semantic body")


def growth_owner_body_v1(reader, table, key):
    if not is_growth_owner_read_v1(reader):
        return False
    # Only these two current control values are decoded as actual GraphAtoms.
    if table == "graph_atoms" and tuple(key) in {
            (_activation_key(reader.namespace).token, *reader.namespace.as_tuple),
            (owner_grant_key(*reader.namespace.as_tuple).token, *reader.namespace.as_tuple)}:
        if reader.general_owner_entry is None:
            raise AuthorityUnavailable("Owner growth controls require actual independent Owner EOF")
        return True
    # The exact already-admitted point fixes columns; no original payload
    # column can enter this profile through the body hook.
    for request in reader.points:
        if request[0] == table and request[3] == tuple(key) and (
                require_growth_control_metadata_point_v1(reader, request)):
            return True
    raise AuthorityUnavailable("Owner growth READ has no protected semantic-body permission")


def _review_v1(reader, target, activation, head, control, grant, growth):
    from .beta1_owner_state_read_v3 import _metadata
    key = growth_review_key_v1(reader.namespace, target.key)
    version, valid = growth_metadata_head_v1(reader.db, reader.namespace, key)
    if not valid:
        return version, "pending", None
    value = _metadata(reader, ("growth_owner_review", key.token))
    expected = {
        "schema": "sylanne.persona-growth-review.v1", "namespace": plain_v1(reader.namespace),
        "target_version": plain_v1(target), "activation_version": plain_v1(activation),
        "persona_head_version": plain_v1(head), "persona_head_id": control.head_id,
        "growth_operation_id": growth[0], "growth_original_digest": growth[2]["original_digest"],
        "graph_incarnation": grant.value["graph_incarnation"],
        "owner_grant": plain_v1(GraphVersion(grant.key, grant.revision))}
    if value is None or any(value[name] != expected[name] for name in expected):
        return version, "stale", None
    producer = growth_target_control_v1(reader.db, version)
    domain = target_domain_v1(target.key)
    state = value["state"]
    expected_kind = CONFIRM_OPERATIONS_V1[domain] if state == "owner_confirmed_keep" else MARK_OPERATIONS_V1[domain]
    if (state not in {"pending", "owner_confirmed_keep"} or producer["domain"] != domain
            or producer["operation_kind"] != expected_kind
            or producer["receipt"].operation_id != value["review_operation_id"]):
        raise AuthorityUnavailable("Owner growth review lost its actual typed producing control")
    return version, state, value["review_operation_id"]


def growth_owner_plan_v1(reader):
    if not is_growth_owner_read_v1(reader):
        return None
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    from .current_method_learning_read_v3 import method_graph_head_v3
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    state = require_owner_state_reader_v3(reader)
    ns = reader.namespace
    activation = method_graph_head_v3(reader.db, ns, _activation_key(ns))
    grant = method_graph_head_v3(reader.db, ns, owner_grant_key(*ns.as_tuple))
    snapshot = GraphSnapshot((activation, grant), (reader.graph_stamp[1],))
    control = PersonaDomain.resolve_active_role_control_v3(snapshot, namespace=ns, current_guard=reader.owner_guard)
    head, valid = growth_metadata_head_v1(reader.db, ns, control.plan_key)
    if not valid:
        raise AuthorityUnavailable("Owner growth current persona control metadata is absent")
    controls = (control, GraphVersion(activation.key, activation.revision), head, grant)
    from .persona_growth_birth_v1 import current_persona_birth_control_v1, persona_birth_status_v1
    birth_control = current_persona_birth_control_v1(reader.db, namespace=ns)
    if (birth_control.activation_version != controls[1] or birth_control.persona_head_version != head
            or birth_control.head_id != control.head_id):
        raise AuthorityUnavailable("Owner growth metadata changed its actual persona identity join")
    growth, census, _ = qualify_growth_metadata_v1(reader.db, ns, controls)
    rows, missing = [], []
    capabilities = reader.owner_binding.capabilities
    can_control = ("workbench.control" in capabilities
        and {"context", "consolidation"} <= reader.owner_binding.purposes
        and "owner" in reader.owner_binding.audiences)
    # Complete the finite target-producer selectors before receipt membership
    # EOF. Several targets from one COMMIT then share one exact receipt recipe.
    targets = {}
    for ref in reader.request.refs:
        key = AtomKey.from_token(ref)
        target, valid = growth_metadata_head_v1(reader.db, ns, key)
        targets[ref] = (target, valid)
        if valid:
            read_growth_review_metadata_v1(reader.db, ("producer", ref, target.revision))
    for ref in reader.request.refs:
        key = AtomKey.from_token(ref)
        target, valid = targets[ref]
        if not valid:
            missing.append("selected_target_unavailable")
            continue
        # The original receipt supplies actual activity identity; its private
        # payload and Source roots are never opened or projected here.
        producer = growth_target_control_v1(reader.db, target)
        review, current, review_operation_id = (None, "not_required", None)
        request, actions = None, []
        baseline = ("no_growth" if growth is None else persona_birth_status_v1(
            reader.db, namespace=ns, target_key=key, current=birth_control))
        if growth is not None and baseline != "birth_current":
            review, current, review_operation_id = _review_v1(
                reader, target, controls[1], head, control, grant, growth)
            request = {"target_ref": ref, "expected_target_revision": target.revision,
                "growth_operation_id": growth[0], "expected_head_id": control.head_id,
                "expected_activation_revision": activation.revision, "expected_review_revision": review.revision}
            domain = target_domain_v1(key)
            if can_control:
                actions = ([CONFIRM_OPERATIONS_V1[domain]] if current == "pending" and review_operation_id
                    else [] if current == "owner_confirmed_keep" else [MARK_OPERATIONS_V1[domain]])
        rows.append({"ref": ref, "type_name": key.type_name, "revision": target.revision,
            "state": current, "baseline_state": baseline, "review_revision": 0 if review is None else review.revision,
            "review_operation_id": review_operation_id, "head_id": control.head_id,
            "activation_revision": activation.revision,
            "growth_operation_id": None if growth is None else growth[0],
            "request": request, "permitted_controls": actions,
            "activity_id": producer["receipt"].activity_id,
            "parent_budget_lease_ref": reader.parent_budget_lease_ref})
    # Finite result is produced only after every selected metadata recipe is EOF.
    state.roots = set()
    state.metadata_complete = True
    state.growth_projection = {"domain": DOMAIN, "items": rows,
        "coverage": "partial" if missing else "complete", "missing_inputs": missing}
    return ProductionReadPlanV1((), (_activation_key(ns), owner_grant_key(*ns.as_tuple)), (), ())


def growth_owner_projection_v1(reader):
    if not is_growth_owner_read_v1(reader):
        return None
    from .beta1_owner_state_read_v3 import require_owner_state_reader_v3
    state = require_owner_state_reader_v3(reader)
    if not state.metadata_complete or state.source_permission is None:
        raise AuthorityUnavailable("Owner growth metadata requires its actual completed readonly Work")
    state.source_permission.require_for_v3(reader)
    return state.growth_projection


RECEIPT_FIELDS = ("status", "operation_id", "operation_digest", "activity_id", "commit_seq")


@dataclass(frozen=True, slots=True)
class GrowthOwnerReceiptV1:
    status: str
    operation_id: str
    operation_digest: str
    activity_id: str
    commit_seq: int
    write_versions: tuple[GraphVersion, ...]


def _receipt_selection_v1(reader, operation_id, members):
    from .beta1_owner_state_read_v3 import _metadata, require_owner_state_reader_v3
    from .persona_growth_review_metadata_v1 import _original_allowed_v1
    if not _original_allowed_v1(reader, operation_id):
        raise AuthorityUnavailable("Growth receipt has no completed selected producer")
    selector = (operation_id, tuple(sorted(members)))
    state = require_owner_state_reader_v3(reader)
    state.growth_receipt_selections.add(selector)
    return _metadata(reader, ("growth_owner_receipt", selector))


def growth_owner_original_control_v1(reader, operation_id):
    from .persona_growth_review_metadata_v1 import _tasks_v1, growth_adoption_activation_control_v1
    tasks = _tasks_v1(reader)
    latest = tasks.get(("latest",))
    growth = (latest is not None and latest.complete and latest.row.latest is not None
        and latest.row.latest[0] == operation_id)
    if growth:
        original = _receipt_selection_v1(reader, operation_id, ((_activation_key(reader.namespace).token, 0),))
        receipt = original["receipt"]
        if ((original["domain"], original["operation_kind"]) not in {
                ("d01", "adopt_growth"), ("d01", "adopt_general_growth_v1")}
                or original["original_digest"] != latest.row.latest[2]
                or receipt.commit_seq != latest.row.latest[3]):
            raise AuthorityUnavailable("Growth receipt metadata differs from complete adopted census")
        versions = tuple((version.key.token, version.revision) for version in receipt.write_versions)
        if latest.growth_activation_versions != versions:
            reader.operation.reserve_retained_state_growth_v3(latest, 8192)
            try:
                latest.growth_activation_versions = versions
            finally:
                reader.operation.finish_retained_state_growth_v3(latest)
        activation = growth_adoption_activation_control_v1(reader.db, original)
        from ..graph_types import Owner
        plan_key = AtomKey(Owner("persona", *reader.namespace.as_tuple), "d01.persona_plan.v1", activation["plan_id"])
        original = _receipt_selection_v1(reader, operation_id, (*versions, (plan_key.token, 0)))
        return original
    members = tuple((selector[1], selector[2]) for selector, task in tasks.items()
        if selector[0] == "producer" and task.complete and task.row == operation_id)
    if not members:
        raise AuthorityUnavailable("Growth target receipt was not explicitly selected")
    return _receipt_selection_v1(reader, operation_id, members)


def _growth_receipt_column_v1(column):
    task = column.beta1_metadata_task
    return (task is not None and is_growth_owner_read_v1(task.reader)
        and task.identity[0] == "growth_owner_receipt")


def growth_owner_receipt_parser_v1(column, *, ensure_ascii):
    if not _growth_receipt_column_v1(column):
        return
    task = column.beta1_metadata_task
    task.growth_receipt_members = {}
    task.growth_receipt_match = ()
    task.growth_receipt_offset = 0
    task.growth_receipt_high = None
    task.growth_receipt_revision = bytearray()
    class SelectedReceiptStreamV1(type(column.parser)):
        def _append_decoded_codepoint(self, codepoint):
            state = self._string
            if (state is not None and state["mode"] == "value"
                    and len(state["path"]) == 3 and state["path"][0] == "write_versions"
                    and state["path"][2] == 0):
                high = task.growth_receipt_high
                if high is not None:
                    task.growth_receipt_high = None
                    if 0xdc00 <= codepoint <= 0xdfff:
                        codepoint = 0x10000 + ((high - 0xd800) << 10) + codepoint - 0xdc00
                    else:
                        _receipt_codepoint_v1(task, high)
                if 0xd800 <= codepoint <= 0xdbff:
                    task.growth_receipt_high = codepoint
                else:
                    _receipt_codepoint_v1(task, codepoint)
                return
            return super()._append_decoded_codepoint(codepoint)
    column.parser = SelectedReceiptStreamV1(ensure_ascii=ensure_ascii)


def _receipt_codepoint_v1(task, codepoint):
    position = task.growth_receipt_offset
    task.growth_receipt_match = tuple(key for key in task.growth_receipt_match
        if position < len(key) and ord(key[position]) == codepoint)
    task.growth_receipt_offset += 1


def growth_owner_metadata_emit_v1(column, event):
    if not _growth_receipt_column_v1(column):
        return column._emit_v3(event)
    task, path = column.beta1_metadata_task, event.path
    if path and path[0] == "write_versions":
        if len(path) == 2 and event.kind == "array_start":
            task.growth_receipt_match = ()
            task.growth_receipt_revision = bytearray()
        elif len(path) == 3 and path[2] == 0:
            if event.kind == "scalar_start":
                if event.scalar_kind != "string":
                    raise AuthorityUnavailable("Growth receipt write member has another registered shape")
                task.growth_receipt_match = tuple(key for key, _ in task.identity[1][1])
                task.growth_receipt_offset = 0
                task.growth_receipt_high = None
            elif event.kind == "scalar_end":
                if task.growth_receipt_high is not None:
                    _receipt_codepoint_v1(task, task.growth_receipt_high)
                    task.growth_receipt_high = None
                task.growth_receipt_match = tuple(key for key in task.growth_receipt_match
                    if len(key) == task.growth_receipt_offset)
        elif len(path) == 3 and path[2] == 1 and task.growth_receipt_match:
            if event.kind == "scalar_chunk":
                if event.scalar_kind != "number" or len(task.growth_receipt_revision) + len(event.raw) > 24:
                    raise AuthorityUnavailable("Growth selected write revision is not a bounded integer")
                task.growth_receipt_revision.extend(event.raw)
            elif event.kind == "scalar_end":
                import json
                revision = json.loads(task.growth_receipt_revision)
                if type(revision) is not int or revision < 1:
                    raise AuthorityUnavailable("Growth selected write revision is not positive")
                expected = dict(task.identity[1][1])
                for key in task.growth_receipt_match:
                    if key in task.growth_receipt_members or expected[key] not in (0, revision):
                        raise AuthorityUnavailable("Growth selected write member changed its exact revision")
                    task.growth_receipt_members[key] = revision
        return
    column._emit_v3(event)
