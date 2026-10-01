"""Actual signed historical identities for a frozen package backup observation.

The first phase authenticates independently owned journal/Core originals before
Graph SQL. The second phase only reads the caller's actual Graph snapshot. The
installed backup-source producer owns the writer locks, drain, before/after
heads and all-four-store row/DDL roots. No package registry is enumerated here.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from weakref import WeakValueDictionary

from .contract import AuthorityUnavailable
from .d12_package_files_v2 import _sha
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

SCHEMA = "d12.historical-manifest-inventory.v1"
KINDS = frozenset(("numeric_claim", "numeric_terminal", "root_claim", "root_terminal",
    "numeric_accounting", "root_accounting", "authored_root", "authored_topology", "semantic", "role_clock"))
_ISSUED = WeakValueDictionary()


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _AuthenticatedPackageHistoryInputsV1:
    numeric_service: object
    root_service: object
    model_store: object
    execution_head: object
    journal_originals: tuple
    model_originals: tuple


def _require_locks(numeric, root, model):
    from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
    from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
    from .v2_model_egress_store import AuthorityV2ModelEgressStore
    if (type(numeric) is not AuthorityD04NumericServiceV3 or type(root) is not AuthorityD04RootExecutionServiceV3
            or type(model) is not AuthorityV2ModelEgressStore
            or any(getattr(root.bridge, name) is not getattr(numeric.bridge, name) for name in ("core", "journal", "deletion", "fences"))
            or root.namespace != numeric.namespace or root.installation_id != numeric.installation_id
            or root.graph_path != numeric.graph_path or model._db is not numeric.bridge.core._db
            or model._lock is not numeric.bridge.core._lock):
        raise AuthorityUnavailable("actual common package-history authorities required")
    bridge = numeric.bridge
    if any(not lock._is_owned() for lock in (bridge.deletion._lock, bridge.journal._lock, bridge.core._lock)):
        raise AuthorityUnavailable("package history requires the actual ordered writer locks")
    return bridge


def read_authenticated_package_history_inputs_v1(numeric_service, root_service, model_store):
    bridge = _require_locks(numeric_service, root_service, model_store)
    if bridge.core._db.in_transaction:
        raise AuthorityUnavailable("authenticate historical originals before Graph/Core SQL")
    from .d04_numeric_journal_v3 import ENTRY_PREFIX, decode_numeric_row_v3
    from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3, decode_root_execution_row_v3
    from .v2_fence_store import AuthorityV2FenceStore
    journal_head, rows = bridge.journal._scan_locked()
    originals, claims = [], {}
    for row in rows:
        if row[4].startswith(ENTRY_PREFIX):
            kind, service = "numeric", numeric_service
            binding, claim, measurement = decode_numeric_row_v3(bridge.journal, row)
        elif row[4].startswith(ROOT_ENTRY_PREFIX_V3):
            kind, service = "root", root_service
            binding, claim, measurement = decode_root_execution_row_v3(bridge.journal, row)
        else:
            continue  # Other kinds are covered by actual namespace reconciliation.
        service._binding_scope(binding)
        service._verify_claim(binding, claim)
        key = (kind, binding.execution_id)
        if measurement is None:
            if key in claims:
                raise AuthorityUnavailable("duplicate historical execution claim")
            claims[key] = claim
        elif claims.get(key) != claim:
            raise AuthorityUnavailable("historical terminal lacks its exact earlier claim")
        originals.append((kind, binding, claim, measurement,
            canonical_digest((*row[:4], hashlib.sha256(row[4]).hexdigest(), *row[5:]))))
    # A consumed C09 call is permanently ineligible for the ordinary reader.
    # Qualify the current control/applied proof before entering Core SQL, then
    # use only its fixed passive accounting join inside the short transaction.
    from .c09_model_budget_original_v1 import (
        read_model_audit_metadata_v1, read_authenticated_model_budget_original_in_tx_v1,
    )
    present = bridge.core._db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone()
    consumed = set() if present is None else {r[0] for r in bridge.core._db.execute(
        "SELECT item_id FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind='model_call'", (bridge.namespace,))}
    context = None
    if consumed:
        reader = getattr(bridge.core, "_c09_storage_reader_v1", None)
        if reader is None:
            raise AuthorityUnavailable("consumed historical model requires its actual current C09 reader")
        context = reader.read_verified_current_storage_v1()
        context.require_current("accounting")
    models = []
    with model_store._tx() as db:
        for (call_id,) in db.execute("SELECT call_id FROM authority_model_egress_v1 WHERE namespace=? ORDER BY call_id", (bridge.namespace,)):
            if call_id in consumed:
                recovery = read_model_audit_metadata_v1(db, call_id)
                retained = read_authenticated_model_budget_original_in_tx_v1(db,
                    namespace=bridge.namespace, call_id=call_id, context=context)
                if recovery is None or retained is None or not recovery.content_erased:
                    raise AuthorityUnavailable("consumed model lacks actual passive accounting originals")
                intent = recovery.intent
                if (intent.namespace != bridge.namespace or retained.installation_id != numeric_service.installation_id
                        or retained.call_id != call_id or retained.model_operation_id != intent.operation_id
                        or retained.job_id != intent.job_id or retained.request_digest != intent.request_digest
                        or retained.provider_id != intent.provider_id or retained.provider_state != recovery.state):
                    raise AuthorityUnavailable("consumed model passive identity and signed recovery frame differ")
                models.append((recovery, None, None, None, retained.original_digest, retained))
                continue
            recovery = model_store._read(db, call_id)
            if recovery is None or recovery.intent.namespace != bridge.namespace:
                raise AuthorityUnavailable("actual historical model identity differs")
            intent = recovery.intent
            admission = receipt = observation = None
            if recovery.state != "prepared":
                admission, report, receipt = model_store.read_admission_locked(db, intent)
                if receipt is not None and report != receipt.report_digest:
                    raise AuthorityUnavailable("historical designated model terminal differs")
                if recovery.state in {"observed", "unknown"} and not recovery.content_erased:
                    observation = model_store._read_observation_locked(db, intent)
            fence = AuthorityV2FenceStore._row(db, intent.operation_id)
            if fence is None or not model_store.is_fence_bound_locked(db, intent):
                raise AuthorityUnavailable("historical model lacks its original actual bound fence")
            models.append((recovery, admission, receipt, observation, canonical_digest(tuple(fence)), None))
    if not consumed.issubset({row[0].intent.call_id for row in models}):
        raise AuthorityUnavailable("consumed model history lacks retained passive metadata")
    if context is not None:
        context.require_current("accounting")
    result = _AuthenticatedPackageHistoryInputsV1(numeric_service, root_service, model_store,
        journal_head, tuple(originals), tuple(models))
    _ISSUED[id(result)] = result
    return result


def decode_historical_manifest_inventory_v1(raw):
    names = {"schema", "namespace", "authority_namespace", "installation_id", "execution_head",
        "manifest_groups", "unversioned_d13_groups", "original_count", "inventory_digest"}
    if type(raw) is not dict or set(raw) != names or raw["schema"] != SCHEMA:
        raise AuthorityUnavailable("closed historical manifest inventory required")
    NamespaceId(**raw["namespace"])
    from .contract import JournalHead
    JournalHead(**raw["execution_head"])
    if (type(raw["original_count"]) is not int or raw["original_count"] < 0
            or type(raw["manifest_groups"]) is not list or len(raw["manifest_groups"]) > 1024
            or type(raw["unversioned_d13_groups"]) is not list or len(raw["unversioned_d13_groups"]) > 256):
        raise AuthorityUnavailable("bounded actual historical inventory required")
    seen = set(); count = 0
    for row in raw["manifest_groups"]:
        if (type(row) is not dict or set(row) != {"manifest_sha256", "kind", "count", "evidence_root"}
                or not _sha(row["manifest_sha256"]) or row["kind"] not in KINDS
                or type(row["count"]) is not int or row["count"] < 1 or not _sha(row["evidence_root"])
                or (row["manifest_sha256"], row["kind"]) in seen):
            raise AuthorityUnavailable("historical manifest evidence group differs")
        seen.add((row["manifest_sha256"], row["kind"])); count += row["count"]
    if [(r["manifest_sha256"], r["kind"]) for r in raw["manifest_groups"]] != sorted(seen):
        raise AuthorityUnavailable("historical manifest groups are unordered")
    d13_seen = set()
    for row in raw["unversioned_d13_groups"]:
        expected = {"provider_config_digest", "template_version", "count", "evidence_root"}
        key = (row.get("provider_config_digest"), row.get("template_version")) if type(row) is dict else None
        if (type(row) is not dict or set(row) != expected or not _sha(row["provider_config_digest"])
                or type(row["template_version"]) is not str or not row["template_version"]
                or type(row["count"]) is not int or row["count"] < 1 or not _sha(row["evidence_root"])
                or key in d13_seen):
            raise AuthorityUnavailable("D13 actual unversioned evidence differs")
        d13_seen.add(key); count += row["count"]
    if [(r["provider_config_digest"], r["template_version"]) for r in raw["unversioned_d13_groups"]] != sorted(d13_seen):
        raise AuthorityUnavailable("D13 historical evidence is unordered")
    body = dict(raw); body.pop("inventory_digest")
    if count != raw["original_count"] or canonical_digest(body) != raw["inventory_digest"]:
        raise AuthorityUnavailable("historical inventory commitment/count differs")
    return raw


def collect_package_history_inventory_in_graph_v1(db, inputs, resource_issuer, budget_issuer, namespace, installation_id):
    if (type(inputs) is not _AuthenticatedPackageHistoryInputsV1 or _ISSUED.get(id(inputs)) is not inputs
            or type(db) is not sqlite3.Connection or not db.in_transaction or type(namespace) is not NamespaceId):
        raise AuthorityUnavailable("historical inventory needs actual authenticated inputs and Graph snapshot")
    bridge = _require_locks(inputs.numeric_service, inputs.root_service, inputs.model_store)
    if (bridge.core._db.in_transaction or namespace != inputs.numeric_service.namespace
            or installation_id != inputs.numeric_service.installation_id
            or Path(db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True) != inputs.numeric_service.graph_path
            or resource_issuer is not inputs.numeric_service.resource_issuer or budget_issuer is not inputs.numeric_service.budget_issuer):
        raise AuthorityUnavailable("historical inventory actual Graph/composition differs")
    from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
    from ..runtime.d04_numeric_accounting_prepared_v3 import read_numeric_accounting_prepared_v3
    from ..runtime.d04_root_accounting_prepared_v3 import read_root_accounting_prepared_v3
    from ..runtime.c09_d04_originals_v3 import validate_d04_original_payload_v3
    groups, d13_groups = {}, {}
    def add(manifest, kind, value):
        if not _sha(manifest) or kind not in KINDS:
            raise AuthorityUnavailable("actual original has no supported historical manifest")
        groups.setdefault((manifest, kind), []).append(canonical_digest(value))
    journal_bindings = {}
    for kind, binding, claim, measurement, row_digest in inputs.journal_originals:
        journal_bindings[(kind, binding.operation_id)] = binding
        add(binding.native_manifest_sha256, kind + ("_claim" if measurement is None else "_terminal"),
            (binding.digest, claim.signature, row_digest))
        if measurement is not None:
            actual = read_d04_original_v3(db, namespace, kind + "_measurement", binding.operation_id)
            if actual is None or actual[0] != json.loads(canonical_serialize(asdict(measurement))):
                raise AuthorityUnavailable("historical independent CPU measurement and Graph differ")
    for kind, reference, encoded, stored_digest in db.execute(
            "SELECT kind,original_ref,payload_json,payload_digest FROM graph_d04_originals_v3 WHERE bot=? AND persona=? ORDER BY kind,original_ref",
            namespace.as_tuple):
        raw = json.loads(encoded)
        if canonical_serialize(raw) != encoded or canonical_digest(raw) != stored_digest:
            raise AuthorityUnavailable("historical D04 original bytes differ")
        validate_d04_original_payload_v3(kind, raw)
        if kind == "numeric_accounting_prepared":
            retained = read_numeric_accounting_prepared_v3(db, namespace, reference, issuer=resource_issuer)
            binding = retained.binding
            actual = journal_bindings.get(("numeric", reference))
            if actual is not None and actual != binding:
                raise AuthorityUnavailable("historical numeric signed accounting differs")
            add(binding.native_manifest_sha256, "numeric_accounting", (reference, retained.digest, binding.digest))
        elif kind == "root_accounting_prepared":
            from ..runtime.d04_root_accounting_prepared_v3 import decode_root_accounting_prepared_payload_v3
            retained = read_root_accounting_prepared_v3(db, namespace, reference,
                resource_issuer=resource_issuer, budget_issuer=budget_issuer)
            binding = decode_root_accounting_prepared_payload_v3(retained[0])[0]
            actual = journal_bindings.get(("root", reference))
            if actual is not None and actual != binding:
                raise AuthorityUnavailable("historical root signed accounting differs")
            add(binding.native_manifest_sha256, "root_accounting", (reference, retained[1], binding.digest))
    from ..runtime.d04_semantic_installation_original_v3 import _read_signed, TABLE as SEMANTIC_TABLE, SIGN_KIND as SEMANTIC_SIGN
    from ..runtime.d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE, SIGN_KIND as CLOCK_SIGN
    for table, sign, kind, schema in ((SEMANTIC_TABLE, SEMANTIC_SIGN, "semantic", "d04.owner-semantic-installation-original.v3"),
            (CLOCK_TABLE, CLOCK_SIGN, "role_clock", "d11.owner-role-clock-original.v1")):
        for (operation,) in db.execute(f"SELECT operation_id FROM {table} WHERE bot=? AND persona=? ORDER BY revision", namespace.as_tuple):
            raw, commitment = _read_signed(db, budget_issuer, table, sign, namespace, operation_id=operation)
            if raw.get("schema") != schema:
                raise AuthorityUnavailable("historical signed configuration schema differs")
            add(raw["manifest_sha256"], kind, (operation, commitment))
    from ..runtime.d04_root_original_store_v3 import read_d04_root_original_v3
    from ..runtime.d11_d04_root_freeze_v3 import read_d11_root_freeze_v3
    roots = {}
    for (operation,) in db.execute("SELECT operation_id FROM graph_d04_root_originals_v3 WHERE bot=? AND persona=? ORDER BY operation_id", namespace.as_tuple):
        root = read_d04_root_original_v3(db, namespace=namespace, operation_id=operation)
        freeze = read_d11_root_freeze_v3(db, budget_issuer, namespace=namespace, operation_id=operation)
        if freeze is None or freeze.original_digest != root.signed_freeze_digest:
            raise AuthorityUnavailable("historical authored root lacks actual signed freeze")
        proof = json.loads(root.initial_box_json)
        manifest = proof["production_binding"]["manifest_sha256"]
        add(manifest, "authored_root", (root.original_digest, freeze.original_digest))
        roots[operation] = root
    from ..runtime.d04_owner_initialization_v3 import TOPOLOGY_TABLE, TOPOLOGY_SCHEMA, TOPOLOGY_ACTIVITY, _topology_owner_evidence
    from ..domains.d04.authored_topology_v3 import decode_authored_root_topology_v3
    for operation, encoded, commitment in db.execute(f"SELECT operation_id,original_json,original_digest FROM {TOPOLOGY_TABLE} WHERE bot=? AND persona=? ORDER BY operation_id", namespace.as_tuple):
        raw = json.loads(encoded)
        if canonical_serialize(raw) != encoded or canonical_digest(raw) != commitment or raw.get("schema") != TOPOLOGY_SCHEMA:
            raise AuthorityUnavailable("historical topology original differs")
        marker = decode_authored_root_topology_v3(raw["marker_value"])
        root = roots.get(marker.root_operation_id)
        if root is None or root.original_digest != marker.root_original_digest or root.signed_freeze_digest != marker.root_freeze_digest:
            raise AuthorityUnavailable("historical topology signed root differs")
        event = db.execute("SELECT digest,revisions,epoch_revision,reads,epoch_reads,invalidated FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?", (*namespace.as_tuple, TOPOLOGY_ACTIVITY, operation)).fetchone()
        if event is None or event[0] != raw["event_digest"]:
            raise AuthorityUnavailable("historical topology event absent")
        _topology_owner_evidence(db, namespace, raw, marker, raw["write_rows"], event)
        add(marker.manifest_digest, "authored_topology", (operation, commitment, root.original_digest))
    _collect_d13(db, inputs, resource_issuer, budget_issuer, namespace, installation_id, d13_groups)
    value = dict(schema=SCHEMA, namespace=asdict(namespace), authority_namespace=bridge.namespace,
        installation_id=installation_id, execution_head=asdict(inputs.execution_head),
        manifest_groups=[dict(manifest_sha256=manifest, kind=kind, count=len(rows), evidence_root=canonical_digest(tuple(sorted(rows))))
            for (manifest, kind), rows in sorted(groups.items())],
        unversioned_d13_groups=[dict(provider_config_digest=config, template_version=version, count=len(rows), evidence_root=canonical_digest(tuple(sorted(rows))))
            for (config, version), rows in sorted(d13_groups.items())],
        original_count=sum(map(len, groups.values())) + sum(map(len, d13_groups.values())))
    value["inventory_digest"] = canonical_digest(value)
    return decode_historical_manifest_inventory_v1(value)


def _collect_d13(db, inputs, resource, budget, namespace, installation_id, groups):
    from ..runtime.d13_paid_intent_original_v1 import load_d13_paid_intent_original_v1, read_d13_paid_call_original_v1
    models = {row[0].intent.call_id: row for row in inputs.model_originals}
    for (job_ref,) in db.execute("SELECT job_ref FROM graph_d13_paid_intent_originals_v1 WHERE bot=? AND persona=? ORDER BY job_ref", namespace.as_tuple):
        original, frozen = load_d13_paid_intent_original_v1(db, namespace, job_ref)
        quote = resource.original_signed_quote(db, original.quote_id, original.quote_version)
        grant, signature = budget.signed_budget_grant_at_version(db, quote.parent_budget_lease_ref, original.grant_version)
        if (canonical_digest(quote) != original.quote_digest or canonical_digest(grant) != original.grant_digest
                or grant.grant_id != original.grant_id or frozen.installation.installation_id != installation_id
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple):
            raise AuthorityUnavailable("historical D13 actual signed budget/provider differs")
        reservation = db.execute("SELECT digest,lease_id FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*namespace.as_tuple, original.budget_operation_id)).fetchone()
        if reservation != (original.budget_reservation_digest, quote.parent_budget_lease_ref):
            raise AuthorityUnavailable("historical D13 reservation original differs")
        call = read_d13_paid_call_original_v1(db, namespace, job_ref)
        actual = models.get(original.binding.call_id)
        if call is not None:
            recorded, request = call
            if recorded.intent_original_digest != original.original_digest or recorded.binding_digest != original.binding.binding_digest:
                raise AuthorityUnavailable("historical D13 call and input original differ")
            if actual is not None:
                intent = actual[0].intent
                if (intent.request_digest != request.digest or intent.job_id != job_ref
                        or intent.provider_config_digest != frozen.installation.provider_config_digest
                        or intent.budget_reservation_digest != original.budget_reservation_digest):
                    raise AuthorityUnavailable("historical D13 independent model admission differs")
        elif actual is not None:
            raise AuthorityUnavailable("historical D13 model has no actual Graph call original")
        key = (frozen.installation.provider_config_digest, frozen.template_version)
        groups.setdefault(key, []).append(canonical_digest((original.original_digest, signature,
            None if call is None else call[0].original_digest,
            None if actual is None else (actual[0], actual[1], actual[2], actual[4], actual[5]))))
