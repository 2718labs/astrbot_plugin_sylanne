"""Pure D03 structure for a qualified host message arrival."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from typing import TYPE_CHECKING

from ...graph_types import (
    AtomKey, CurrentSceneProof, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite,
    IngressIdentityReceipt, Owner,
)
from ...host.ingress import HostIngressEnvelope
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime.first_ingress_v2 import scene_ref_for_conversation
from ...runtime_contracts import (
    CommandEnvelope, DependencySet, DomainProposal, SourceQualification,
    canonical_digest,
)
from .context import AccountBinding, ContextProvider, EntityAnchor, WorldEvent

if TYPE_CHECKING:
    from ...host.current_scene import CurrentHostScene


@dataclass(frozen=True)
class MessageArrivalCandidate:
    """A proposal with its source guards; it is neither a graph write nor authority."""

    sender_anchor: EntityAnchor
    sender_key: AtomKey
    account_binding: AccountBinding
    account_binding_key: AtomKey
    event: WorldEvent
    event_key: AtomKey
    source_version: GraphVersion
    access_version: GraphVersion


def build_message_arrival_candidate(
    ingress: HostIngressEnvelope,
    current_scene: CurrentHostScene,
    source: SourceRecord,
    access: dict,
    qualification: SourceQualification,
    *,
    source_version: GraphVersion,
    access_version: GraphVersion,
) -> MessageArrivalCandidate:
    """Describe the host-observed receipt, without endorsing the message text.

    The caller obtains ``current_scene`` through the host verifier and both
    graph versions and access through a current D06 read. A committing graph
    transaction must check those guards and the source's current access again.
    """
    if not isinstance(ingress, HostIngressEnvelope):
        raise TypeError("host ingress is required")
    if not isinstance(source, SourceRecord) or not isinstance(qualification, SourceQualification):
        raise TypeError("qualified D06 source is required")
    validate_access(access)
    namespace = ingress.namespace
    expected_scene = scene_ref_for_conversation(
        namespace, ingress.platform_ref, ingress.conversation_ref,
    )
    if (
        current_scene.namespace != namespace
        or current_scene.platform_ref != ingress.platform_ref
        or current_scene.conversation_ref != ingress.conversation_ref
        or current_scene.visibility != ingress.visibility
        or current_scene.scene_ref != expected_scene
    ):
        raise ValueError("current host scene differs from this ingress")
    source_atom = source_key(*namespace.as_tuple, ingress.lineage.source_ref)
    access_atom = access_key(*namespace.as_tuple, ingress.lineage.source_ref)
    if (
        source_version.key != source_atom or source_version.revision < 1
        or access_version.key != access_atom or access_version.revision < 1
        or access["source_id"] != source.source_id
        or access["status"] != "active"
        or ingress.conversation_ref not in access["audiences"]
        or "context" not in access["purposes"]
        or qualification.source_refs != (source_atom.token,)
        or qualification.source_family != "reported"
        or qualification.content_reality != "external_report"
        or qualification.evidence_eligibility != "qualified"
        or qualification.occurred_at != ingress.occurred_at
        # v2 freezes learned_at from the paired Authority clock. The host
        # envelope's receive time is only an untrusted input candidate.
        or qualification.learned_at != source.recorded_at
        or source.source_id != ingress.lineage.source_ref
        or source.text != ingress.text
        or source.speaker_id != ingress.sender_ref
        or source.source_kind != "reported"
        or source.assertion_status != "reported"
        or source.occurred_at != ingress.occurred_at
        or source.provenance_root != ingress.lineage.provenance_family
        or source.audiences != (ingress.conversation_ref,)
        or "context" not in source.purposes
    ):
        raise ValueError("current qualified source differs from host message")

    account_identity = {
        "namespace": namespace.as_tuple,
        "platform_ref": ingress.platform_ref,
        "sender_ref": ingress.sender_ref,
    }
    sender_id = "entity:account-v1:" + canonical_digest(account_identity)
    account_id = "account:v1:" + canonical_digest(account_identity)
    event_id = "world:message-arrival-v1:" + canonical_digest({
        "namespace": namespace.as_tuple,
        "platform_ref": ingress.platform_ref,
        "conversation_ref": ingress.conversation_ref,
        "message_id": ingress.message_id,
        "source_id": source.source_id,
    })
    sender = EntityAnchor(
        sender_id, "account", f"persona:{namespace.persona_id}",
        (source_atom.token,), "active",
    )
    event = WorldEvent(
        event_id, "message_received", ((sender_id, "sender_account"),),
        source.recorded_at, source.recorded_at, source.recorded_at,
        expected_scene, (source_atom.token,), "host_observed",
    )
    event_key = AtomKey(
        Owner("event", *namespace.as_tuple, event_id), "d03.world_event", "current",
    )
    account_binding = AccountBinding(
        account_id, ingress.platform_ref, ingress.sender_ref, sender_id,
        event_key.token, source.recorded_at, None,
    )
    return MessageArrivalCandidate(
        sender,
        AtomKey(Owner("persona", *namespace.as_tuple), "d03.entity_anchor", sender_id),
        account_binding,
        AtomKey(Owner("persona", *namespace.as_tuple), "d03.account_binding", account_id),
        event,
        event_key,
        source_version, access_version,
    )


def build_message_arrival_proposal(
    envelope: CommandEnvelope,
    candidate: MessageArrivalCandidate,
    *,
    sender_atom: GraphAtom | None,
    binding_atom: GraphAtom | None,
) -> DomainProposal:
    """Compile guarded D03 writes; the coordinator alone can adopt them.

    ``sender_atom`` and ``binding_atom`` are current graph reads, or None
    when their keys were absent. The caller carries both revisions in the
    envelope and includes the namespace query closure.
    """
    if type(envelope) is not CommandEnvelope or type(candidate) is not MessageArrivalCandidate:
        raise TypeError("typed command and message arrival candidate are required")
    namespace = envelope.authority.namespace
    authority = envelope.authority
    source, access = candidate.source_version, candidate.access_version
    sender_key, binding_key, event_key = (
        candidate.sender_key, candidate.account_binding_key, candidate.event_key,
    )
    sender = candidate.sender_anchor
    binding = candidate.account_binding
    event = candidate.event
    if (
        authority.issuer_domain != "d11" or authority.purpose != "context"
        or not {"persona", "event"}.issubset(authority.owner_scope)
        or len(authority.audience) != 1
        or any(key.owner.bot != namespace.bot_id or key.owner.persona != namespace.persona_id
               for key in (source.key, access.key, sender_key, binding_key, event_key))
        or source.key != source_key(*namespace.as_tuple, source.key.owner.subject or "")
        or access.key != access_key(*namespace.as_tuple, source.key.owner.subject or "")
        or sender_key != AtomKey(Owner("persona", *namespace.as_tuple),
                                 "d03.entity_anchor", sender.entity_id)
        or event_key != AtomKey(Owner("event", *namespace.as_tuple, event.event_id),
                                "d03.world_event", "current")
        or binding_key != AtomKey(Owner("persona", *namespace.as_tuple),
                                  "d03.account_binding", binding.account_id)
        or sender.kind != "account" or sender.owner_scope != f"persona:{namespace.persona_id}"
        or binding.entity_id != sender.entity_id
        or binding.verification_ref != event_key.token
        or binding.valid_from != event.learned_at or binding.valid_until is not None
        or event.kind != "message_received" or event.reality != "host_observed"
        or event.source_refs != (source.key.token,)
        or event.participant_roles != ((sender.entity_id, "sender_account"),)
        or event.learned_at != envelope.source_qualification.learned_at
        or envelope.source_qualification.source_refs != (source.key.token,)
        or envelope.source_qualification.source_family != "reported"
        or envelope.source_qualification.content_reality != "external_report"
        or envelope.source_qualification.evidence_eligibility != "qualified"
        or envelope.input_refs != (source.key.token,)
    ):
        raise ValueError("arrival command differs from qualified source and host account")
    reads = {version.key: version.revision for version in envelope.version_guard.read_versions}
    if reads.get(source.key) != source.revision or reads.get(access.key) != access.revision:
        raise ValueError("arrival command lacks current source and access guards")
    if (reads.get(event_key) != 0
            or not any(query.namespace == namespace and query.scope_ref == "all"
                       for query in envelope.version_guard.query_epochs)):
        raise ValueError("arrival event needs a revision-0 guard and namespace query")
    sender_revision = reads.get(sender_key)
    if sender_atom is None:
        if sender_revision != 0:
            raise ValueError("new sender anchor needs a revision-0 guard")
    else:
        if (type(sender_atom) is not GraphAtom or sender_atom.key != sender_key
                or not sender_atom.valid or sender_atom.revision < 1
                or sender_revision != sender_atom.revision):
            raise ValueError("existing sender anchor lacks a matching current guard")
        prior = EntityAnchor(**{
            **sender_atom.value,
            "creation_evidence_refs": tuple(sender_atom.value.get("creation_evidence_refs", ())),
        })
        if (prior.entity_id != sender.entity_id or prior.kind != "account"
                or prior.owner_scope != sender.owner_scope or prior.status != "active"
                or any(AtomKey.from_token(ref).type_name != "memory.source"
                       or AtomKey.from_token(ref).owner.bot != namespace.bot_id
                       or AtomKey.from_token(ref).owner.persona != namespace.persona_id
                       for ref in prior.creation_evidence_refs)):
            raise ValueError("existing sender anchor is not a compatible account")
    binding_revision = reads.get(binding_key)
    if binding_atom is None:
        if binding_revision != 0:
            raise ValueError("new account binding needs a revision-0 guard")
    else:
        if (type(binding_atom) is not GraphAtom or binding_atom.key != binding_key
                or not binding_atom.valid or binding_atom.revision < 1
                or binding_revision != binding_atom.revision):
            raise ValueError("existing account binding lacks a matching current guard")
        prior_binding = AccountBinding(**binding_atom.value)
        try:
            prior_event = AtomKey.from_token(prior_binding.verification_ref)
        except (TypeError, ValueError) as exc:
            raise ValueError("existing account binding has invalid event evidence") from exc
        if (prior_binding.account_id != binding.account_id
                or prior_binding.platform_namespace != binding.platform_namespace
                or prior_binding.platform_identifier != binding.platform_identifier
                or prior_binding.entity_id != sender.entity_id
                or prior_binding.valid_until is not None
                or prior_event.type_name != "d03.world_event"
                or prior_event.owner.kind != "event"
                or prior_event.owner.bot != namespace.bot_id
                or prior_event.owner.persona != namespace.persona_id
                or prior_event.name != "current"
                or reads.get(prior_event) is None or reads[prior_event] < 1):
            raise ValueError("existing account binding is not a compatible account")
    dependencies = (source, access, GraphVersion(sender_key, sender_revision))
    if binding_atom is not None:
        dependencies += (GraphVersion(binding_key, binding_revision),
                         GraphVersion(prior_event, reads[prior_event]))
    else:
        # The new binding points to the event written in this bundle.  Classify
        # that absent-key dependency just like every GraphWrite edge.
        dependencies += (GraphVersion(event_key, 0),)
    writes = []
    if sender_atom is None:
        sender_value = asdict(sender)
        sender_value["creation_evidence_refs"] = list(sender.creation_evidence_refs)
        writes.append(GraphWrite(sender_key, sender_value, (source.key, access.key)))
    event_value = asdict(event)
    event_value["participant_roles"] = [list(role) for role in event.participant_roles]
    event_value["source_refs"] = list(event.source_refs)
    event_dependencies = (source.key, access.key, sender_key)
    if binding_atom is not None:
        event_dependencies += (binding_key, prior_event)
    writes.append(GraphWrite(event_key, event_value, event_dependencies))
    if binding_atom is None:
        writes.append(GraphWrite(binding_key, asdict(binding),
                                 (source.key, access.key, sender_key, event_key)))
    return DomainProposal(
        "d03", "d03.proposal.v1", ContextProvider().descriptor.request_schema_hash,
        envelope, tuple(writes), DependencySet(current_invalidation=dependencies), (), (),
    )


def validate_message_arrival_snapshot(
    proposal: DomainProposal, snapshot: GraphSnapshot,
) -> None:
    """Recheck arrival semantics against the coordinator's locked read set."""
    if type(snapshot) is not GraphSnapshot:
        raise ValueError("message arrival needs a current graph snapshot")
    events = tuple(write for write in proposal.typed_writes
                   if write.key.type_name == "d03.world_event"
                   and write.value.get("kind") == "message_received")
    if len(events) != 1 or len(proposal.typed_writes) not in (1, 2, 3):
        raise ValueError("message arrival must contain one received event")
    event_write = events[0]
    event = WorldEvent(**{
        **event_write.value,
        "participant_roles": tuple(tuple(pair) for pair in event_write.value["participant_roles"]),
        "source_refs": tuple(event_write.value["source_refs"]),
    })
    namespace = proposal.envelope.authority.namespace
    if len(event.source_refs) != 1 or len(event.participant_roles) != 1:
        raise ValueError("message arrival needs one source and sender account")
    source = AtomKey.from_token(event.source_refs[0])
    access = access_key(*namespace.as_tuple, source.owner.subject or "")
    sender_id, role = event.participant_roles[0]
    sender = AtomKey(Owner("persona", *namespace.as_tuple), "d03.entity_anchor", sender_id)
    binding_id = "account:v1:" + sender_id.removeprefix("entity:account-v1:")
    binding_key = AtomKey(Owner("persona", *namespace.as_tuple),
                          "d03.account_binding", binding_id)
    event_prior = snapshot.get(event_write.key)
    source_atom = snapshot.get(source)
    access_atom = snapshot.get(access)
    sender_atom = snapshot.get(sender)
    binding_atom = snapshot.get(binding_key)
    if (source != source_key(*namespace.as_tuple, source.owner.subject or "")
            or event_write.key != AtomKey(Owner("event", *namespace.as_tuple, event.event_id),
                                          "d03.world_event", "current")
            or event_prior is None or event_prior.revision != 0
            or source_atom is None or not source_atom.valid or source_atom.revision < 1
            or access_atom is None or not access_atom.valid or access_atom.revision < 1
            or sender_atom is None or binding_atom is None
            or role != "sender_account"
            or event.reality != "host_observed"
            or event.occurred_from != event.learned_at
            or event.occurred_until != event.learned_at):
        raise ValueError("message arrival snapshot is incomplete or inconsistent")
    record = SourceRecord.from_dict(source_atom.value)
    validate_access(access_atom.value)
    qualification = proposal.envelope.source_qualification
    if (qualification.source_refs != (source.token,)
            or qualification.source_family != "reported"
            or qualification.content_reality != "external_report"
            or qualification.evidence_eligibility != "qualified"
            or qualification.occurred_at != record.occurred_at
            or qualification.learned_at != record.recorded_at
            or proposal.envelope.input_refs != (source.token,)
            or record.source_id != source.owner.subject or record.source_kind != "reported"
            or record.assertion_status != "reported"
            or record.recorded_at != event.learned_at
            or not set(proposal.envelope.authority.audience).issubset(record.audiences)
            or "context" not in record.purposes
            or access_atom.value["source_id"] != record.source_id
            or access_atom.value["status"] != "active"
            or not set(proposal.envelope.authority.audience).issubset(access_atom.value["audiences"])
            or "context" not in access_atom.value["purposes"]):
        raise ValueError("message arrival source or access lost current eligibility")
    anchor_writes = tuple(write for write in proposal.typed_writes
                          if write.key.type_name == "d03.entity_anchor")
    binding_writes = tuple(write for write in proposal.typed_writes
                           if write.key.type_name == "d03.account_binding")
    expected_writes = {event_write.key}
    if sender_atom.revision == 0:
        expected_writes.add(sender)
    if binding_atom.revision == 0:
        expected_writes.add(binding_key)
    if (len(proposal.typed_writes) != len(expected_writes)
            or {write.key for write in proposal.typed_writes} != expected_writes):
        raise ValueError("message arrival write shape differs from sender state")
    if sender_atom.revision == 0:
        if len(anchor_writes) != 1 or anchor_writes[0].key != sender:
            raise ValueError("new sender anchor write is missing")
        anchor_value = anchor_writes[0].value
        if (anchor_value.get("creation_evidence_refs") != [source.token]
                or set(anchor_writes[0].dependencies) != {source, access}):
            raise ValueError("new sender anchor has invalid source dependencies")
    else:
        if not sender_atom.valid or anchor_writes:
            raise ValueError("existing sender anchor cannot be overwritten")
        anchor_value = sender_atom.value
    anchor = EntityAnchor(**{
        **anchor_value,
        "creation_evidence_refs": tuple(anchor_value["creation_evidence_refs"]),
    })
    if (anchor.entity_id != sender_id or anchor.kind != "account"
            or anchor.owner_scope != f"persona:{namespace.persona_id}"
            or anchor.status != "active"):
        raise ValueError("sender anchor differs from current account identity")
    if binding_atom.revision == 0:
        if len(binding_writes) != 1 or binding_writes[0].key != binding_key:
            raise ValueError("new account binding write is missing")
        binding_value = binding_writes[0].value
        if set(binding_writes[0].dependencies) != {source, access, sender, event_write.key}:
            raise ValueError("new account binding lost its event evidence dependency")
    else:
        if not binding_atom.valid or binding_writes:
            raise ValueError("existing account binding cannot be overwritten")
        binding_value = binding_atom.value
    binding = AccountBinding(**binding_value)
    if (binding.account_id != binding_id
            or binding.entity_id != sender_id
            or binding.valid_until is not None):
        raise ValueError("account binding differs from current account identity")
    try:
        verification_key = AtomKey.from_token(binding.verification_ref)
    except (TypeError, ValueError) as exc:
        raise ValueError("account binding lacks trusted event evidence") from exc
    if binding_atom.revision == 0:
        if (verification_key != event_write.key
                or binding.valid_from != event.learned_at):
            raise ValueError("new account binding must cite this arrival event")
    else:
        verification_atom = snapshot.get(verification_key)
        if (verification_key.type_name != "d03.world_event"
                or verification_key.owner.kind != "event"
                or verification_key.owner.bot != namespace.bot_id
                or verification_key.owner.persona != namespace.persona_id
                or verification_key.name != "current"
                or verification_atom is None or not verification_atom.valid
                or verification_atom.revision < 1
                or verification_atom.value.get("kind") != "message_received"
                or verification_atom.value.get("reality") != "host_observed"
                or verification_atom.value.get("participant_roles")
                != [[sender_id, "sender_account"]]
                or verification_atom.value.get("learned_at") != binding.valid_from):
            raise ValueError("existing account binding lacks current trusted arrival evidence")
    expected_dependencies = {source, access, sender}
    expected_event_dependencies = {source, access, sender}
    if binding_atom.revision > 0:
        expected_dependencies.update((binding_key, verification_key))
        expected_event_dependencies.update((binding_key, verification_key))
    else:
        expected_dependencies.add(event_write.key)
    if (set(event_write.dependencies) != expected_event_dependencies
            or {ref.key for ref in proposal.dependencies.current_invalidation}
            != expected_dependencies):
        raise ValueError("message arrival lost source, access, sender, or binding dependencies")
    scene_ref, visibility = derive_trusted_message_arrival_identity(
        proposal, snapshot)
    trusted_identity = json.loads(snapshot.ingress_receipts[0].identity_json)
    if (binding.platform_namespace != trusted_identity["platform_ref"]
            or binding.platform_identifier != trusted_identity["sender_ref"]):
        raise ValueError("account binding differs from trusted host account")
    if (len(snapshot.scene_proofs) != 1
            or type(snapshot.scene_proofs[0]) is not CurrentSceneProof
            or len(snapshot.epochs) != 1):
        raise ValueError("trusted host scene evidence is unavailable for message arrival")
    proof = snapshot.scene_proofs[0]
    epoch = snapshot.epochs[0]
    if (epoch.bot != namespace.bot_id or epoch.persona != namespace.persona_id
            or proof.source_ref != source.owner.subject
            or proof.scene_ref != scene_ref or event.scene_ref != proof.scene_ref
            or proof.visibility != visibility
            or proof.learned_at != record.recorded_at
            or proof.graph_epoch != epoch.revision
            or type(proof.graph_incarnation) is not str
            or not proof.graph_incarnation
            or not proof.owner_grant_id or not proof.owner_authorization_head
            or proof.owner_authorization_revision < 1
            or type(proof.owner_revocation_epoch) is not int
            or proof.owner_revocation_epoch < 0
            or not proof.role_head_id or not proof.binding_id
            or proof.binding_version < 1
            or not proof.binding_receipt_operation_id
            or not 0 < proof.binding_receipt_graph_epoch <= proof.graph_epoch):
        raise ValueError("trusted host scene evidence differs from current arrival")


def derive_trusted_message_arrival_identity(
    proposal: DomainProposal, snapshot: GraphSnapshot,
) -> tuple[str, str]:
    """Rebuild D03 IDs from W01's committed receipt and current D06 source.

    This is one prerequisite, not scene admission. The caller still needs a
    same-snapshot current scene/Owner proof before adopting host_observed.
    """
    from ...contracts import canonical_json
    from ...graph_coordinator import (
        IngressHostFacts, IngressLineage, ingress_host_fingerprint,
    )
    from ...runtime.first_ingress_v2 import ingress_ids

    if (type(snapshot) is not GraphSnapshot
            or len(snapshot.ingress_receipts) != 1
            or type(snapshot.ingress_receipts[0]) is not IngressIdentityReceipt):
        raise ValueError("trusted host scene evidence is unavailable for message arrival")
    try:
        receipt = snapshot.ingress_receipts[0]
        identity = json.loads(receipt.identity_json)
        namespace = proposal.envelope.authority.namespace
        event_writes = [write for write in proposal.typed_writes
                        if write.key.type_name == "d03.world_event"
                        and write.value.get("kind") == "message_received"]
        if len(event_writes) != 1:
            raise ValueError("one arrival event is required")
        write = event_writes[0]
        source_refs = write.value["source_refs"]
        if type(source_refs) is not list or len(source_refs) != 1:
            raise ValueError("arrival source is required")
        source_key_current = AtomKey.from_token(source_refs[0])
        source_atom = snapshot.get(source_key_current)
        if source_atom is None or not source_atom.valid:
            raise ValueError("current source is unavailable")
        record = SourceRecord.from_dict(source_atom.value)
        if (type(identity) is not dict or set(identity) != {
                "schema", "namespace", "operation_id", "source_ref",
                "platform_ref", "conversation_ref", "sender_ref", "message_id",
                "visibility", "lineage"}
                or identity["schema"] != "sylanne3.ingress.identity.v1"
                or identity["namespace"] != list(namespace.as_tuple)
                or identity["source_ref"] != record.source_id
                or identity["operation_id"] != ingress_ids(record.source_id)[2]
                or canonical_json(identity) != receipt.identity_json
                or receipt.learned_at != record.recorded_at
                or type(receipt.bundle_digest) is not str
                or len(receipt.bundle_digest) != 64
                or any(ch not in "0123456789abcdef"
                       for ch in receipt.bundle_digest)):
            raise ValueError("receipt does not identify current source")
        lineage = IngressLineage(**identity["lineage"])
        host = IngressHostFacts(
            namespace, identity["platform_ref"], identity["conversation_ref"],
            identity["sender_ref"], identity["message_id"], record.text,
            record.occurred_at, record.recorded_at, identity["visibility"],
            lineage,
        )
        scene_ref = scene_ref_for_conversation(
            namespace, host.platform_ref, host.conversation_ref)
        sender_id = "entity:account-v1:" + canonical_digest({
            "namespace": namespace.as_tuple,
            "platform_ref": host.platform_ref,
            "sender_ref": host.sender_ref,
        })
        event_id = "world:message-arrival-v1:" + canonical_digest({
            "namespace": namespace.as_tuple,
            "platform_ref": host.platform_ref,
            "conversation_ref": host.conversation_ref,
            "message_id": host.message_id,
            "source_id": record.source_id,
        })
        if (ingress_host_fingerprint(host) != receipt.content_fingerprint
                or record.speaker_id != host.sender_ref
                or record.source_kind != lineage.source_kind
                or record.assertion_status != "reported"
                or record.provenance_root != lineage.provenance_family
                or record.audiences != (host.conversation_ref,)
                or "context" not in record.purposes
                or write.value["event_id"] != event_id
                or write.key != AtomKey(
                    Owner("event", *namespace.as_tuple, event_id),
                    "d03.world_event", "current")
                or write.value["scene_ref"] != scene_ref
                or write.value["participant_roles"]
                != [[sender_id, "sender_account"]]
                or write.value["learned_at"] != record.recorded_at):
            raise ValueError("arrival differs from committed host identity")
        return scene_ref, host.visibility
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise ValueError("trusted ingress identity does not match D03 arrival") from exc


__all__ = (
    "MessageArrivalCandidate", "build_message_arrival_candidate",
    "build_message_arrival_proposal",
)
