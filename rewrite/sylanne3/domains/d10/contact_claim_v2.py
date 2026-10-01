"""One finite proactive contact, with its approved quota window and lineage."""
from dataclasses import asdict, dataclass, replace

from . import ContactClaim, ContactPolicy, D10TypeSpec, _exact_fields, _finite
from ...graph_types import AtomKey, GraphWrite, Owner
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash


def contact_window_id_v2(policy: ContactPolicy) -> str:
    return "contact-window:" + canonical_digest((policy.namespace, policy.subject_ref,
        policy.channel, policy.category, policy.window_start, policy.window_end))


@dataclass(frozen=True)
class ContactClaimV2(ContactClaim):
    window_id: str
    window_start: float
    window_end: float
    approval_ref: str
    approval_digest: str

    def __post_init__(self):
        # Validate the common contact identity/status with the original closed
        # rules. Platform acceptance is a handoff for contact occupancy only.
        observations = tuple(tuple(row) for row in self.observations)
        mapped = tuple((effect, "handed_off" if result in {"accepted", "delivered"}
                        else result) for effect, result in observations)
        ContactClaim(self.contact_id, self.communication_action_id, self.subject_ref,
            self.channel, self.category, tuple(self.segment_effects), mapped,
            self.status, self.policy_id, self.policy_version)
        if (type(self.policy_version) is not int or self.policy_version < 1
                or _finite(self.window_start, "window_start") >= _finite(self.window_end, "window_end")
                or not self.window_id.startswith("contact-window:")
                or type(self.approval_ref) is not str or not self.approval_ref
                or type(self.approval_digest) is not str or len(self.approval_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.approval_digest)):
            raise ValueError("contact claim requires the exact approved quota window")
        object.__setattr__(self, "segment_effects", tuple(self.segment_effects))
        object.__setattr__(self, "observations", observations)

    def observe(self, effect_id, observation):
        if effect_id not in self.segment_effects or observation not in {
                "not_handed_off", "handed_off", "unknown", "accepted", "delivered"}:
            raise ValueError("contact observation must name an original finite segment")
        current = dict(self.observations)
        old = current.get(effect_id)
        if old == observation:
            return self
        if old is not None and (old, observation) not in {
                ("unknown", "accepted"), ("unknown", "delivered"),
                ("handed_off", "accepted"), ("handed_off", "delivered"),
                ("accepted", "delivered")}:
            raise ValueError("contact observation contradicts an existing external effect")
        current[effect_id] = observation
        values = set(current.values())
        status = ("pending_confirmation" if "unknown" in values else "handed_off"
                  if values & {"handed_off", "accepted", "delivered"} else "claimed")
        return replace(self, observations=tuple(sorted(current.items())), status=status)


def decode_contact_claim_v2(value):
    fields = frozenset(ContactClaimV2.__dataclass_fields__)
    data = _exact_fields(value, fields, "contact claim v2")
    return ContactClaimV2(**{**data, "segment_effects": tuple(data["segment_effects"]),
        "observations": tuple(tuple(row) for row in data["observations"])})


def contact_claim_key_v2(namespace: NamespaceId, contact_id: str):
    return AtomKey(Owner("persona", *namespace.as_tuple), "d10.contact_claim.v2", contact_id)


def contact_claim_graph_write_v2(namespace, claim, *, policy_key, opportunity_key):
    if type(claim) is not ContactClaimV2:
        raise TypeError("exact approved-window contact claim required")
    return GraphWrite(contact_claim_key_v2(namespace, claim.contact_id), asdict(claim),
                      (policy_key, opportunity_key))


def contact_claim_type_spec_v2():
    return D10TypeSpec("d10.contact_claim.v2", "d10", schema_hash({"d10.contact_claim.v2": 2}),
                      ("persona",), "state", decode_contact_claim_v2)
