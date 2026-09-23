"""Typed graph values and registry for the phase 5b graph contract."""

from dataclasses import dataclass, field
import hashlib
import json
import re

from .contracts import Event, canonical_json, json_object, nonempty


OWNER_KINDS = frozenset({"persona", "relation", "scene", "event", "activity"})
STORAGE_ROLES = frozenset({"source", "state", "projection", "cache"})
OWNER_GRANT_TYPE = "d11.owner_grant.v1"
_OWNER_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def validate_owner_grant_v1(value: dict) -> None:
    """Validate the graph's durable grant record, not its Authority status."""
    expected = {
        "schema", "authority_id", "installation_id", "grant_id", "principal",
        "ticket_id", "creation_operation_id", "creation_digest",
        "issue_operation_id", "grant_revision", "state",
        "scope", "issuer_ref", "capabilities", "purposes", "audiences",
        "activation_generation", "graph_incarnation",
    }
    if type(value) is not dict or set(value) != expected:
        raise ValueError("owner grant fields differ from v1 schema")
    if value["schema"] != "sylanne3.graph.owner_grant.v1":
        raise ValueError("unknown graph owner grant schema")
    for name in ("authority_id", "installation_id", "grant_id", "ticket_id",
                 "creation_operation_id", "issue_operation_id", "scope",
                 "issuer_ref", "graph_incarnation"):
        if type(value[name]) is not str or not value[name]:
            raise ValueError(f"owner grant {name} is required")
    for name in ("creation_digest",):
        if type(value[name]) is not str or _OWNER_DIGEST.fullmatch(value[name]) is None:
            raise ValueError(f"owner grant {name} must be SHA-256")
    principal = value["principal"]
    if (type(principal) is not dict or set(principal) != {
            "identity_provider", "account_ref", "account_incarnation"}
            or any(type(item) is not str or not item for item in principal.values())):
        raise ValueError("owner grant requires a stable principal")
    for name in ("capabilities", "purposes", "audiences"):
        items = value[name]
        if (type(items) is not list or not items
                or any(type(item) is not str or not item for item in items)
                or items != sorted(set(items))):
            raise ValueError(f"owner grant {name} must be a sorted nonempty set")
    if (value["grant_revision"] != 1 or type(value["grant_revision"]) is not int
            or value["state"] != "pending_authority"
            or type(value["activation_generation"]) is not int
            or value["activation_generation"] < 1):
        raise ValueError("first owner grant must remain pending at revision one")


def owner_grant_key(bot: str, persona: str) -> "AtomKey":
    return AtomKey(Owner("persona", bot, persona), OWNER_GRANT_TYPE, "primary")


def owner_grant_spec() -> "TypeSpec":
    """W01's reserved type, explicitly registered by the product catalogue."""
    return TypeSpec(
        OWNER_GRANT_TYPE, ("persona",), "state",
        validate_owner_grant_v1, schema_version=1, writer_domain="d11",
        schema_hash=hashlib.sha256(
            b"sylanne3.graph.owner_grant.v1:strict:pending"
        ).hexdigest(),
    )


def owner_grant_policy_digest_v1(value: dict, *, bot: str, persona: str) -> str:
    """Bind claim-ticket policy to the grant's exact content permissions."""
    validate_owner_grant_v1(value)
    payload = {
        "schema": "sylanne3.graph.owner_grant_policy.v1",
        "namespace": [bot, persona],
        "authority_id": value["authority_id"],
        "installation_id": value["installation_id"],
        "scope": value["scope"],
        "issuer_ref": value["issuer_ref"],
        "capabilities": value["capabilities"],
        "purposes": value["purposes"],
        "audiences": value["audiences"],
        "activation_generation": value["activation_generation"],
    }
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Owner:
    kind: str
    bot: str
    persona: str
    subject: str | None = None

    def __post_init__(self):
        if self.kind not in OWNER_KINDS:
            raise ValueError(f"unknown owner kind: {self.kind!r}")
        nonempty(self.bot, "bot")
        nonempty(self.persona, "persona")
        if self.kind == "persona":
            if self.subject is not None:
                raise ValueError("persona owner must not have a subject")
        else:
            nonempty(self.subject, "subject")


@dataclass(frozen=True)
class AtomKey:
    owner: Owner
    type_name: str
    name: str

    def __post_init__(self):
        if not isinstance(self.owner, Owner):
            raise TypeError("owner must be Owner")
        nonempty(self.type_name, "type_name")
        nonempty(self.name, "name")

    @property
    def token(self) -> str:
        owner = self.owner
        return canonical_json([
            owner.kind, owner.bot, owner.persona, owner.subject, self.type_name, self.name
        ])

    @classmethod
    def from_token(cls, token: str) -> "AtomKey":
        if not isinstance(token, str):
            raise TypeError("token must be a string")
        try:
            parts = json.loads(token)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid atom token") from exc
        if type(parts) is not list or len(parts) != 6:
            raise ValueError("atom token must contain six fields")
        kind, bot, persona, subject, type_name, name = parts
        key = cls(Owner(kind, bot, persona, subject), type_name, name)
        if key.token != token:
            raise ValueError("atom token is not canonical")
        return key


@dataclass(frozen=True)
class TypeSpec:
    name: str
    owner_kinds: tuple[str, ...]
    storage_role: str
    validator: object = field(compare=False, repr=False)
    immutable: bool = False
    schema_version: int = 1
    writer_domain: str | None = None
    schema_hash: str | None = None

    def __post_init__(self):
        nonempty(self.name, "type name")
        kinds = tuple(sorted(self.owner_kinds))
        if not kinds or len(set(kinds)) != len(kinds) or any(kind not in OWNER_KINDS for kind in kinds):
            raise ValueError("owner_kinds must be unique supported owner kinds")
        if self.storage_role not in STORAGE_ROLES:
            raise ValueError(f"unknown storage role: {self.storage_role!r}")
        if not callable(self.validator):
            raise TypeError("validator must be callable")
        if type(self.immutable) is not bool:
            raise TypeError("immutable must be bool")
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise ValueError("schema_version must be a positive exact integer")
        if self.writer_domain is not None:
            nonempty(self.writer_domain, "writer_domain")
        if self.schema_hash is not None:
            if (type(self.schema_hash) is not str or len(self.schema_hash) != 64
                    or any(ch not in "0123456789abcdef" for ch in self.schema_hash)):
                raise ValueError("schema_hash must be a lowercase SHA-256 digest")
        object.__setattr__(self, "owner_kinds", kinds)


class TypeRegistry:
    """Mutable builder; GraphStore takes an isolated snapshot at construction."""

    def __init__(self):
        self._specs: dict[str, TypeSpec] = {}

    def register(self, spec: TypeSpec) -> None:
        if not isinstance(spec, TypeSpec):
            raise TypeError("spec must be TypeSpec")
        if spec.name in self._specs:
            raise ValueError(f"type already registered: {spec.name}")
        self._specs[spec.name] = spec

    def spec(self, name: str) -> TypeSpec:
        nonempty(name, "type name")
        try:
            return self._specs[name]
        except KeyError:
            raise KeyError(f"unknown graph type: {name}") from None

    def validate(self, key: AtomKey, value: dict) -> dict:
        if not isinstance(key, AtomKey):
            raise TypeError("key must be AtomKey")
        spec = self.spec(key.type_name)
        if key.owner.kind not in spec.owner_kinds:
            raise ValueError(f"type {spec.name!r} does not support owner kind {key.owner.kind!r}")
        detached = json_object(value)
        spec.validator(json_object(detached))
        return detached

    def freeze(self) -> "TypeRegistry":
        frozen = TypeRegistry()
        frozen._specs = dict(self._specs)
        return frozen

    @property
    def specs(self) -> tuple[TypeSpec, ...]:
        return tuple(self._specs[name] for name in sorted(self._specs))

    @property
    def catalogue_hash(self) -> str:
        rows = [[spec.name, list(spec.owner_kinds), spec.storage_role,
                 spec.immutable, spec.schema_version, spec.writer_domain,
                 spec.schema_hash] for spec in self.specs]
        return hashlib.sha256(canonical_json(rows).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GraphVersion:
    key: AtomKey
    revision: int

    def __post_init__(self):
        if not isinstance(self.key, AtomKey):
            raise TypeError("key must be AtomKey")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("revision must be a nonnegative exact integer")


@dataclass(frozen=True)
class GraphAtom:
    key: AtomKey
    revision: int
    value: dict
    valid: bool = True

    def __post_init__(self):
        GraphVersion(self.key, self.revision)
        if type(self.valid) is not bool:
            raise TypeError("valid must be bool")
        object.__setattr__(self, "value", json_object(self.value))


@dataclass(frozen=True)
class NamespaceEpoch:
    bot: str
    persona: str
    revision: int

    def __post_init__(self):
        nonempty(self.bot, "bot")
        nonempty(self.persona, "persona")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("revision must be a nonnegative exact integer")


@dataclass(frozen=True)
class GraphSnapshot:
    atoms: tuple[GraphAtom, ...]
    epochs: tuple[NamespaceEpoch, ...]

    def __post_init__(self):
        atoms = tuple(self.atoms)
        epochs = tuple(self.epochs)
        if any(not isinstance(atom, GraphAtom) for atom in atoms):
            raise TypeError("atoms must contain GraphAtom values")
        if any(not isinstance(epoch, NamespaceEpoch) for epoch in epochs):
            raise TypeError("epochs must contain NamespaceEpoch values")
        object.__setattr__(self, "atoms", atoms)
        object.__setattr__(self, "epochs", epochs)

    def get(self, key: AtomKey) -> GraphAtom | None:
        return next((atom for atom in self.atoms if atom.key == key), None)

    @property
    def versions(self) -> tuple[GraphVersion, ...]:
        return tuple(GraphVersion(atom.key, atom.revision) for atom in self.atoms)


@dataclass(frozen=True)
class GraphWrite:
    key: AtomKey
    value: dict
    dependencies: tuple[AtomKey, ...] = ()

    def __post_init__(self):
        if not isinstance(self.key, AtomKey):
            raise TypeError("key must be AtomKey")
        dependencies = tuple(self.dependencies)
        if any(not isinstance(key, AtomKey) for key in dependencies):
            raise TypeError("dependencies must contain AtomKey values")
        if len(set(dependencies)) != len(dependencies):
            raise ValueError("duplicate dependencies")
        object.__setattr__(self, "value", json_object(self.value))
        object.__setattr__(self, "dependencies", dependencies)


@dataclass(frozen=True)
class GraphPage:
    snapshot: GraphSnapshot
    next_after: AtomKey | None

    def __post_init__(self):
        if not isinstance(self.snapshot, GraphSnapshot):
            raise TypeError('snapshot must be GraphSnapshot')
        if self.next_after is not None and not isinstance(self.next_after, AtomKey):
            raise TypeError('next_after must be AtomKey or None')


@dataclass(frozen=True)
class GraphCandidate:
    event: Event
    reads: tuple[GraphVersion, ...]
    writes: tuple[GraphWrite, ...]
    epochs: tuple[NamespaceEpoch, ...] = ()

    def __post_init__(self):
        if not isinstance(self.event, Event):
            raise TypeError("event must be Event")
        reads = tuple(self.reads)
        writes = tuple(self.writes)
        epochs = tuple(self.epochs)
        if any(not isinstance(value, GraphVersion) for value in reads):
            raise TypeError("reads must contain GraphVersion values")
        if any(not isinstance(value, GraphWrite) for value in writes):
            raise TypeError("writes must contain GraphWrite values")
        if any(not isinstance(value, NamespaceEpoch) for value in epochs):
            raise TypeError("epochs must contain NamespaceEpoch values")
        # Rebuild writes to detach mutable values from the caller at the candidate boundary.
        object.__setattr__(self, "reads", reads)
        object.__setattr__(self, "writes", tuple(GraphWrite(w.key, w.value, w.dependencies) for w in writes))
        object.__setattr__(self, "epochs", epochs)


@dataclass(frozen=True)
class GraphReceipt:
    status: str
    revisions: tuple[GraphVersion, ...]
    invalidated: tuple[GraphVersion, ...]
    epoch: NamespaceEpoch

    def __post_init__(self):
        if self.status not in ("committed", "duplicate"):
            raise ValueError("status must be committed or duplicate")
        revisions = tuple(self.revisions)
        invalidated = tuple(self.invalidated)
        if any(not isinstance(value, GraphVersion) for value in revisions + invalidated):
            raise TypeError("receipt revisions must contain GraphVersion values")
        if not isinstance(self.epoch, NamespaceEpoch):
            raise TypeError("epoch must be NamespaceEpoch")
        object.__setattr__(self, "revisions", revisions)
        object.__setattr__(self, "invalidated", invalidated)
