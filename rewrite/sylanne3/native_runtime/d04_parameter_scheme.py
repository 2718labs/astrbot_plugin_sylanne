"""Finite, source-conditioned D04 recovery parameter *candidates*.

The eight registered choices below are engineering hypotheses, not calibrated
human constants. The caller must provide a trusted, current graph snapshot and
Authority guard, and D11 must recheck recorded reads before any adoption. This
module does not replace an installed operator or establish G2 acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import math
from types import MappingProxyType

from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ..domains.d01 import PersonaDomain
from ..domains.d02 import BodyState
from ..domains.d04 import AffectProvider
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime_contracts import NamespaceId


SCHEMA = "d04.conditional-recovery-parameter.v1"
POSITIVE_RATE_FLOOR = 1.0 / 1024.0
RATE_CEILING = 1.0
STRATEGY_BLOCK_IDS = MappingProxyType({
    "d04.recovery.adaptive.v1": "adaptive",
    "d04.recovery.persistent.v1": "persistent",
})
_BASE_RATES = {
    "adaptive": (Fraction(1), Fraction(1, 8), Fraction(1, 64)),
    "persistent": (Fraction(3, 4), Fraction(3, 32), Fraction(1, 128)),
}
_RESOURCE_FACTORS = {"available": Fraction(1), "depleted": Fraction(3, 4)}
_MEANING_FACTORS = {
    "controllable": (Fraction(1), Fraction(1), Fraction(1)),
    "low_control": (Fraction(1), Fraction(3, 4), Fraction(1, 2)),
}


@dataclass(frozen=True, slots=True)
class D04RegisteredRecoveryScheme:
    scheme_id: str
    parameter_version: str
    fast_rate: float
    residual_rate: float
    slow_rate: float
    rates_24d: tuple[float, ...]
    status: str = "registered_engineering_candidate_only"


def _register_schemes() -> dict[str, D04RegisteredRecoveryScheme]:
    registered = {}
    for strategy, base in _BASE_RATES.items():
        for resource, resource_factor in _RESOURCE_FACTORS.items():
            for meaning, meaning_factors in _MEANING_FACTORS.items():
                rates = tuple(float(base[index] * resource_factor * meaning_factors[index])
                              for index in range(3))
                if not (RATE_CEILING >= rates[0] > rates[1] > rates[2]
                        >= POSITIVE_RATE_FLOOR):
                    raise AssertionError("registered D04 recovery rates violate their bounds")
                scheme_id = f"{strategy}:{resource}:{meaning}"
                registered[scheme_id] = D04RegisteredRecoveryScheme(
                    scheme_id, f"candidate:d04-recovery:v1:{scheme_id}",
                    *rates, rates * 8,
                )
    return registered


REGISTERED_RECOVERY_SCHEMES = MappingProxyType(_register_schemes())


@dataclass(frozen=True, slots=True)
class D04ParameterSelection:
    status: str
    hold_reason: str | None
    scheme: D04RegisteredRecoveryScheme | None
    namespace: NamespaceId
    source_versions: tuple[GraphVersion, ...]
    graph_epoch: int | None
    meaning_facet_id: str | None
    schema: str = SCHEMA


def _hold(namespace: NamespaceId, reason: str) -> D04ParameterSelection:
    return D04ParameterSelection("HOLD", reason, None, namespace, (), None, None)


def select_d04_recovery_scheme(
    snapshot: GraphSnapshot | None,
    *,
    namespace: NamespaceId,
    current_guard: OwnerAuthorizationGuardV1 | None,
    read_versions: tuple[GraphVersion, ...],
    resource_ref: str | None,
    meaning_ref: str | None,
    meaning_facet_id: str | None,
) -> D04ParameterSelection:
    """Select from verified D01/D02/D04 reads, or return HOLD.

    D01 qualification checks the current Owner guard and active persona head.
    D02 body state and D04 appraisal must be valid, same-namespace graph rows
    with exact versions in the caller's read guard. The read guard is a
    condition for later D11 adoption; this pure function cannot attest that
    the supplied snapshot/guard came from the live graph/Authority.

    An authored D01 strategy block picks one of two base profiles. Resource
    energy and one named, known controllability facet choose finite modifiers.
    The thresholds and factors are versioned engineering assumptions only.
    """
    if type(namespace) is not NamespaceId:
        raise TypeError("D04 parameter selection needs a namespace")
    if (type(snapshot) is not GraphSnapshot
            or type(current_guard) is not OwnerAuthorizationGuardV1
            or type(read_versions) is not tuple
            or any(type(item) is not GraphVersion for item in read_versions)
            or any(type(item) is not str or not item for item in
                   (resource_ref, meaning_ref, meaning_facet_id))):
        return _hold(namespace, "missing_trusted_source_read")
    if (len({version.key for version in read_versions}) != len(read_versions)
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)):
        return _hold(namespace, "ambiguous_source_versions")
    try:
        persona = PersonaDomain.resolve_active_role(
            snapshot, namespace=namespace, current_guard=current_guard,
        )
        resource_key = AtomKey.from_token(resource_ref)
        meaning_key = AtomKey.from_token(meaning_ref)
    except (TypeError, ValueError):
        return _hold(namespace, "unqualified_persona_or_source_ref")
    if (resource_key.type_name != "d02.body_state.v1"
            or resource_key.owner.kind != "persona"
            or meaning_key.type_name != "d04.appraisal_bundle.v1"
            or meaning_key.owner.kind != "event"
            or any((key.owner.bot, key.owner.persona) != namespace.as_tuple
                   for key in (resource_key, meaning_key))):
        return _hold(namespace, "source_type_or_namespace_mismatch")
    resource_atom = snapshot.get(resource_key)
    meaning_atom = snapshot.get(meaning_key)
    if (resource_atom is None or meaning_atom is None
            or not resource_atom.valid or not meaning_atom.valid
            or resource_atom.revision < 1 or meaning_atom.revision < 1):
        return _hold(namespace, "source_missing_or_invalid")
    required = (*persona.read_versions,
                GraphVersion(resource_key, resource_atom.revision),
                GraphVersion(meaning_key, meaning_atom.revision))
    if not set(required) <= set(read_versions):
        return _hold(namespace, "source_not_version_guarded")
    try:
        resource = BodyState(**resource_atom.value)
        appraisal_spec = next(spec for spec in AffectProvider().type_specs()
                              if spec.name == "d04.appraisal_bundle.v1")
        appraisal = appraisal_spec.validator(meaning_atom.value)
    except (TypeError, ValueError, KeyError, StopIteration):
        return _hold(namespace, "source_payload_invalid")
    if (resource.profile_id != resource_key.name
            or appraisal.appraisal_id != meaning_key.name):
        return _hold(namespace, "source_identity_mismatch")
    selected_blocks = [block for block in persona.plan.blocks
                       if block.block_id in STRATEGY_BLOCK_IDS]
    if (not persona.plan.authored or len(selected_blocks) != 1
            or selected_blocks[0].kind != "strategy"):
        return _hold(namespace, "registered_persona_strategy_missing_or_ambiguous")
    facets = [facet for facet in appraisal.meaning_facets
              if facet.facet_id == meaning_facet_id]
    if len(facets) != 1 or facets[0].controllability is None:
        return _hold(namespace, "meaning_facet_missing_or_unknown")

    strategy = STRATEGY_BLOCK_IDS[selected_blocks[0].block_id]
    resource_band = "depleted" if resource.energy < 0.5 else "available"
    meaning_band = "low_control" if facets[0].controllability < 0.5 else "controllable"
    scheme = REGISTERED_RECOVERY_SCHEMES[f"{strategy}:{resource_band}:{meaning_band}"]
    return D04ParameterSelection(
        "conditional_candidate", None, scheme, namespace, required,
        persona.graph_epoch, meaning_facet_id,
    )


@dataclass(frozen=True, slots=True)
class D04ParameterSwitchProposal:
    switch_id: str
    previous_parameter_version: str
    proposed_parameter_version: str
    effective_role_time: float
    source_versions: tuple[GraphVersion, ...]
    graph_epoch: int
    state_mapping: None = None
    energy_delta: None = None
    status: str = "HOLD_REQUIRES_STATE_MAP_AND_ENERGY_LEDGER"
    schema: str = "d04.parameter-switch-proposal.v1"


def propose_d04_parameter_switch(
    *, switch_id: str, previous_scheme_id: str,
    selection: D04ParameterSelection, effective_role_time: float,
) -> D04ParameterSwitchProposal:
    """Record a requested version change without claiming a state transition.

    A joint D04/D11 compiler must attach an authenticated pre-switch state,
    explicit map and energy difference before a real switch can be adopted.
    Fixed-parameter dissipation cannot be carried across this boundary.
    """
    if type(switch_id) is not str or not switch_id:
        raise ValueError("switch_id is required")
    if (type(selection) is not D04ParameterSelection
            or previous_scheme_id not in REGISTERED_RECOVERY_SCHEMES
            or selection.status != "conditional_candidate" or selection.scheme is None
            or REGISTERED_RECOVERY_SCHEMES.get(selection.scheme.scheme_id) != selection.scheme
            or previous_scheme_id == selection.scheme.scheme_id):
        raise ValueError("switch needs distinct registered source and target schemes")
    if (type(effective_role_time) not in (int, float)
            or not math.isfinite(effective_role_time) or effective_role_time < 0):
        raise ValueError("effective role time must be finite and nonnegative")
    previous = REGISTERED_RECOVERY_SCHEMES[previous_scheme_id]
    return D04ParameterSwitchProposal(
        switch_id, previous.parameter_version, selection.scheme.parameter_version,
        float(effective_role_time), selection.source_versions, selection.graph_epoch,
    )
