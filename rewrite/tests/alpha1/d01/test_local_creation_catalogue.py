import hashlib
import json
from pathlib import Path

from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.d01_onboarding import VerifiedBudgetLease, VerifiedModelCapability
from sylanne3.workbench_api.local_creation_catalogue import LocalCreationCatalogue


NAMESPACE = NamespaceId("bot", "persona")
ASSET = Path("resources/catalogue/d01-onboarding-presets.json")


class HostChecks:
    def __init__(self, *, model=True, budget=True):
        self.model = model
        self.budget = budget
        self.seen = []

    def resolve_current_model_capability(self, *, namespace, capability_ref):
        self.seen.append(("model", namespace, capability_ref))
        if self.model and capability_ref == "model:local-current":
            return VerifiedModelCapability(namespace, capability_ref, "provider/model", 3,
                                           "sha256:" + "a" * 64)
        return None

    def resolve_current_budget_lease(self, *, namespace, budget_ref):
        self.seen.append(("budget", namespace, budget_ref))
        if self.budget and budget_ref == "budget:local-current":
            return VerifiedBudgetLease(namespace, budget_ref, "lease:current", 2,
                                       "sha256:" + "b" * 64)
        return None


def package_root(tmp_path: Path) -> Path:
    root = tmp_path
    (root / ASSET).parent.mkdir(parents=True)
    content = (Path(__file__).resolve().parents[4] / ASSET).read_bytes()
    (root / ASSET).write_bytes(content)
    (root / "release-manifest.json").write_text(json.dumps({
        "files": [{"path": ASSET.as_posix(), "sha256": hashlib.sha256(content).hexdigest()}],
    }), encoding="utf-8")
    return root


def catalogue(root, checks):
    return LocalCreationCatalogue(package_root=root, model_checker=checks, budget_checker=checks)


def resolve(cat, blueprint="d01.persona.warm-listener.v1", model="model:local-current",
            budget="budget:local-current"):
    return cat.resolve_current_resources(
        namespace=NAMESPACE, blueprint_ref=blueprint,
        model_capability_ref=model, budget_ref=budget,
    )


def test_resolves_manifest_bound_chinese_persona_preset(tmp_path):
    checks = HostChecks()
    resources = resolve(catalogue(package_root(tmp_path), checks))
    assert resources is not None
    assert resources.blocks[0].claim == "倾向先听清对方的意思，再给出回应。"
    assert resources.values[0].rule_id == "careful-listening"
    assert resources.model.resource_ref == "provider/model"
    assert resources.budget.lease_ref == "lease:current"
    assert checks.seen == [
        ("model", NAMESPACE, "model:local-current"),
        ("budget", NAMESPACE, "budget:local-current"),
    ]


def test_rejects_modified_preset_bytes_even_when_selection_exists(tmp_path):
    root = package_root(tmp_path)
    asset_path = root / ASSET
    asset_path.write_bytes(asset_path.read_bytes().replace("温和而坦诚".encode(), "强势说服".encode()))
    assert resolve(catalogue(root, HostChecks())) is None


def test_rejects_unknown_blueprint_and_unavailable_host_model_or_budget(tmp_path):
    root = package_root(tmp_path)
    checks = HostChecks()
    cat = catalogue(root, checks)
    assert resolve(cat, blueprint="browser-supplied") is None
    assert resolve(cat, model="model:browser-invented") is None
    assert resolve(cat, budget="budget:browser-invented") is None
    assert checks.seen == [
        ("model", NAMESPACE, "model:browser-invented"),
        ("budget", NAMESPACE, "budget:local-current"),
        ("model", NAMESPACE, "model:local-current"),
        ("budget", NAMESPACE, "budget:browser-invented"),
    ]


def test_rejects_host_reported_stale_capabilities(tmp_path):
    root = package_root(tmp_path)
    assert resolve(catalogue(root, HostChecks(model=False))) is None
    assert resolve(catalogue(root, HostChecks(budget=False))) is None
