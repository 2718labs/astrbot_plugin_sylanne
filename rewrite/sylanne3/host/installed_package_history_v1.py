"""Compose historical recipe readers from the actual selected protected cohort."""
from pathlib import Path
from .authority_profile import AdminInstallationBundle
from .selected_profile_cohort_v2 import BINDING_NAME, validate_profile_cohort_binding_v2, require_current_bundle_selection_v2
from ..authority_service.linux_installation_security_v1 import read_installed_json_v1
from ..authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
from ..authority_service.d12_public_history_eligibility_v1 import InstalledPublicHistoricalEligibilityReaderV1


def _actual_history(bundle, package_root):
    if type(bundle) is not AdminInstallationBundle:
        raise TypeError('actual protected package profile required')
    selected = bundle.package_selection
    if selected is None or selected.revision == 0:
        return None
    require_current_bundle_selection_v2(bundle, package_root, require_selected_python=True)
    directory=Path(bundle.tls_profile.client_private_key).parent
    binding=validate_profile_cohort_binding_v2(read_installed_json_v1(directory/BINDING_NAME),directory)
    if binding['installation_id'] != bundle.installation_policy.installation_id:
        raise ValueError('package history fixed credential installation differs')
    files=InstalledPackageSelectionFilesV2(control_directory=binding['control_directory'])
    eligibility=InstalledPublicHistoricalEligibilityReaderV1(package_files=files).read_current_v1()
    if eligibility.selection != selected:
        raise ValueError('historical eligibility belongs to another actual selected cohort')
    return files,eligibility


def build_installed_host_d04_history_v1(installation):
    from .v2_installation import V2InstallationAssembly
    from .installed_d04_historical_compatibility_v1 import InstalledHistoricalD04CompatibilityV1
    if type(installation) is not V2InstallationAssembly:
        raise TypeError('actual Host installation required for historical D04 reads')
    bundle=installation.admin_bundle
    if bundle is None: return None
    observed=_actual_history(bundle,installation.package_root)
    if observed is None:return None
    files,eligibility=observed;policy=bundle.installation_policy
    return InstalledHistoricalD04CompatibilityV1(package_files=files,namespace=policy.namespace,
        installation_id=policy.installation_id,current_manifest_sha256=policy.manifest_digest,
        historical_eligibility=eligibility,host_installation=installation)


def build_installed_authority_d04_recipe_history_v1(bundle, package_root):
    from ..authority_service.d12_historical_d04_recipe_v1 import InstalledHistoricalD04RecipeReaderV1
    observed=_actual_history(bundle,package_root)
    if observed is None:return None
    files,eligibility=observed;policy=bundle.installation_policy
    return InstalledHistoricalD04RecipeReaderV1(package_files=files,namespace=policy.namespace,
        installation_id=policy.installation_id,current_manifest_sha256=policy.manifest_digest,
        historical_eligibility=eligibility)
