# Frozen backend-only alpha1 candidate (local)

Do this only after backend G0–G7 acceptance, the domain registry and D04
scheme have frozen, `resources/catalogue/current.json` is independently
approved as `runtime_verified`/`READY`, and `metadata.yaml` names
`3.0.0-alpha1`. The entire checkout must be committed and clean. Keep output
outside the checkout; do not commit the ZIP, inventory, native binary, or logs.

On the target host, first run the Rust tests and build the release library:

```powershell
cargo test --locked --release --manifest-path rewrite/native/Cargo.toml
cargo build --locked --release --manifest-path rewrite/native/Cargo.toml
```

For a frozen Windows x86_64 checkout, run from the repository root:

```powershell
$sourceCommit = (git rev-parse HEAD).Trim()
$catalogueHash = (Get-Content resources/catalogue/current.json -Raw | ConvertFrom-Json).catalogue_hash
$nativePath = 'rewrite/native/target/release/sylanne3_kernel.dll'
$nativeHash = (Get-FileHash $nativePath -Algorithm SHA256).Hash.ToLowerInvariant()
$candidateDir = Join-Path $env:TEMP 'sylanne-alpha1-candidate'
$inventoryPath = Join-Path $candidateDir 'windows-x86_64-inventory.json'
py -3 scripts/alpha1/audit_backend_candidate.py build --expected-source-commit $sourceCommit --expected-catalogue-sha256 $catalogueHash --expected-native-sha256 $nativeHash --target-os windows --target-arch x86_64 --native-library $nativePath --output-dir $candidateDir --inventory-output $inventoryPath
$audit = Get-Content $inventoryPath -Raw | ConvertFrom-Json
py -3 scripts/alpha1/verify_formal_cold_install.py --package $audit.package --expected-manifest-sha256 $audit.manifest_sha256
```

The build command rejects a dirty or wrong commit, unapproved catalogue,
incorrect native hash, wrong formal version, invalid resources and bad platform
binary before reporting success. The receipt independently hashes each ZIP
member and records ZIP, manifest, source, catalogue and native hashes. Pin the
ZIP and manifest hashes in the acceptance record. The cold probe uses its
caller-supplied hash to check isolated package mechanics; this local sequence
does not replace a trusted distribution root or host/product G5 acceptance.
Backend catalogue and migration resources use an explicit file allowlist in
`build_plugin_package.py`. A new release resource needs an intentional allowlist
review before it can enter the ZIP; runtime databases, credentials and native
build outputs remain outside the candidate even if they appear under a release
resource directory. The ZIP verifier applies the same rule to imported archives.

For Linux x86_64/glibc and macOS arm64, build on the matching host with the
matching release library and run `audit_backend_candidate.py build` using
`--target-os linux --target-arch x86_64 --target-libc glibc` or
`--target-os macos --target-arch aarch64`, respectively. Run the cold probe
on that host. An archive copied from another host can be checked without
building via `audit_backend_candidate.py audit --package ...` with the same
pinned source/catalogue/native/platform arguments, an external
`--inventory-output`, and preferably pinned `--expected-package-sha256` and
`--expected-manifest-sha256`. Cross-compilation or a copied `.dylib` is not a
macOS load, test or representative-solve receipt.

Current environment evidence (2026-09-28): Windows MSVC and WSL2 Ubuntu
`AstrEmbodimentVerify` each passed 59 release Rust tests and an ABI2 native
load/representative solve against the same native source tree SHA256
`7b3fe3f9d8aea7d42a5b33a060cd5ea5ee7a8b32ab4c79281e2e72def062e461`.
The Windows DLL SHA256 is
`ab1dab46aa1a6a715b30cd66a9088b19e8c1af75850b69a736d3761e46b854a8`;
the WSL Linux `.so` SHA256 is
`e91bf7dbf042a4d080e35884ed93b81f38b76af43d42a759dcc624efe89b0070`.
The other registered WSL distribution `zhuoyi-Ubuntu-20.04` cannot start:
`Wsl/Service/CreateInstance/MountDisk/HCS/ERROR_PATH_NOT_FOUND`. The Windows
Rust toolchain can `cargo check --locked --target aarch64-apple-darwin`;
producing the macOS
`cdylib` fails because `xcrun`, the macOS SDK and a target linker are absent.
Neither cross-check nor historical CI substitutes for a matching Mac run.
