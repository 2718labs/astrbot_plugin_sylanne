# Native kernel: first foundation slice

Build: `cargo build --release --manifest-path rewrite/native/Cargo.toml`.
The Python bridge discovers `target/release` then `target/debug`; it never uses a
Python numerical fallback. ABI version is 1; see `../CONTRACT.md` for its signature.
The only Rust dependency is std. No native I/O or worker spawning occurs.

Safety: foreign callers must supply valid aligned allocations, readable for the
full input array lengths (n, or n*n for edges), writable for n solution doubles
and four metric doubles, and valid throughout the call. Outputs must not overlap
inputs or each other. Concurrent mutation is forbidden. Null pointers and scalar
bounds are checked, but C cannot prove pointer provenance or allocation lengths.
The ctypes bridge establishes these conditions with owned disjoint allocations.
Direct foreign callers are responsible for honoring them.

Dimensions are limited to 1..256; a native call accepts 1..64 Gauss-Seidel sweeps.
The Python job caps each requested budget at 64 and its remaining total allowance.
Cancellation is checked before and after a call; it cannot interrupt a sweep,
so cancellation latency is one bounded native quantum plus scheduling latency.
The scheduler is responsible for running jobs away from the event loop.

Every refinement uses the same copied physical previous state, drive and dt.
Only the numerical iterate changes. Every sweep checks the global residual.
Residual evaluation preserves the structure: `base_i*x_i + sum(w_ij*(x_i-x_j))
- b_i`, where `base = mass + dt*recovery`. The acceptance bound is
`(residual_l2 + roundoff_allowance) / safe_lower`, with
`safe_lower = min(base)*(1 - 4*EPSILON)`. This deliberately exceeds the bare
exact-arithmetic residual bound. For dimension n, gamma is
`32*(n+4)*EPSILON`. Each row's roundoff allowance is gamma times
`abs(base*x_i) + sum(w_ij*(abs(x_i)+abs(x_j))) + abs(mass_i*previous_i)
+ abs(dt*drive_i)`, plus `(n+4)*MIN_POSITIVE` when state/input is nonzero.
Row allowances are combined with the Euclidean norm. Exact zero data has no
artificial nonzero floor.

The supported binary64 numerical domain additionally requires normal positive
base and dt*recovery, normal nonzero edge products and RHS products, finite
assembly, and `gamma*assembled_diagonal < base` for every row. This rejects
coupling scales that can erase the positive local term. Nonfinite intermediate
values fail closed. If the residual is nominally within tolerance but the
roundoff allowance alone exceeds tolerance, status -3 rejects the attempted
certificate. Python surfaces this as ArithmeticError. Work that merely runs out
of sweeps still raises AccuracyNotMet. These are conservative numerical guardrails
with a roundoff budget, not a formal interval-arithmetic proof.
This does not certify time discretization accuracy, physical calibration, or an
emotion model. No-input energy decay follows from positive mass and recovery and
nonnegative symmetric graph edges; finite overflow fails closed with no certificate.

Validation: RED was unittest import failure before implementation
(`ModuleNotFoundError: sylanne3.native`). GREEN includes independent dense Gaussian
elimination, coupled systems, full residual, input immutability, precision budget
partitioning, energy dissipation, parameter rejection and cancellation. Windows
MSVC DLL loading is exercised. Linux/macOS library discovery names are implemented
but have not been executed on those operating systems.

Review regression: mass=recovery=[1,1], coupling=1e20, previous=[1,1],
drive=[-1,-1], dt=1 formerly returned a false zero residual for solution [1,1].
This case now explicitly rejects with status -3. A scalar 1/3 solve requested at
1e-30 tolerance also rejects instead of accepting its rounded zero residual.
Both regressions were observed failing before this correction.
