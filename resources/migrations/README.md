# Migration policy

The versioned `native_data_policy` in `v1.json` describes the backend-only
alpha1 startup gate. A missing or empty plugin data directory is a fresh
installation. A directory containing only `sylanne3.sqlite3` and its SQLite
`-wal`/`-shm` sidecars is an existing native candidate, subject to the graph's
exact type catalogue and Authority recovery checks. Any other entry, unsafe
directory, or orphan journal requires migration review **before** the graph
opens. The packaged policy identifies
`sylanne3.host.legacy_data_preflight:inspect_native_data_dir_v1` as the
implementation; it does not silently import or delete data.

`v1.json` registers one deliberately narrow preview migrator for the exact
v2.5 `PersonProfile` implementation pinned by source revision and blob ID. It
requires an independently verified deletion watermark and produces only an
isolated D12 draft for human review. It never activates data and does not map
legacy relationship counters, affinity, emotion, or profile values into trust,
shared experience, or active character state.

Legacy upgrade remains HOLD, including in a backend-only formal package. There is no verified legacy export/archive format,
target identity mapping, complete deletion/execution watermark proof, or D11
atomic adoption path. A package name, file hash, or successful unpack is not
migration proof.
