# Migration policy

`v1.json` registers one deliberately narrow preview migrator for the exact
v2.5 `PersonProfile` implementation pinned by source revision and blob ID. It
requires an independently verified deletion watermark and produces only an
isolated D12 draft for human review. It never activates data and does not map
legacy relationship counters, affinity, emotion, or profile values into trust,
shared experience, or active character state.

Formal release remains HOLD. There is no verified legacy export/archive format,
target identity mapping, complete deletion/execution watermark proof, or D11
atomic adoption path. A package name, file hash, or successful unpack is not
migration proof.
