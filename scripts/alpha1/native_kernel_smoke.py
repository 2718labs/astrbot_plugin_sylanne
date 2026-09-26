#!/usr/bin/env python3
"""Build-output smoke for native ABI2 loading and one nonlinear step.

The temporary manifest only binds the just-built library for this local smoke;
it is not a release artifact or a product trust root.
"""

from __future__ import annotations

import argparse
import ctypes
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "rewrite"))

from sylanne3.native_runtime.fixed_block_transcript import (  # noqa: E402
    FixedBlockCSR,
    FixedBlockStep,
)
from sylanne3.native_runtime.abi2 import (  # noqa: E402
    ABI2CSR,
    ABI2StepInput,
    ABI2StepResult,
    ABI_VERSION,
    parse_fixed_block_interval_result,
)
from sylanne3.native_runtime.loader import ABI2NativeLibrary, _runtime_target  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--expect-target", help="expected loader target, such as macos-aarch64")
    args = parser.parse_args()

    library = args.library.resolve()
    if not library.is_file():
        parser.error(f"native library does not exist: {library}")
    os_name, arch, _libc = _runtime_target()
    target = f"{os_name}-{arch}"
    if args.expect_target and args.expect_target != target:
        raise SystemExit(f"runner target mismatch: expected {args.expect_target}, got {target}")

    handle = ABI2NativeLibrary(ctypes.CDLL(str(library)), library)
    abi_version = handle.capabilities.abi_version
    if not handle.capabilities.supports_fixed_block_interval_math_v1:
        raise SystemExit("native library does not expose fixed-block interval math")
    block = FixedBlockStep(
        k=FixedBlockCSR(1, 1, (0, 1), (0,), (2.0,)),
        r=FixedBlockCSR(1, 1, (0, 1), (0,), (1.0,)),
        j=FixedBlockCSR(1, 1, (0, 0), (), ()),
        a=FixedBlockCSR(1, 1, (0, 1), (0,), (1.0,)),
        alpha=(0.5,), previous=(0.4,), drive=(0.0,), iterate=(0.4,),
        h=0.1, previous_error=0.0, max_iterations=30, tolerance=1e-10,
    )

    def csr(value: FixedBlockCSR) -> tuple[ABI2CSR, tuple[object, ...]]:
        offsets = (ctypes.c_uint32 * len(value.offsets))(*value.offsets)
        indices = (ctypes.c_uint32 * len(value.indices))(*value.indices)
        values = (ctypes.c_double * len(value.values))(*value.values)
        return ABI2CSR(value.rows, value.cols, len(value.values), offsets, indices, values), (offsets, indices, values)

    matrices = [csr(matrix) for matrix in (block.k, block.r, block.j, block.a)]
    arrays = [
        (ctypes.c_double * len(values))(*values)
        for values in (block.alpha, block.previous, block.drive, block.iterate)
    ]
    request = ABI2StepInput(
        ctypes.sizeof(ABI2StepInput), ABI_VERSION, 1,
        *(matrix for matrix, _buffers in matrices), *arrays,
        block.h, block.previous_error, block.max_iterations, block.tolerance, block.boundary_eta,
    )
    output = (ctypes.c_double * 1)()
    raw = ABI2StepResult()
    status = handle._step(ctypes.byref(request), output, 1, ctypes.byref(raw))
    if status != 0 or raw.status != 0:
        raise SystemExit(f"representative native solve failed: return={status}, status={raw.status}")
    bounds = parse_fixed_block_interval_result(raw)
    if not (0.0 < output[0] < 0.4) or bounds.residual >= 1e-10:
        raise SystemExit(f"representative solve returned invalid output={output[0]} residual={bounds.residual}")

    print(
        f"native ABI2 smoke passed: target={target} "
        f"abi={abi_version} state={output[0]:.12g} "
        f"residual={bounds.residual:.3g}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
