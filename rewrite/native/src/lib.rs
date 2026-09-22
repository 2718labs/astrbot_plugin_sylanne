//! Fixed backward-Euler system refinement. Certificates concern the discrete
//! linear system only, never the temporal discretization error.
use std::slice;

#[no_mangle]
pub extern "C" fn sylanne3_abi_version() -> u32 {
    1
}

/// Refine an immutable physical interval; `initial` is only the numerical iterate.
///
/// # Safety
/// Caller provides live, aligned readable arrays of n doubles (edges: n*n),
/// writable solution of n doubles and metrics of 4 doubles. Output memory must
/// not overlap any input or each other. Pointers must remain valid throughout
/// the call; no concurrent mutation is permitted. Null is rejected, but allocation
/// bounds and pointer provenance cannot be established by a C ABI.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_refine(
    n: usize,
    mass: *const f64,
    recovery: *const f64,
    edges: *const f64,
    previous: *const f64,
    drive: *const f64,
    dt: f64,
    initial: *const f64,
    max_sweeps: usize,
    tolerance: f64,
    solution: *mut f64,
    metrics: *mut f64,
) -> i32 {
    if !(1..=256).contains(&n)
        || !(1..=64).contains(&max_sweeps)
        || !dt.is_finite()
        || dt <= 0.0
        || !tolerance.is_finite()
        || tolerance <= 0.0
        || mass.is_null()
        || recovery.is_null()
        || edges.is_null()
        || previous.is_null()
        || drive.is_null()
        || initial.is_null()
        || solution.is_null()
        || metrics.is_null()
    {
        return -1;
    }
    let m = slice::from_raw_parts(mass, n);
    let r = slice::from_raw_parts(recovery, n);
    let e = slice::from_raw_parts(edges, n * n);
    let p = slice::from_raw_parts(previous, n);
    let d = slice::from_raw_parts(drive, n);
    let start = slice::from_raw_parts(initial, n);
    if m.iter().chain(r).any(|v| !v.is_finite() || *v <= 0.0)
        || e.iter()
            .chain(p)
            .chain(d)
            .chain(start)
            .any(|v| !v.is_finite())
    {
        return -1;
    }
    for i in 0..n {
        for j in 0..n {
            if e[i * n + j] < 0.0 || e[i * n + j] != e[j * n + i] || (i == j && e[i * n + j] != 0.0)
            {
                return -1;
            }
        }
    }
    let mut a = vec![0.0; n * n];
    let mut b = vec![0.0; n];
    let mut lower = f64::INFINITY;
    let mut bases = vec![0.0; n];
    let mut rhs_scale = vec![0.0; n];
    // Conservative operation-count allowance, well below 1 for n <= 256.
    // It includes coefficient/RHS construction and structural residual arithmetic.
    let gamma = 32.0 * (n as f64 + 4.0) * f64::EPSILON;
    for i in 0..n {
        let base = m[i] + dt * r[i];
        if !base.is_normal() || !(dt * r[i]).is_normal() {
            return -3;
        }
        bases[i] = base;
        lower = lower.min(base * (1.0 - 4.0 * f64::EPSILON));
        a[i * n + i] = base;
        for j in 0..n {
            if i != j {
                let w = dt * e[i * n + j];
                if e[i * n + j] != 0.0 && !w.is_normal() {
                    return -3;
                }
                a[i * n + i] += w;
                a[i * n + j] = -w;
            }
        }
        let mp = m[i] * p[i];
        let dd = dt * d[i];
        if (p[i] != 0.0 && !mp.is_normal()) || (d[i] != 0.0 && !dd.is_normal()) {
            return -3;
        }
        b[i] = mp + dd;
        rhs_scale[i] = mp.abs() + dd.abs();
        // Keep the strictly positive diagonal component well above assembly
        // roundoff. Otherwise the assembled iteration can erase recovery.
        if !a[i * n + i].is_finite() || gamma * a[i * n + i] >= base {
            return -3;
        }
    }
    if a.iter().chain(&b).any(|v| !v.is_finite()) || !lower.is_finite() {
        return -2;
    }
    let mut x = start.to_vec();
    let mut residual: f64;
    let mut bound: f64;
    let mut used = 0;
    loop {
        residual = 0.0;
        let mut roundoff = 0.0_f64;
        for i in 0..n {
            // Preserve the Laplacian's constant mode: never form diagonal*x
            // minus a comparably huge edge*x to recover the local term.
            let mut ax = bases[i] * x[i];
            let mut scale = bases[i].abs() * x[i].abs() + rhs_scale[i];
            for j in 0..n {
                if i != j {
                    let w = -a[i * n + j];
                    ax += w * (x[i] - x[j]);
                    scale += w * (x[i].abs() + x[j].abs());
                }
            }
            residual = residual.hypot(ax - b[i]);
            // An absolute underflow allowance is only present for nonzero
            // physical data/iterates; the exact all-zero solution stays zero.
            let tiny = if x.iter().any(|v| *v != 0.0) || p[i] != 0.0 || d[i] != 0.0 {
                (n as f64 + 4.0) * f64::MIN_POSITIVE
            } else {
                0.0
            };
            roundoff = roundoff.hypot(gamma * scale + tiny);
        }
        bound = (residual + roundoff) / lower;
        // A small rounded residual alone is insufficient for certification.
        if residual / lower <= tolerance && roundoff / lower > tolerance {
            return -3;
        }
        if !residual.is_finite() || !bound.is_finite() {
            return -2;
        }
        if bound <= tolerance || used == max_sweeps {
            break;
        }
        for i in 0..n {
            let off: f64 = (0..n)
                .filter(|j| *j != i)
                .map(|j| a[i * n + j] * x[j])
                .sum();
            x[i] = (b[i] - off) / a[i * n + i];
            if !x[i].is_finite() {
                return -2;
            }
        }
        used += 1;
    }
    let energy: f64 = (0..n)
        .map(|i| 0.5 * m[i] * (x[i] * x[i] - p[i] * p[i]))
        .sum();
    if !energy.is_finite() {
        return -2;
    }
    slice::from_raw_parts_mut(solution, n).copy_from_slice(&x);
    slice::from_raw_parts_mut(metrics, 4).copy_from_slice(&[residual, bound, energy, used as f64]);
    if bound <= tolerance {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_null_and_unbounded_work() {
        unsafe {
            assert_eq!(
                sylanne3_refine(
                    257,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1.0,
                    std::ptr::null(),
                    1,
                    1e-8,
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                -1
            );
        }
    }
    #[test]
    fn scalar_exact() {
        let mut out = [0.0];
        let mut metrics = [0.0; 4];
        let rc = unsafe {
            sylanne3_refine(
                1,
                [2.0].as_ptr(),
                [3.0].as_ptr(),
                [0.0].as_ptr(),
                [4.0].as_ptr(),
                [5.0].as_ptr(),
                0.5,
                [4.0].as_ptr(),
                1,
                1e-12,
                out.as_mut_ptr(),
                metrics.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(out[0], 3.0);
        assert_eq!(metrics[0], 0.0);
    }
}
