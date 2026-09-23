//! ABI 2 sparse nonlinear AVF step.
//!
//! All current step results are diagnostic. Certificate bits remain reserved
//! until an independent outward-rounding verifier covers the full operator.
use std::{
    ptr, slice,
    sync::atomic::{AtomicU32, Ordering},
};

const ABI: u32 = 2;
const MAX_N: usize = 65_536;
const MAX_NNZ: usize = 2_000_000;
const MAX_ITER: u32 = 256;

#[repr(C)]
pub struct Csr {
    pub rows: u32,
    pub cols: u32,
    pub nnz: u32,
    pub offsets: *const u32, // rows + 1
    pub indices: *const u32, // nnz
    pub values: *const f64,  // nnz
}

#[repr(C)]
pub struct StepInput {
    pub struct_size: u32,
    pub abi_version: u32,
    pub n: u32,
    pub k: Csr,
    pub r: Csr,
    pub j: Csr,
    pub a: Csr,               // each row is one log-cosh argument
    pub alpha: *const f64,    // a.rows
    pub previous: *const f64, // n
    pub drive: *const f64,    // n; preassembled G u
    pub iterate: *const f64,  // n; continuation from prior output
    pub h: f64,
    pub previous_error: f64,
    pub max_iterations: u32,
    pub tolerance: f64,
    pub boundary_eta: f64, // bound for omitted full-system defect; zero for full block
}

#[repr(C)]
#[derive(Default)]
pub struct StepResult {
    pub struct_size: u32,
    pub abi_version: u32,
    pub status: i32, // 0 tolerance diagnostic met; 1 continue; negative rejected
    pub iterations: u32,
    pub certificate_flags: u32,
    pub residual: f64,
    pub iteration_error: f64,
    pub time_defect: f64,
    pub trajectory_error: f64,
    pub energy_before: f64,
    pub energy_after: f64,
    pub energy_balance_defect: f64,
    pub q_upper: f64,
    pub boundary_eta: f64,
}

#[no_mangle]
pub extern "C" fn sylanne3_v2_abi_version() -> u32 {
    ABI
}

#[no_mangle]
pub extern "C" fn sylanne3_v2_supported_certificate_flags() -> u32 {
    // Current f64 estimates lack cross-platform directed-rounding proof.
    0
}

#[no_mangle]
pub extern "C" fn sylanne3_v2_max_dimension() -> u32 {
    MAX_N as u32
}

struct Matrix<'a> {
    rows: usize,
    offsets: &'a [u32],
    indices: &'a [u32],
    values: &'a [f64],
}
impl Matrix<'_> {
    fn mul(&self, x: &[f64]) -> Vec<f64> {
        (0..self.rows)
            .map(|i| {
                (self.offsets[i] as usize..self.offsets[i + 1] as usize)
                    .map(|p| self.values[p] * x[self.indices[p] as usize])
                    .sum()
            })
            .collect()
    }
    fn row_abs_max(&self) -> f64 {
        (0..self.rows)
            .map(|i| {
                (self.offsets[i] as usize..self.offsets[i + 1] as usize)
                    .map(|p| self.values[p].abs())
                    .sum::<f64>()
            })
            .fold(0.0, f64::max)
    }
    fn col_abs_max(&self, n: usize) -> f64 {
        let mut sums = vec![0.0; n];
        for p in 0..self.values.len() {
            sums[self.indices[p] as usize] += self.values[p].abs();
        }
        sums.into_iter().fold(0.0, f64::max)
    }
    fn entry(&self, row: usize, col: u32) -> Option<f64> {
        let start = self.offsets[row] as usize;
        let end = self.offsets[row + 1] as usize;
        self.indices[start..end]
            .binary_search(&col)
            .ok()
            .map(|p| self.values[start + p])
    }

    fn is_strict_positive_diagonal(&self) -> bool {
        (0..self.rows).all(|row| {
            let start = self.offsets[row] as usize;
            let end = self.offsets[row + 1] as usize;
            end == start + 1 && self.indices[start] as usize == row && self.values[start] > 0.0
        })
    }

    fn is_zero(&self) -> bool {
        self.values.iter().all(|value| *value == 0.0)
    }
}

// SAFETY: the caller owns all live, aligned buffers for the entire call. Outputs
// must not overlap input buffers. Lengths and provenance remain caller duties.
unsafe fn read_matrix<'a>(csr: &'a Csr, rows: usize, cols: usize) -> Option<Matrix<'a>> {
    let nnz = csr.nnz as usize;
    if csr.rows as usize != rows
        || csr.cols as usize != cols
        || nnz > MAX_NNZ
        || csr.offsets.is_null()
        || (csr.offsets as usize) % std::mem::align_of::<u32>() != 0
        || (nnz != 0 && (csr.indices.is_null() || csr.values.is_null()))
        || (nnz != 0
            && ((csr.indices as usize) % std::mem::align_of::<u32>() != 0
                || (csr.values as usize) % std::mem::align_of::<f64>() != 0))
    {
        return None;
    }
    let offsets = slice::from_raw_parts(csr.offsets, rows + 1);
    let indices = if nnz == 0 {
        &[]
    } else {
        slice::from_raw_parts(csr.indices, nnz)
    };
    let values = if nnz == 0 {
        &[]
    } else {
        slice::from_raw_parts(csr.values, nnz)
    };
    if offsets[0] != 0 || offsets[rows] as usize != nnz || values.iter().any(|v| !v.is_finite()) {
        return None;
    }
    for i in 0..rows {
        let start = offsets[i] as usize;
        let end = offsets[i + 1] as usize;
        if start > end
            || end > nnz
            || indices[start..end].iter().any(|&c| c as usize >= cols)
            || indices[start..end].windows(2).any(|w| w[0] >= w[1])
        {
            return None;
        }
    }
    Some(Matrix {
        rows,
        offsets,
        indices,
        values,
    })
}

fn validate_structured(m: &Matrix, sign: f64) -> bool {
    for i in 0..m.rows {
        let mut diagonal = 0.0;
        let mut off = 0.0;
        for p in m.offsets[i] as usize..m.offsets[i + 1] as usize {
            let j = m.indices[p] as usize;
            let v = m.values[p];
            if i == j {
                diagonal = v;
            } else {
                if sign == 1.0 && v > 0.0 {
                    return false;
                }
                off += v.abs();
                if m.entry(j, i as u32) != Some(sign * v) {
                    return false;
                }
            }
        }
        if sign == -1.0 {
            if diagonal != 0.0 {
                return false;
            }
        } else if !(diagonal > off) {
            return false;
        }
    }
    true
}

fn logcosh(v: f64) -> f64 {
    v.abs() + (-2.0 * v.abs()).exp().ln_1p() - std::f64::consts::LN_2
}
fn quotient(u: f64, v: f64) -> f64 {
    let d = v - u;
    if u > 20.0 && v > 20.0 {
        return 1.0;
    }
    if u < -20.0 && v < -20.0 {
        return -1.0;
    }
    if d.abs() < 1e-4 {
        let mid = 0.5 * u + 0.5 * v;
        let t = mid.tanh();
        // Centered integral mean of tanh, with O(d^4) remainder.
        t - (d * d / 12.0) * t * (1.0 - t * t)
    } else {
        (logcosh(v) - logcosh(u)) / d
    }
}
fn norm(v: &[f64]) -> f64 {
    v.iter().fold(0.0, |s, x| s.hypot(*x))
}
fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

fn round_margin(scale: f64, operations: usize) -> Option<f64> {
    if !scale.is_finite() || scale < 0.0 {
        return None;
    }
    let count = operations.max(1) as f64;
    let gamma = count * f64::EPSILON;
    if gamma >= 0.25 {
        return None;
    }
    let margin = (scale + 1.0) * gamma / (1.0 - gamma) + count * f64::MIN_POSITIVE;
    margin.is_finite().then_some(margin)
}

fn certifiable_quadratic_diagonal(
    k: &Matrix,
    r: &Matrix,
    j: &Matrix,
    a: &Matrix,
    eta: f64,
) -> bool {
    a.rows == 0
        && j.is_zero()
        && k.is_strict_positive_diagonal()
        && r.is_strict_positive_diagonal()
        && eta == 0.0
}

fn diagonal_residual_roundoff(
    k: &Matrix,
    r: &Matrix,
    x: &[f64],
    y: &[f64],
    drive: &[f64],
    h: f64,
) -> Option<f64> {
    let mut coordinate_bounds = Vec::with_capacity(x.len());
    for i in 0..x.len() {
        let kval = k.values[k.offsets[i] as usize].abs();
        let rval = r.values[r.offsets[i] as usize].abs();
        let midpoint_scale = 0.5 * (x[i].abs() + y[i].abs());
        let force_scale = rval * kval * midpoint_scale + drive[i].abs();
        let scale = x[i].abs() + y[i].abs() + h.abs() * force_scale;
        coordinate_bounds.push(round_margin(scale, 16)?);
    }
    let component_norm = norm(&coordinate_bounds);
    let norm_margin = round_margin(component_norm, x.len().saturating_mul(4))?;
    Some(component_norm + norm_margin)
}

fn energy(k: &Matrix, a: &Matrix, alpha: &[f64], z: &[f64]) -> f64 {
    let kz = k.mul(z);
    let az = a.mul(z);
    0.5 * dot(z, &kz)
        + az.iter()
            .zip(alpha)
            .map(|(v, c)| c * logcosh(*v))
            .sum::<f64>()
}

fn discrete_gradient(k: &Matrix, a: &Matrix, alpha: &[f64], x: &[f64], y: &[f64]) -> Vec<f64> {
    let mid: Vec<f64> = x.iter().zip(y).map(|(u, v)| 0.5 * u + 0.5 * v).collect();
    let mut g = k.mul(&mid);
    let ax = a.mul(x);
    let ay = a.mul(y);
    for l in 0..a.rows {
        let coeff = alpha[l] * quotient(ax[l], ay[l]);
        for p in a.offsets[l] as usize..a.offsets[l + 1] as usize {
            g[a.indices[p] as usize] += coeff * a.values[p];
        }
    }
    g
}

/// One bounded batch of fixed-point iterations; the returned vector is the
/// caller's next iterate. Status 0 is diagnostic convergence, not certification.
/// Negative statuses: -1 invalid ABI/input, -2 numeric overflow, -3 q/domain,
/// -4 cancelled before output publication.
/// On failure output vector is untouched; result has deterministic status.
///
/// # Safety
/// Pointers must be aligned, live, non-overlapping and sized as declared.
unsafe fn step_impl(
    input: *const StepInput,
    output: *mut f64,
    output_len: u32,
    result: *mut StepResult,
    cancellation: Option<(&AtomicU32, u32)>,
) -> i32 {
    if input.is_null() || result.is_null() {
        return -1;
    }
    let inp = &*input;
    let out = &mut *result;
    *out = StepResult {
        struct_size: std::mem::size_of::<StepResult>() as u32,
        abi_version: ABI,
        status: -1,
        ..StepResult::default()
    };
    if cancellation
        .map(|(epoch, expected)| epoch.load(Ordering::Acquire) != expected)
        .unwrap_or(false)
    {
        out.status = -4;
        return -4;
    }
    let n = inp.n as usize;
    if inp.struct_size as usize != std::mem::size_of::<StepInput>()
        || inp.abi_version != ABI
        || n == 0
        || n > MAX_N
        || output_len as usize != n
        || output.is_null()
        || inp.previous.is_null()
        || inp.drive.is_null()
        || inp.iterate.is_null()
        || inp.a.rows as usize > MAX_N
        || inp.max_iterations == 0
        || inp.max_iterations > MAX_ITER
        || !inp.h.is_finite()
        || inp.h <= 0.0
        || !inp.tolerance.is_finite()
        || inp.tolerance <= 0.0
        || !inp.previous_error.is_finite()
        || inp.previous_error < 0.0
        || !inp.boundary_eta.is_finite()
        || inp.boundary_eta < 0.0
    {
        return -1;
    }
    let nnz = inp.k.nnz as usize + inp.r.nnz as usize + inp.j.nnz as usize + inp.a.nnz as usize;
    if nnz > MAX_NNZ {
        return -1;
    }
    let (Some(k), Some(r), Some(j), Some(a)) = (
        read_matrix(&inp.k, n, n),
        read_matrix(&inp.r, n, n),
        read_matrix(&inp.j, n, n),
        read_matrix(&inp.a, inp.a.rows as usize, n),
    ) else {
        return -1;
    };
    if !validate_structured(&k, 1.0)
        || !validate_structured(&r, 1.0)
        || !validate_structured(&j, -1.0)
    {
        return -1;
    }
    let alpha = if a.rows == 0 {
        &[]
    } else {
        if inp.alpha.is_null() {
            return -1;
        }
        slice::from_raw_parts(inp.alpha, a.rows)
    };
    let x = slice::from_raw_parts(inp.previous, n);
    let drive = slice::from_raw_parts(inp.drive, n);
    let mut y = slice::from_raw_parts(inp.iterate, n).to_vec();
    if alpha.iter().any(|v| !v.is_finite() || *v < 0.0)
        || x.iter().chain(drive).chain(&y).any(|v| !v.is_finite())
    {
        return -1;
    }
    let mut le = k.row_abs_max().max(k.col_abs_max(n));
    for l in 0..a.rows {
        let squared: f64 = (a.offsets[l] as usize..a.offsets[l + 1] as usize)
            .map(|p| a.values[p] * a.values[p])
            .sum();
        le += alpha[l] * squared;
    }
    let le_upper = le
        + round_margin(
            le.abs(),
            k.values
                .len()
                .saturating_add(a.values.len().saturating_mul(4)),
        )
        .unwrap_or(f64::INFINITY);
    let b_row_raw = j.row_abs_max() + r.row_abs_max();
    let b_col_raw = j.col_abs_max(n) + r.col_abs_max(n);
    let b_operations = j
        .values
        .len()
        .saturating_add(r.values.len())
        .saturating_mul(2);
    let b_row = b_row_raw + round_margin(b_row_raw.abs(), b_operations).unwrap_or(f64::INFINITY);
    let b_col = b_col_raw + round_margin(b_col_raw.abs(), b_operations).unwrap_or(f64::INFINITY);
    let b_norm_raw = (b_row * b_col).sqrt();
    let b_norm = b_norm_raw + round_margin(b_norm_raw.abs(), 8).unwrap_or(f64::INFINITY);
    let lipschitz_raw = b_norm * le_upper;
    let lipschitz = lipschitz_raw + round_margin(lipschitz_raw.abs(), 8).unwrap_or(f64::INFINITY);
    let q = inp.h * lipschitz / 2.0;
    let q_margin = round_margin(q.abs(), 8).unwrap_or(f64::INFINITY);
    let q_upper = q + q_margin;
    if !q_upper.is_finite() || q_upper > 0.8 {
        out.status = -3;
        return -3;
    }
    let mut used = 0;
    for _ in 0..inp.max_iterations {
        if cancellation
            .map(|(epoch, expected)| epoch.load(Ordering::Acquire) != expected)
            .unwrap_or(false)
        {
            out.status = -4;
            return -4;
        }
        let g = discrete_gradient(&k, &a, alpha, x, &y);
        let jg = j.mul(&g);
        let rg = r.mul(&g);
        let next: Vec<f64> = (0..n)
            .map(|i| x[i] + inp.h * (jg[i] - rg[i] + drive[i]))
            .collect();
        if next.iter().any(|v| !v.is_finite()) {
            out.status = -2;
            return -2;
        }
        y = next;
        used += 1;
    }
    let g = discrete_gradient(&k, &a, alpha, x, &y);
    let jg = j.mul(&g);
    let rg = r.mul(&g);
    let residual_vec: Vec<f64> = (0..n)
        .map(|i| y[i] - x[i] - inp.h * (jg[i] - rg[i] + drive[i]))
        .collect();
    let residual = norm(&residual_vec);
    let certified_scope = certifiable_quadratic_diagonal(&k, &r, &j, &a, inp.boundary_eta);
    let residual_roundoff = if certified_scope {
        diagonal_residual_roundoff(&k, &r, x, &y, drive, inp.h)
    } else {
        None
    };
    let iteration_nominal = (residual + residual_roundoff.unwrap_or(0.0)) / (1.0 - q_upper);
    let iteration_error = if certified_scope {
        iteration_nominal + round_margin(iteration_nominal.abs(), 8).unwrap_or(f64::INFINITY)
    } else {
        iteration_nominal
    };
    let gx = discrete_gradient(&k, &a, alpha, x, x);
    let jgx = j.mul(&gx);
    let rgx = r.mul(&gx);
    let dx: Vec<f64> = (0..n).map(|i| y[i] - x[i]).collect();
    let defect_vec: Vec<f64> = (0..n)
        .map(|i| dx[i] / inp.h - (jgx[i] - rgx[i] + drive[i]))
        .collect();
    let defect_roundoff = if certified_scope {
        round_margin(
            norm(&defect_vec) + lipschitz.abs() * norm(&dx) + norm(x) + norm(&y),
            n.saturating_mul(32),
        )
    } else {
        None
    };
    let defect = norm(&defect_vec)
        + lipschitz * norm(&dx)
        + inp.boundary_eta
        + defect_roundoff.unwrap_or(0.0);
    let lh = lipschitz * inp.h;
    let trajectory_nominal = (lh.exp() * inp.previous_error)
        + if lipschitz == 0.0 {
            inp.h * defect
        } else {
            lh.exp_m1() * defect / lipschitz
        };
    let trajectory = if certified_scope {
        trajectory_nominal
            + round_margin(
                trajectory_nominal.abs() + inp.previous_error + inp.h.abs() * defect,
                16,
            )
            .unwrap_or(f64::INFINITY)
    } else {
        trajectory_nominal
    };
    let e0 = energy(&k, &a, alpha, x);
    let e1 = energy(&k, &a, alpha, &y);
    let raw_balance =
        (e1 - e0) + inp.h * dot(&g, &rg) - inp.h * dot(&g, drive) - dot(&g, &residual_vec);
    let balance_roundoff = if certified_scope {
        round_margin(
            e0.abs()
                + e1.abs()
                + inp.h.abs() * (dot(&g, &rg).abs() + dot(&g, drive).abs())
                + dot(&g, &residual_vec).abs(),
            n.saturating_mul(48),
        )
    } else {
        None
    };
    let balance = if certified_scope {
        let balance_nominal = raw_balance.abs() + balance_roundoff.unwrap_or(0.0);
        balance_nominal + round_margin(balance_nominal, 8).unwrap_or(f64::INFINITY)
    } else {
        raw_balance
    };
    if [
        residual,
        iteration_error,
        defect,
        trajectory,
        e0,
        e1,
        balance,
    ]
    .iter()
    .any(|v| !v.is_finite())
    {
        out.status = -2;
        return -2;
    }
    ptr::copy_nonoverlapping(y.as_ptr(), output, n);
    *out = StepResult {
        struct_size: std::mem::size_of::<StepResult>() as u32,
        abi_version: ABI,
        status: if iteration_error <= inp.tolerance {
            0
        } else {
            1
        },
        iterations: used,
        certificate_flags: 0,
        residual,
        iteration_error,
        time_defect: defect,
        trajectory_error: trajectory,
        energy_before: e0,
        energy_after: e1,
        energy_balance_defect: balance,
        q_upper,
        boundary_eta: inp.boundary_eta,
    };
    // Keep all bounds diagnostic until independently verified outward interval
    // arithmetic encloses every intermediate operation and transcendental.
    out.certificate_flags = 0;
    out.status
}

/// ABI-compatible diagnostic step without a cancellation token.
///
/// # Safety
/// Follows [`step_impl`] pointer requirements.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_v2_step(
    input: *const StepInput,
    output: *mut f64,
    output_len: u32,
    result: *mut StepResult,
) -> i32 {
    step_impl(input, output, output_len, result, None)
}

/// Bounded step with an externally owned atomic cancellation epoch.
///
/// `cancel_epoch` must point to storage updated atomically by the host.  The
/// output vector is published only if the epoch stays equal to `expected_epoch`.
///
/// # Safety
/// In addition to [`step_impl`] requirements, `cancel_epoch` must be aligned,
/// live for the call and compatible with an atomic 32-bit unsigned integer.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_v2_step_cancelable(
    input: *const StepInput,
    output: *mut f64,
    output_len: u32,
    result: *mut StepResult,
    cancel_epoch: *const u32,
    expected_epoch: u32,
) -> i32 {
    if cancel_epoch.is_null() || (cancel_epoch as usize) % std::mem::align_of::<AtomicU32>() != 0 {
        if !result.is_null() {
            let out = &mut *result;
            *out = StepResult {
                struct_size: std::mem::size_of::<StepResult>() as u32,
                abi_version: ABI,
                status: -1,
                ..StepResult::default()
            };
        }
        return -1;
    }
    let cancellation = &*(cancel_epoch.cast::<AtomicU32>());
    step_impl(
        input,
        output,
        output_len,
        result,
        Some((cancellation, expected_epoch)),
    )
}

/// Propagate an already certified state-error envelope through an explicit
/// parameter/basis mapping.  This does not certify the mapping bounds supplied
/// by the caller.  Output is `[new_error_bound, nominal_energy_delta,
/// energy_delta_roundoff_bound]` and is untouched on rejection.
///
/// # Safety
/// `output` must be live, aligned, writable for three f64 values, and must not
/// overlap mutable storage used by another thread.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_v2_propagate_parameter_switch_bounds(
    previous_error: f64,
    mapping_lipschitz_bound: f64,
    mapping_error_bound: f64,
    energy_before: f64,
    energy_after: f64,
    output: *mut f64,
    output_len: u32,
) -> i32 {
    if output.is_null()
        || output_len != 3
        || !previous_error.is_finite()
        || previous_error < 0.0
        || !mapping_lipschitz_bound.is_finite()
        || mapping_lipschitz_bound < 0.0
        || !mapping_error_bound.is_finite()
        || mapping_error_bound < 0.0
        || !energy_before.is_finite()
        || !energy_after.is_finite()
    {
        return -1;
    }
    let mapped_nominal = mapping_lipschitz_bound * previous_error + mapping_error_bound;
    let Some(mapped_roundoff) = round_margin(
        mapping_lipschitz_bound * previous_error.abs() + mapping_error_bound,
        4,
    ) else {
        return -2;
    };
    let energy_delta = energy_after - energy_before;
    let Some(energy_delta_roundoff) = round_margin(energy_before.abs() + energy_after.abs(), 2)
    else {
        return -2;
    };
    let mapped_bound = mapped_nominal + mapped_roundoff;
    if !mapped_bound.is_finite() || !energy_delta.is_finite() {
        return -2;
    }
    slice::from_raw_parts_mut(output, 3).copy_from_slice(&[
        mapped_bound,
        energy_delta,
        energy_delta_roundoff,
    ]);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csr(rows: u32, cols: u32, offsets: &[u32], indices: &[u32], values: &[f64]) -> Csr {
        Csr {
            rows,
            cols,
            nnz: values.len() as u32,
            offsets: offsets.as_ptr(),
            indices: indices.as_ptr(),
            values: values.as_ptr(),
        }
    }

    #[test]
    fn nonlinear_scalar_matches_independent_bisection_and_continues() {
        let offs = [0, 1];
        let inds = [0];
        let kval = [2.0];
        let rval = [1.0];
        let joffs = [0, 0];
        let empty_i: [u32; 0] = [];
        let empty_v: [f64; 0] = [];
        let aval = [1.0];
        let alpha = [0.5];
        let x = [0.4];
        let drive = [0.0];
        let mut current = x;
        let mut out = [0.0];
        let mut result = StepResult::default();
        let mut input = StepInput {
            struct_size: std::mem::size_of::<StepInput>() as u32,
            abi_version: 2,
            n: 1,
            k: csr(1, 1, &offs, &inds, &kval),
            r: csr(1, 1, &offs, &inds, &rval),
            j: csr(1, 1, &joffs, &empty_i, &empty_v),
            a: csr(1, 1, &offs, &inds, &aval),
            alpha: alpha.as_ptr(),
            previous: x.as_ptr(),
            drive: drive.as_ptr(),
            iterate: current.as_ptr(),
            h: 0.1,
            previous_error: 0.0,
            max_iterations: 1,
            tolerance: 1e-12,
            boundary_eta: 0.0,
        };
        for _ in 0..20 {
            input.iterate = current.as_ptr();
            let status = unsafe { sylanne3_v2_step(&input, &mut out[0], 1, &mut result) };
            assert!(status == 0 || status == 1);
            current = out;
            if status == 0 {
                break;
            }
        }
        assert_eq!(result.status, 0);
        let mut lo = 0.0;
        let mut hi = x[0];
        for _ in 0..100 {
            let mid = (lo + hi) / 2.0;
            let f = mid - x[0]
                + 0.1 * (x[0] + mid + 0.5 * (logcosh(mid) - logcosh(x[0])) / (mid - x[0]));
            if f > 0.0 {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        assert!((out[0] - (lo + hi) / 2.0).abs() < 1e-12);
        assert!(result.energy_after < result.energy_before);
        assert!(result.energy_balance_defect.abs() < 1e-12);
        assert_eq!(result.certificate_flags, 0);
    }

    #[test]
    fn coupled_sparse_and_domain_rejections() {
        let off = [0, 2, 4];
        let ind = [0, 1, 0, 1];
        let kval = [2.0, -0.5, -0.5, 2.0];
        let rval = [1.0, 0.0, 0.0, 1.0];
        let jval = [0.0, 0.2, -0.2, 0.0];
        let aoff = [0, 2];
        let aind = [0, 1];
        let aval = [1.0, -1.0];
        let alpha = [0.3];
        let x = [0.4, -0.2];
        let drive = [0.0, 0.0];
        let mut y = [0.0; 2];
        let mut result = StepResult::default();
        let mut input = StepInput {
            struct_size: std::mem::size_of::<StepInput>() as u32,
            abi_version: 2,
            n: 2,
            k: csr(2, 2, &off, &ind, &kval),
            r: csr(2, 2, &off, &ind, &rval),
            j: csr(2, 2, &off, &ind, &jval),
            a: csr(1, 2, &aoff, &aind, &aval),
            alpha: alpha.as_ptr(),
            previous: x.as_ptr(),
            drive: drive.as_ptr(),
            iterate: x.as_ptr(),
            h: 0.1,
            previous_error: 0.0,
            max_iterations: 30,
            tolerance: 1e-10,
            boundary_eta: 0.0,
        };
        assert_eq!(
            unsafe { sylanne3_v2_step(&input, y.as_mut_ptr(), 2, &mut result) },
            0
        );
        assert!(result.residual < 1e-10 && result.energy_after < result.energy_before);
        assert!(result.time_defect > 0.0 && result.trajectory_error >= result.time_defect * 0.1);
        let saved = y;
        input.h = 10.0;
        assert_eq!(
            unsafe { sylanne3_v2_step(&input, y.as_mut_ptr(), 2, &mut result) },
            -3
        );
        assert_eq!(y, saved);
        input.h = 0.1;
        let nan = [f64::NAN, 0.0];
        input.drive = nan.as_ptr();
        assert_eq!(
            unsafe { sylanne3_v2_step(&input, y.as_mut_ptr(), 2, &mut result) },
            -1
        );
        input.drive = drive.as_ptr();
        let bad_j = [0.0, 0.2, 0.2, 0.0];
        input.j = csr(2, 2, &off, &ind, &bad_j);
        assert_eq!(
            unsafe { sylanne3_v2_step(&input, y.as_mut_ptr(), 2, &mut result) },
            -1
        );
    }

    #[test]
    fn diagonal_quadratic_scope_reports_diagnostic_endpoint_bounds() {
        let offs = [0, 1];
        let inds = [0];
        let kval = [2.0];
        let rval = [1.0];
        let joff = [0, 0];
        let aoff = [0];
        let empty_i: [u32; 0] = [];
        let empty_v: [f64; 0] = [];
        let x = [0.4];
        let drive = [0.1];
        let mut iterate = x;
        let mut out = [0.0];
        let mut result = StepResult::default();
        let mut input = StepInput {
            struct_size: std::mem::size_of::<StepInput>() as u32,
            abi_version: 2,
            n: 1,
            k: csr(1, 1, &offs, &inds, &kval),
            r: csr(1, 1, &offs, &inds, &rval),
            j: csr(1, 1, &joff, &empty_i, &empty_v),
            a: csr(0, 1, &aoff, &empty_i, &empty_v),
            alpha: std::ptr::null(),
            previous: x.as_ptr(),
            drive: drive.as_ptr(),
            iterate: iterate.as_ptr(),
            h: 0.1,
            previous_error: 0.0,
            max_iterations: 2,
            tolerance: 1e-12,
            boundary_eta: 0.0,
        };
        for _ in 0..24 {
            input.iterate = iterate.as_ptr();
            let status = unsafe { sylanne3_v2_step(&input, out.as_mut_ptr(), 1, &mut result) };
            assert!(status == 0 || status == 1);
            iterate = out;
            if status == 0 {
                break;
            }
        }
        assert_eq!(result.status, 0);
        assert_eq!(result.certificate_flags, 0);
        let discrete_exact = (x[0] * (1.0 - 0.1) + 0.1 * drive[0]) / (1.0 + 0.1);
        assert!((out[0] - discrete_exact).abs() <= result.iteration_error);
        let equilibrium = drive[0] / 2.0;
        let continuous_exact = equilibrium + (x[0] - equilibrium) * (-0.2_f64).exp();
        assert!((out[0] - continuous_exact).abs() <= result.trajectory_error);
        assert!(result.energy_balance_defect >= 0.0);
    }

    #[test]
    fn small_spacing_quotient_matches_independent_quadrature() {
        for (u, v) in [
            (0.7, 0.7 + 1e-12),
            (-0.4, -0.4 + 1e-7),
            (-1.0, 0.3),
            (22.0, 22.5),
        ] as [(f64, f64); 4]
        {
            let panels = 20_000usize;
            let step = 1.0 / panels as f64;
            let mut sum = u.tanh() + v.tanh();
            for panel in 1..panels {
                let s = panel as f64 * step;
                let weight = if panel % 2 == 0 { 2.0 } else { 4.0 };
                sum += weight * (u + s * (v - u)).tanh();
            }
            let reference = sum * step / 3.0;
            assert!((quotient(u, v) - reference).abs() < 2e-12, "u={u}, v={v}");
        }
    }

    #[test]
    fn boundary_or_nonlinearity_stays_outside_certified_scope() {
        let offs = [0, 1];
        let inds = [0];
        let kval = [2.0];
        let rval = [1.0];
        let joff = [0, 0];
        let aoff = [0];
        let empty_i: [u32; 0] = [];
        let empty_v: [f64; 0] = [];
        let x = [0.4];
        let drive = [0.0];
        let mut out = [9.0];
        let mut result = StepResult::default();
        let input = StepInput {
            struct_size: std::mem::size_of::<StepInput>() as u32,
            abi_version: 2,
            n: 1,
            k: csr(1, 1, &offs, &inds, &kval),
            r: csr(1, 1, &offs, &inds, &rval),
            j: csr(1, 1, &joff, &empty_i, &empty_v),
            a: csr(0, 1, &aoff, &empty_i, &empty_v),
            alpha: std::ptr::null(),
            previous: x.as_ptr(),
            drive: drive.as_ptr(),
            iterate: x.as_ptr(),
            h: 0.1,
            previous_error: 0.0,
            max_iterations: 40,
            tolerance: 1e-10,
            boundary_eta: 1e-6,
        };
        assert_eq!(
            unsafe { sylanne3_v2_step(&input, out.as_mut_ptr(), 1, &mut result) },
            0
        );
        assert_eq!(result.certificate_flags, 0);
    }

    #[test]
    fn cancellation_is_checked_before_output_and_between_iterations() {
        let offs = [0, 1];
        let inds = [0];
        let kval = [2.0];
        let rval = [1.0];
        let joff = [0, 0];
        let aoff = [0];
        let empty_i: [u32; 0] = [];
        let empty_v: [f64; 0] = [];
        let x = [0.4];
        let drive = [0.0];
        let input = StepInput {
            struct_size: std::mem::size_of::<StepInput>() as u32,
            abi_version: 2,
            n: 1,
            k: csr(1, 1, &offs, &inds, &kval),
            r: csr(1, 1, &offs, &inds, &rval),
            j: csr(1, 1, &joff, &empty_i, &empty_v),
            a: csr(0, 1, &aoff, &empty_i, &empty_v),
            alpha: std::ptr::null(),
            previous: x.as_ptr(),
            drive: drive.as_ptr(),
            iterate: x.as_ptr(),
            h: 0.1,
            previous_error: 0.0,
            max_iterations: 40,
            tolerance: 1e-12,
            boundary_eta: 0.0,
        };
        let cancel_epoch = std::sync::atomic::AtomicU32::new(2);
        let mut out = [123.0];
        let mut result = StepResult::default();
        let status = unsafe {
            sylanne3_v2_step_cancelable(
                &input,
                out.as_mut_ptr(),
                1,
                &mut result,
                cancel_epoch.as_ptr(),
                1,
            )
        };
        assert_eq!(status, -4);
        assert_eq!(result.status, -4);
        assert_eq!(out, [123.0]);
    }

    #[test]
    fn parameter_switch_propagates_old_error_or_rejects_unknown_bounds() {
        let mut output = [0.0; 3];
        let status = unsafe {
            sylanne3_v2_propagate_parameter_switch_bounds(
                0.1,
                3.0,
                0.02,
                2.0,
                1.5,
                output.as_mut_ptr(),
                output.len() as u32,
            )
        };
        assert_eq!(status, 0);
        assert!(output[0] >= 0.32);
        assert_eq!(output[1], -0.5);
        assert!(output[2] > 0.0);
        let saved = output;
        assert_eq!(
            unsafe {
                sylanne3_v2_propagate_parameter_switch_bounds(
                    0.1,
                    f64::NAN,
                    0.02,
                    2.0,
                    1.5,
                    output.as_mut_ptr(),
                    output.len() as u32,
                )
            },
            -1
        );
        assert_eq!(output, saved);
    }

    #[test]
    fn supported_flag_mask_is_explicit_and_csr_rejects_misaligned_offsets() {
        assert_eq!(sylanne3_v2_supported_certificate_flags(), 0);
        let bytes = [0u8; 16];
        let indices = [0u32];
        let values = [1.0f64];
        let malformed = Csr {
            rows: 1,
            cols: 1,
            nnz: 1,
            offsets: unsafe { bytes.as_ptr().add(1).cast::<u32>() },
            indices: indices.as_ptr(),
            values: values.as_ptr(),
        };
        assert!(unsafe { read_matrix(&malformed, 1, 1) }.is_none());
    }
}
