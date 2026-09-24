//! Version 1 mathematical-input arithmetic reports. These are not ABI2 step
//! certificates or product receipts. The caller owns all input buffers for the
//! entire synchronous call and must not mutate them or overlap the output.
use crate::interval::Interval;
use crate::interval_verifier::{
    linear_readout, verify_fixed_trajectory, verify_fixed_trajectory_from_error,
    verify_joint_error_bounds, verify_joint_step, JointVerificationInput, SparseMatrix,
};
use sha2::{Digest, Sha256};
use std::{mem, ptr, slice};

const VERSION: u32 = 1;
const MAX_N: usize = 64;
const MAX_NNZ: usize = 4_096;
const MAX_TRAJECTORY_STEPS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReportCsr {
    rows: u32,
    cols: u32,
    nnz: u32,
    offsets: *const u32,
    indices: *const u32,
    values: *const f64,
}

#[repr(C)]
pub struct ReportInput {
    struct_size: u32,
    version: u32,
    n: u32,
    k: ReportCsr,
    r: ReportCsr,
    j: ReportCsr,
    a: ReportCsr,
    alpha: *const f64,
    x: *const f64,
    y: *const f64,
    drive: *const f64,
    readout: *const f64,
    h: f64,
    inherited_error_upper: f64,
    threshold: f64,
    cancelled: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ReportInterval {
    lower: f64,
    upper: f64,
}

impl From<Interval> for ReportInterval {
    fn from(value: Interval) -> Self {
        Self {
            lower: value.lower(),
            upper: value.upper(),
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub struct ArithmeticReport {
    struct_size: u32,
    version: u32,
    status: i32, // 0 arithmetic success; -1 layout/input; -2 numerical rejection; -3 cancelled
    product_certificate_flags: u32, // permanently zero for this report version
    input_sha256: [u8; 32],
    energy_difference: ReportInterval,
    gradient_displacement: ReportInterval,
    dissipation: ReportInterval,
    drive_work: ReportInterval,
    residual_work: ReportInterval,
    gradient_identity_defect: ReportInterval,
    energy_balance_defect: ReportInterval,
    residual_norm: ReportInterval,
    endpoint_error: ReportInterval,
    reconstruction_defect: ReportInterval,
    time_error: ReportInterval,
    readout_point: ReportInterval,
    readout_enclosure: ReportInterval,
    threshold_relation: i32,
}

/// One mathematical step of the received fixed CSR block. The first x is the
/// mathematical initial condition; the native verifier checks all later x/y
/// links and derives every inherited error itself.
#[repr(C)]
pub struct TrajectoryMathStep {
    struct_size: u32,
    version: u32,
    n: u32,
    k: ReportCsr,
    r: ReportCsr,
    j: ReportCsr,
    a: ReportCsr,
    alpha: *const f64,
    x: *const f64,
    y: *const f64,
    drive: *const f64,
    h: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TrajectoryMathReport {
    struct_size: u32,
    version: u32,
    status: i32, // 0 mathematical success; -1 layout/input; -2 numerical rejection
    product_certificate_flags: u32, // always zero: external source and graph closure unverified
    steps_verified: u32,
    input_sha256: [u8; 32],
    final_time_error: ReportInterval,
    max_endpoint_error: ReportInterval,
    max_reconstruction_defect: ReportInterval,
}

#[no_mangle]
pub extern "C" fn sylanne3_arithmetic_report_version() -> u32 {
    VERSION
}

fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && (pointer as usize) % mem::align_of::<T>() == 0
}

// SAFETY: the caller promises live readable storage of the declared length.
unsafe fn vector<'a>(pointer: *const f64, length: usize) -> Option<&'a [f64]> {
    if length == 0 {
        return Some(&[]);
    }
    if !aligned(pointer) {
        return None;
    }
    Some(slice::from_raw_parts(pointer, length))
}

// SAFETY: the caller promises live readable CSR buffers and no mutation.
unsafe fn matrix<'a>(raw: ReportCsr, rows: usize, cols: usize) -> Option<SparseMatrix<'a>> {
    let nnz = raw.nnz as usize;
    if raw.rows as usize != rows
        || raw.cols as usize != cols
        || nnz > MAX_NNZ
        || !aligned(raw.offsets)
        || (nnz > 0 && (!aligned(raw.indices) || !aligned(raw.values)))
    {
        return None;
    }
    let offsets = slice::from_raw_parts(raw.offsets, rows + 1);
    let indices = if nnz == 0 {
        &[]
    } else {
        slice::from_raw_parts(raw.indices, nnz)
    };
    let values = vector(raw.values, nnz)?;
    Some(SparseMatrix::new(rows, cols, offsets, indices, values))
}

fn hash_u32(hash: &mut Sha256, value: u32) {
    hash.update(value.to_le_bytes());
}
fn hash_f64(hash: &mut Sha256, value: f64) {
    hash.update(value.to_bits().to_le_bytes());
}
fn hash_vector(hash: &mut Sha256, values: &[f64]) {
    hash_u32(hash, values.len() as u32);
    for &value in values {
        hash_f64(hash, value);
    }
}
fn hash_matrix(hash: &mut Sha256, raw: ReportCsr, matrix: SparseMatrix<'_>) {
    hash_u32(hash, raw.rows);
    hash_u32(hash, raw.cols);
    hash_u32(hash, raw.nnz);
    // Matrix slices were validated and borrowed above; raw pointers remain live.
    let offsets = unsafe { slice::from_raw_parts(raw.offsets, raw.rows as usize + 1) };
    let indices = if raw.nnz == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(raw.indices, raw.nnz as usize) }
    };
    let values = if raw.nnz == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(raw.values, raw.nnz as usize) }
    };
    let _ = matrix;
    for &value in offsets {
        hash_u32(hash, value);
    }
    for &value in indices {
        hash_u32(hash, value);
    }
    hash_vector(hash, values);
}

/// # Safety
/// Both structs and all pointer buffers must be live, aligned, non-overlapping,
/// and immutable (except the exclusive output) through this synchronous call.
/// Invalid pointer provenance cannot be detected by a C ABI. `input_size` and
/// `output_size` must exactly match this version's layouts.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_arithmetic_report_v1(
    input: *const ReportInput,
    input_size: u32,
    output: *mut ArithmeticReport,
    output_size: u32,
) -> i32 {
    if !aligned(output) || output_size as usize != mem::size_of::<ArithmeticReport>() {
        return -1;
    }
    let mut report = ArithmeticReport {
        struct_size: mem::size_of::<ArithmeticReport>() as u32,
        version: VERSION,
        status: -1,
        ..ArithmeticReport::default()
    };
    // Reset before every attempt so a failed/cancelled call cannot reuse success.
    ptr::write(
        output,
        ArithmeticReport {
            struct_size: mem::size_of::<ArithmeticReport>() as u32,
            version: VERSION,
            status: -1,
            ..ArithmeticReport::default()
        },
    );
    if !aligned(input) || input_size as usize != mem::size_of::<ReportInput>() {
        return -1;
    }
    let raw = &*input;
    if raw.struct_size as usize != mem::size_of::<ReportInput>()
        || raw.version != VERSION
        || !(1..=MAX_N).contains(&(raw.n as usize))
        || raw.a.rows as usize > MAX_N
    {
        return -1;
    }
    if raw.cancelled != 0 {
        report.status = -3;
        ptr::write(output, report);
        return -3;
    }
    let n = raw.n as usize;
    let Some(k) = matrix(raw.k, n, n) else {
        return -1;
    };
    let Some(r) = matrix(raw.r, n, n) else {
        return -1;
    };
    let Some(j) = matrix(raw.j, n, n) else {
        return -1;
    };
    let Some(a) = matrix(raw.a, raw.a.rows as usize, n) else {
        return -1;
    };
    let Some(alpha) = vector(raw.alpha, raw.a.rows as usize) else {
        return -1;
    };
    let Some(x) = vector(raw.x, n) else {
        return -1;
    };
    let Some(y) = vector(raw.y, n) else {
        return -1;
    };
    let Some(drive) = vector(raw.drive, n) else {
        return -1;
    };
    let Some(c) = vector(raw.readout, n) else {
        return -1;
    };
    let numeric = JointVerificationInput {
        k,
        r,
        j,
        a,
        alpha,
        x,
        y,
        h: raw.h,
        drive,
    };
    let bounds = crate::interval::Interval::new(0.0, raw.inherited_error_upper);
    let computed = bounds.ok().and_then(|inherited| {
        let envelope = verify_joint_step(&numeric).ok()?;
        let error = verify_joint_error_bounds(&numeric, inherited).ok()?;
        let readout = linear_readout(y, c, error.time_error.upper(), raw.threshold).ok()?;
        Some((envelope, error, readout))
    });
    let Some((envelope, error, readout)) = computed else {
        report.status = -2;
        ptr::write(output, report);
        return -2;
    };
    let mut hash = Sha256::new();
    hash.update(b"sylanne3-arithmetic-report-v1\0");
    hash_u32(&mut hash, raw.n);
    for (wire, matrix) in [(raw.k, k), (raw.r, r), (raw.j, j), (raw.a, a)] {
        hash_matrix(&mut hash, wire, matrix);
    }
    for vector in [alpha, x, y, drive, c] {
        hash_vector(&mut hash, vector);
    }
    for value in [raw.h, raw.inherited_error_upper, raw.threshold] {
        hash_f64(&mut hash, value);
    }
    report.input_sha256.copy_from_slice(&hash.finalize());
    report.energy_difference = envelope.energy_difference.into();
    report.gradient_displacement = envelope.gradient_displacement.into();
    report.dissipation = envelope.dissipation.into();
    report.drive_work = envelope.drive_work.into();
    report.residual_work = envelope.residual_work.into();
    report.gradient_identity_defect = envelope.gradient_identity_defect.into();
    report.energy_balance_defect = envelope.energy_balance_defect.into();
    report.residual_norm = envelope.residual_norm.into();
    report.endpoint_error = error.endpoint_error.into();
    report.reconstruction_defect = error.reconstruction_defect.into();
    report.time_error = error.time_error.into();
    report.readout_point = readout.point.into();
    report.readout_enclosure = readout.enclosure.into();
    report.threshold_relation = readout.threshold_relation;
    report.status = 0;
    ptr::write(output, report);
    0
}

/// Recheck a bounded fixed-model mathematical trajectory with no caller-supplied
/// inherited error. This report binds the checked bytes but does not establish
/// the initial state's external origin or whole-graph closure.
///
/// # Safety
/// The step array and all referenced buffers must remain live, aligned and
/// immutable through the call. Output must be exclusive and non-overlapping.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_v2_trajectory_math_report_v1(
    steps: *const TrajectoryMathStep,
    step_count: u32,
    output: *mut TrajectoryMathReport,
    output_size: u32,
) -> i32 {
    trajectory_math_report_impl(steps, step_count, None, output, output_size)
}

/// Recheck a linked fixed-model trajectory from a supplied initial state-error
/// upper bound. The caller must independently establish that bound's source.
/// The mathematical input digest includes this bound. Product flags stay zero.
///
/// # Safety
/// Follows [`sylanne3_v2_trajectory_math_report_v1`] pointer requirements.
#[no_mangle]
pub unsafe extern "C" fn sylanne3_v2_trajectory_math_report_from_error_v1(
    steps: *const TrajectoryMathStep,
    step_count: u32,
    initial_error_upper: f64,
    output: *mut TrajectoryMathReport,
    output_size: u32,
) -> i32 {
    trajectory_math_report_impl(
        steps,
        step_count,
        Some(initial_error_upper),
        output,
        output_size,
    )
}

unsafe fn trajectory_math_report_impl(
    steps: *const TrajectoryMathStep,
    step_count: u32,
    initial_error_upper: Option<f64>,
    output: *mut TrajectoryMathReport,
    output_size: u32,
) -> i32 {
    if !aligned(output) || output_size as usize != mem::size_of::<TrajectoryMathReport>() {
        return -1;
    }
    let mut report = TrajectoryMathReport {
        struct_size: mem::size_of::<TrajectoryMathReport>() as u32,
        version: VERSION,
        status: -1,
        ..TrajectoryMathReport::default()
    };
    ptr::write(output, report);
    if !aligned(steps) || !(1..=MAX_TRAJECTORY_STEPS).contains(&(step_count as usize)) {
        return -1;
    }
    let raw_steps = slice::from_raw_parts(steps, step_count as usize);
    let mut numerical_steps = Vec::with_capacity(raw_steps.len());
    for raw in raw_steps {
        let n = raw.n as usize;
        if raw.struct_size as usize != mem::size_of::<TrajectoryMathStep>()
            || raw.version != VERSION
            || !(1..=MAX_N).contains(&n)
            || raw.a.rows as usize > MAX_N
        {
            return -1;
        }
        let (Some(k), Some(r), Some(j), Some(a)) = (
            matrix(raw.k, n, n),
            matrix(raw.r, n, n),
            matrix(raw.j, n, n),
            matrix(raw.a, raw.a.rows as usize, n),
        ) else {
            return -1;
        };
        let (Some(alpha), Some(x), Some(y), Some(drive)) = (
            vector(raw.alpha, raw.a.rows as usize),
            vector(raw.x, n),
            vector(raw.y, n),
            vector(raw.drive, n),
        ) else {
            return -1;
        };
        numerical_steps.push(JointVerificationInput {
            k,
            r,
            j,
            a,
            alpha,
            x,
            y,
            h: raw.h,
            drive,
        });
    }
    let verified = match initial_error_upper {
        Some(error) => Interval::new(0.0, error)
            .ok()
            .and_then(|bound| verify_fixed_trajectory_from_error(&numerical_steps, bound).ok()),
        None => verify_fixed_trajectory(&numerical_steps).ok(),
    };
    let Some(verified) = verified else {
        report.status = -2;
        ptr::write(output, report);
        return -2;
    };
    let max_endpoint = verified
        .steps
        .iter()
        .map(|step| step.endpoint_error.upper())
        .fold(0.0_f64, f64::max);
    let max_defect = verified
        .steps
        .iter()
        .map(|step| step.reconstruction_defect.upper())
        .fold(0.0_f64, f64::max);
    report.steps_verified = step_count;
    report.input_sha256 = verified.input_sha256;
    report.final_time_error = verified.final_time_error.into();
    report.max_endpoint_error = ReportInterval {
        lower: 0.0,
        upper: max_endpoint,
    };
    report.max_reconstruction_defect = ReportInterval {
        lower: 0.0,
        upper: max_defect,
    };
    report.status = 0;
    ptr::write(output, report);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_trajectory_derives_history_and_rejects_forged_link() {
        let offsets = [0, 1];
        let indices = [0];
        let values = [1.0];
        let empty_offsets = [0, 0];
        let empty_a_offsets = [0];
        let positive = ReportCsr {
            rows: 1,
            cols: 1,
            nnz: 1,
            offsets: offsets.as_ptr(),
            indices: indices.as_ptr(),
            values: values.as_ptr(),
        };
        let empty = ReportCsr {
            rows: 1,
            cols: 1,
            nnz: 0,
            offsets: empty_offsets.as_ptr(),
            indices: ptr::null(),
            values: ptr::null(),
        };
        let no_nonlinear = ReportCsr {
            rows: 0,
            cols: 1,
            nnz: 0,
            offsets: empty_a_offsets.as_ptr(),
            indices: ptr::null(),
            values: ptr::null(),
        };
        let x0 = [1.0];
        let y0 = [0.9];
        let x1 = [0.9];
        let y1 = [0.82];
        let changed_y1 = [0.83];
        let drive = [0.0];
        let step = |x: &[f64; 1], y: &[f64; 1]| TrajectoryMathStep {
            struct_size: mem::size_of::<TrajectoryMathStep>() as u32,
            version: VERSION,
            n: 1,
            k: positive,
            r: positive,
            j: empty,
            a: no_nonlinear,
            alpha: ptr::null(),
            x: x.as_ptr(),
            y: y.as_ptr(),
            drive: drive.as_ptr(),
            h: 0.1,
        };
        let mut steps = [step(&x0, &y0), step(&x1, &y1)];
        let mut report = TrajectoryMathReport::default();
        let size = mem::size_of::<TrajectoryMathReport>() as u32;
        assert_eq!(
            unsafe { sylanne3_v2_trajectory_math_report_v1(steps.as_ptr(), 2, &mut report, size) },
            0
        );
        assert_eq!(report.product_certificate_flags, 0);
        assert_eq!(report.steps_verified, 2);
        assert!(report.final_time_error.upper >= (0.82 - (-0.2_f64).exp()).abs());
        assert!(report.max_endpoint_error.upper > 0.0);
        let mut reset_report = TrajectoryMathReport::default();
        assert_eq!(
            unsafe {
                sylanne3_v2_trajectory_math_report_v1(
                    steps.as_ptr().add(1),
                    1,
                    &mut reset_report,
                    size,
                )
            },
            0
        );
        assert!(report.final_time_error.upper > reset_report.final_time_error.upper);
        let original_hash = report.input_sha256;
        let mut inherited = TrajectoryMathReport::default();
        assert_eq!(
            unsafe {
                sylanne3_v2_trajectory_math_report_from_error_v1(
                    steps.as_ptr(),
                    2,
                    0.01,
                    &mut inherited,
                    size,
                )
            },
            0
        );
        assert_eq!(inherited.product_certificate_flags, 0);
        assert!(inherited.final_time_error.upper > report.final_time_error.upper);
        assert!(inherited.final_time_error.upper >= (0.82 - 1.01 * (-0.2_f64).exp()).abs());
        assert_ne!(inherited.input_sha256, original_hash);
        let inherited_hash = inherited.input_sha256;
        assert_eq!(
            unsafe {
                sylanne3_v2_trajectory_math_report_from_error_v1(
                    steps.as_ptr(),
                    2,
                    0.02,
                    &mut inherited,
                    size,
                )
            },
            0
        );
        assert_ne!(inherited.input_sha256, inherited_hash);
        assert_eq!(
            unsafe {
                sylanne3_v2_trajectory_math_report_from_error_v1(
                    steps.as_ptr(),
                    2,
                    -1.0,
                    &mut inherited,
                    size,
                )
            },
            -2
        );
        assert_eq!(inherited.product_certificate_flags, 0);
        assert_eq!(inherited.steps_verified, 0);
        assert_eq!(inherited.input_sha256, [0; 32]);
        steps[1].y = changed_y1.as_ptr();
        assert_eq!(
            unsafe { sylanne3_v2_trajectory_math_report_v1(steps.as_ptr(), 2, &mut report, size) },
            0
        );
        assert_ne!(report.input_sha256, original_hash);

        steps[1].x = x0.as_ptr();
        assert_eq!(
            unsafe { sylanne3_v2_trajectory_math_report_v1(steps.as_ptr(), 2, &mut report, size) },
            -2
        );
        assert_eq!(report.product_certificate_flags, 0);
        assert_eq!(report.steps_verified, 0);
        assert_eq!(report.input_sha256, [0; 32]);
    }
}
