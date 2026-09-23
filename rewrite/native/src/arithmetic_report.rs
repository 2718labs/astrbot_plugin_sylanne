//! Version 1 mathematical-input arithmetic report. This is not an ABI2 step
//! certificate or product receipt. The caller owns all input buffers for the
//! entire synchronous call and must not mutate them or overlap the output.
use crate::interval::Interval;
use crate::interval_verifier::{
    linear_readout, verify_joint_error_bounds, verify_joint_step, JointVerificationInput,
    SparseMatrix,
};
use sha2::{Digest, Sha256};
use std::{mem, ptr, slice};

const VERSION: u32 = 1;
const MAX_N: usize = 64;
const MAX_NNZ: usize = 4_096;

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
