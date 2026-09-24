//! Independent outward-interval verification kernel for the bounded ABI 2
//! sparse nonlinear step. ABI 2 uses it for a fixed complete block certificate.

use crate::interval::{environment_supported, Interval, IntervalError};
use sha2::{Digest, Sha256};

pub(crate) const MAX_VERIFIED_N: usize = 64;
const MAX_VERIFIED_A_ROWS: usize = 64;
const MAX_MATRIX_NNZ: usize = 4_096;
const MAX_TOTAL_NNZ: usize = 16_384;
const MAX_ABS_INPUT: f64 = 1.0e6;
const MAX_STEP: f64 = 1.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatrixRole {
    K,
    R,
    J,
    A,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VerifierError {
    UnsupportedEnvironment,
    InvalidDimension,
    CapacityExceeded,
    InvalidCsr(MatrixRole),
    CoefficientOutOfRange(MatrixRole),
    InvalidStructure(MatrixRole),
    PositivityNotProven(MatrixRole),
    InvalidAlpha,
    InvalidState,
    InvalidStep,
    InvalidInheritedError,
    TrajectorySourceMismatch,
    ContractionNotProven,
    TemporalBoundUnavailable,
    NonlinearArgumentOutOfRange,
    Arithmetic(IntervalError),
}

impl From<IntervalError> for VerifierError {
    fn from(value: IntervalError) -> Self {
        Self::Arithmetic(value)
    }
}

/// Borrowed canonical CSR matrix. Construction is cheap; [`verify_joint_step`]
/// performs all shape, ordering, coefficient and structure checks independently.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SparseMatrix<'a> {
    rows: usize,
    cols: usize,
    offsets: &'a [u32],
    indices: &'a [u32],
    values: &'a [f64],
}

impl<'a> SparseMatrix<'a> {
    pub(crate) fn new(
        rows: usize,
        cols: usize,
        offsets: &'a [u32],
        indices: &'a [u32],
        values: &'a [f64],
    ) -> Self {
        Self {
            rows,
            cols,
            offsets,
            indices,
            values,
        }
    }

    fn row_range(self, row: usize) -> std::ops::Range<usize> {
        self.offsets[row] as usize..self.offsets[row + 1] as usize
    }

    fn entry(self, row: usize, column: usize) -> Option<f64> {
        let range = self.row_range(row);
        self.indices[range.clone()]
            .binary_search(&(column as u32))
            .ok()
            .map(|position| self.values[range.start + position])
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct JointVerificationInput<'a> {
    pub(crate) k: SparseMatrix<'a>,
    pub(crate) r: SparseMatrix<'a>,
    pub(crate) j: SparseMatrix<'a>,
    pub(crate) a: SparseMatrix<'a>,
    pub(crate) alpha: &'a [f64],
    pub(crate) x: &'a [f64],
    pub(crate) y: &'a [f64],
    pub(crate) h: f64,
    pub(crate) drive: &'a [f64],
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct OperatorBounds {
    pub(crate) k_coercivity_lower: f64,
    pub(crate) r_coercivity_lower: f64,
    pub(crate) k_row_abs_upper: f64,
    pub(crate) r_row_abs_upper: f64,
    pub(crate) j_row_abs_upper: f64,
    pub(crate) jr_operator_norm_upper: f64,
    pub(crate) a_row_abs_upper: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct JointVerificationEnvelope {
    pub(crate) gradient: Vec<Interval>,
    pub(crate) residual_components: Vec<Interval>,
    pub(crate) residual_norm: Interval,
    pub(crate) energy_before: Interval,
    pub(crate) energy_after: Interval,
    pub(crate) energy_difference: Interval,
    pub(crate) gradient_displacement: Interval,
    pub(crate) dissipation: Interval,
    pub(crate) drive_work: Interval,
    pub(crate) residual_work: Interval,
    pub(crate) gradient_identity_defect: Interval,
    pub(crate) energy_balance_defect: Interval,
    pub(crate) operator_bounds: OperatorBounds,
}

/// Conservative bounds for one complete, fixed-parameter coupled step.
/// ABI 2 can publish these bounds when all fixed-block certificate gates pass.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct JointErrorBounds {
    pub(crate) gradient_lipschitz_upper: f64,
    pub(crate) vector_field_lipschitz_upper: f64,
    pub(crate) contraction_upper: f64,
    pub(crate) endpoint_error: Interval,
    pub(crate) reconstruction_defect: Interval,
    pub(crate) time_error: Interval,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct FixedTrajectoryBounds {
    pub(crate) steps: Vec<JointErrorBounds>,
    pub(crate) final_time_error: Interval,
    /// Digest of the complete mathematical inputs actually verified here.
    /// A digest binds bytes but does not authenticate their external origin.
    pub(crate) input_sha256: [u8; 32],
}

/// A mathematical envelope for one explicit affine basis/parameter switch.
/// It says nothing about the external source or authorization of that switch.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct AffineSwitchBounds {
    pub(crate) mapping_lipschitz_upper: f64,
    pub(crate) nominal_mapping_error: Interval,
    pub(crate) mapped_error: Interval,
}

/// Propagate a verified old-state error through `new = M old + offset`.
/// The complete mapping is checked here; no caller-supplied Lipschitz claim is
/// accepted. The nominal new state may differ from the exact affine image by
/// its explicitly enclosed mapping error, which is added to the inherited ball.
pub(crate) fn verify_affine_parameter_switch(
    mapping: SparseMatrix<'_>,
    offset: &[f64],
    old_nominal: &[f64],
    new_nominal: &[f64],
    old_error: Interval,
) -> Result<AffineSwitchBounds, VerifierError> {
    if !environment_supported() {
        return Err(VerifierError::UnsupportedEnvironment);
    }
    let old_n = old_nominal.len();
    let new_n = new_nominal.len();
    if old_n == 0
        || new_n == 0
        || old_n > MAX_VERIFIED_N
        || new_n > MAX_VERIFIED_N
        || offset.len() != new_n
    {
        return Err(VerifierError::InvalidDimension);
    }
    if !old_error.lower().is_finite() || !old_error.upper().is_finite() || old_error.lower() < 0.0 {
        return Err(VerifierError::InvalidInheritedError);
    }
    validate_state(old_nominal)?;
    validate_state(new_nominal)?;
    validate_state(offset)?;
    validate_csr(mapping, MatrixRole::A, new_n, old_n)?;

    let mut column_sums = vec![Interval::point(0.0)?; old_n];
    let mut row_max = 0.0_f64;
    for row in 0..new_n {
        let mut row_sum = Interval::point(0.0)?;
        for position in mapping.row_range(row) {
            let column = mapping.indices[position] as usize;
            let absolute = Interval::point(mapping.values[position].abs())?;
            row_sum = finite_interval(row_sum.add(absolute)?)?;
            column_sums[column] = finite_interval(column_sums[column].add(absolute)?)?;
        }
        row_max = row_max.max(row_sum.upper());
    }
    let column_max = column_sums
        .iter()
        .map(|sum| sum.upper())
        .fold(0.0_f64, f64::max);
    // ||M||_2 <= sqrt(||M||_1 ||M||_infinity) <= max of the two norms.
    let mapping_lipschitz_upper = row_max.max(column_max);
    let image = matvec(mapping, &point_vector(old_nominal)?)?;
    let nominal = point_vector(new_nominal)?;
    let mut differences = Vec::with_capacity(new_n);
    for row in 0..new_n {
        differences.push(finite_interval(
            image[row]
                .add(Interval::point(offset[row])?)?
                .sub(nominal[row])?,
        )?);
    }
    let nominal_mapping_error = interval_l2_norm(&differences)?;
    let mapped_upper = finite_interval(
        Interval::point(mapping_lipschitz_upper)?
            .mul(old_error)?
            .add(nominal_mapping_error)?,
    )?
    .upper();
    Ok(AffineSwitchBounds {
        mapping_lipschitz_upper,
        nominal_mapping_error,
        mapped_error: Interval::new(0.0, mapped_upper)?,
    })
}

/// Verify a mathematical fixed-parameter IVP from the first exact input state.
/// Subsequent inherited errors are computed from the preceding verified step,
/// never supplied by a caller. This establishes neither the external origin of
/// the initial state nor whether this CSR block closes a larger graph.
pub(crate) fn verify_fixed_trajectory(
    steps: &[JointVerificationInput<'_>],
) -> Result<FixedTrajectoryBounds, VerifierError> {
    let Some(first) = steps.first() else {
        return Err(VerifierError::InvalidDimension);
    };
    let mut prior_error = Interval::point(0.0)?;
    let mut verified = Vec::with_capacity(steps.len());
    let mut digest = Sha256::new();
    digest.update(b"sylanne3-fixed-trajectory-math-v1\0");
    hash_length(&mut digest, steps.len());
    for (index, step) in steps.iter().enumerate() {
        if index > 0 {
            let previous = &steps[index - 1];
            if !same_f64_bits(previous.y, step.x) || !same_fixed_model(first, step) {
                return Err(VerifierError::TrajectorySourceMismatch);
            }
        }
        let bounds = verify_joint_error_bounds(step, prior_error)?;
        hash_joint_input(&mut digest, step);
        prior_error = bounds.time_error;
        verified.push(bounds);
    }
    Ok(FixedTrajectoryBounds {
        steps: verified,
        final_time_error: prior_error,
        input_sha256: digest.finalize().into(),
    })
}

fn hash_length(digest: &mut Sha256, length: usize) {
    digest.update((length as u64).to_le_bytes());
}

fn hash_f64_values(digest: &mut Sha256, values: &[f64]) {
    hash_length(digest, values.len());
    for value in values {
        digest.update(value.to_bits().to_le_bytes());
    }
}

fn hash_matrix(digest: &mut Sha256, matrix: SparseMatrix<'_>) {
    hash_length(digest, matrix.rows);
    hash_length(digest, matrix.cols);
    hash_length(digest, matrix.offsets.len());
    for offset in matrix.offsets {
        digest.update(offset.to_le_bytes());
    }
    hash_length(digest, matrix.indices.len());
    for index in matrix.indices {
        digest.update(index.to_le_bytes());
    }
    hash_f64_values(digest, matrix.values);
}

fn hash_joint_input(digest: &mut Sha256, input: &JointVerificationInput<'_>) {
    for matrix in [input.k, input.r, input.j, input.a] {
        hash_matrix(digest, matrix);
    }
    for values in [input.alpha, input.x, input.y, input.drive] {
        hash_f64_values(digest, values);
    }
    digest.update(input.h.to_bits().to_le_bytes());
}

fn same_f64_bits(lhs: &[f64], rhs: &[f64]) -> bool {
    lhs.len() == rhs.len()
        && lhs
            .iter()
            .zip(rhs)
            .all(|(left, right)| left.to_bits() == right.to_bits())
}

fn same_matrix_bits(lhs: SparseMatrix<'_>, rhs: SparseMatrix<'_>) -> bool {
    lhs.rows == rhs.rows
        && lhs.cols == rhs.cols
        && lhs.offsets == rhs.offsets
        && lhs.indices == rhs.indices
        && same_f64_bits(lhs.values, rhs.values)
}

fn same_fixed_model(lhs: &JointVerificationInput<'_>, rhs: &JointVerificationInput<'_>) -> bool {
    same_matrix_bits(lhs.k, rhs.k)
        && same_matrix_bits(lhs.r, rhs.r)
        && same_matrix_bits(lhs.j, rhs.j)
        && same_matrix_bits(lhs.a, rhs.a)
        && same_f64_bits(lhs.alpha, rhs.alpha)
        && same_f64_bits(lhs.drive, rhs.drive)
}

/// Independently reconstruct the bounded nonlinear discrete gradient, fixed-point
/// residual and endpoint energy difference using outward interval arithmetic.
///
/// This envelope is local to the supplied block. It does not prove the origin
/// of inherited error, omitted-boundary closure, or input provenance.
pub(crate) fn verify_joint_step(
    input: &JointVerificationInput<'_>,
) -> Result<JointVerificationEnvelope, VerifierError> {
    if !environment_supported() {
        return Err(VerifierError::UnsupportedEnvironment);
    }
    let n = input.x.len();
    if n == 0 {
        return Err(VerifierError::InvalidDimension);
    }
    if n > MAX_VERIFIED_N || input.a.rows > MAX_VERIFIED_A_ROWS {
        return Err(VerifierError::CapacityExceeded);
    }
    if input.y.len() != n || input.drive.len() != n {
        return Err(VerifierError::InvalidDimension);
    }
    if !input.h.is_finite() || input.h <= 0.0 || input.h > MAX_STEP {
        return Err(VerifierError::InvalidStep);
    }
    validate_state(input.x)?;
    validate_state(input.y)?;
    validate_state(input.drive)?;
    if input.alpha.len() != input.a.rows
        || input
            .alpha
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0 || value.abs() > MAX_ABS_INPUT)
    {
        return Err(VerifierError::InvalidAlpha);
    }

    validate_csr(input.k, MatrixRole::K, n, n)?;
    validate_csr(input.r, MatrixRole::R, n, n)?;
    validate_csr(input.j, MatrixRole::J, n, n)?;
    validate_csr(input.a, MatrixRole::A, input.a.rows, n)?;
    let total_nnz = input
        .k
        .values
        .len()
        .saturating_add(input.r.values.len())
        .saturating_add(input.j.values.len())
        .saturating_add(input.a.values.len());
    if total_nnz > MAX_TOTAL_NNZ {
        return Err(VerifierError::CapacityExceeded);
    }

    let (k_coercivity_lower, k_row_abs_upper) = validate_positive_operator(input.k, MatrixRole::K)?;
    let (r_coercivity_lower, r_row_abs_upper) = validate_positive_operator(input.r, MatrixRole::R)?;
    let j_row_abs_upper = validate_skew_operator(input.j)?;
    let jr_operator_norm_upper = combined_operator_norm_upper(input.j, input.r)?;
    let a_row_abs_upper = row_abs_upper(input.a)?;

    let x = point_vector(input.x)?;
    let y = point_vector(input.y)?;
    let drive = point_vector(input.drive)?;
    let two = Interval::point(2.0)?;
    let mut midpoint = Vec::with_capacity(n);
    for index in 0..n {
        midpoint.push(finite_interval(x[index].add(y[index])?.div(two)?)?);
    }

    let mut gradient = matvec(input.k, &midpoint)?;
    let ax = matvec(input.a, &x)?;
    let ay = matvec(input.a, &y)?;
    for row in 0..input.a.rows {
        let hull = Interval::new(
            ax[row].lower().min(ay[row].lower()),
            ax[row].upper().max(ay[row].upper()),
        )?;
        if hull.lower() < -17.0 / 4.0 || hull.upper() > 17.0 / 4.0 {
            return Err(VerifierError::NonlinearArgumentOutOfRange);
        }
        // The AVF quotient is the integral mean of tanh on this segment.
        // Its monotone hull remains sound at coincident arguments; when the
        // endpoint difference excludes zero, intersect it with the independently
        // enclosed log-cosh secant to make useful tight step certificates.
        let mut quotient = finite_interval(hull.tanh()?)?;
        let difference = finite_interval(ay[row].sub(ax[row])?)?;
        if difference.lower() > 0.0 || difference.upper() < 0.0 {
            let energy_difference = finite_interval(ay[row].log_cosh()?.sub(ax[row].log_cosh()?)?)?;
            let secant = finite_interval(energy_difference.div(difference)?)?;
            quotient = Interval::new(
                quotient.lower().max(secant.lower()),
                quotient.upper().min(secant.upper()),
            )?;
        }
        let coefficient = finite_interval(Interval::point(input.alpha[row])?.mul(quotient)?)?;
        for position in input.a.row_range(row) {
            let column = input.a.indices[position] as usize;
            let contribution =
                finite_interval(coefficient.mul(Interval::point(input.a.values[position])?)?)?;
            gradient[column] = finite_interval(gradient[column].add(contribution)?)?;
        }
    }

    let jg = matvec(input.j, &gradient)?;
    let rg = matvec(input.r, &gradient)?;
    let step = Interval::point(input.h)?;
    let mut residual_components = Vec::with_capacity(n);
    for index in 0..n {
        let force = jg[index].sub(rg[index])?.add(drive[index])?;
        let displacement = y[index].sub(x[index])?;
        residual_components.push(finite_interval(displacement.sub(step.mul(force)?)?)?);
    }
    let residual_norm = interval_l2_norm(&residual_components)?;

    let energy_before = energy(input.k, input.a, input.alpha, &x, &ax)?;
    let energy_after = energy(input.k, input.a, input.alpha, &y, &ay)?;
    let energy_difference = finite_interval(energy_after.sub(energy_before)?)?;
    let mut displacement = Vec::with_capacity(n);
    for index in 0..n {
        displacement.push(finite_interval(y[index].sub(x[index])?)?);
    }
    let gradient_displacement = interval_dot(&gradient, &displacement)?;
    let dissipation =
        finite_interval(Interval::point(-input.h)?.mul(interval_dot(&gradient, &rg)?)?)?;
    let drive_work = finite_interval(step.mul(interval_dot(&gradient, &drive)?)?)?;
    let residual_work = interval_dot(&gradient, &residual_components)?;
    let gradient_identity_defect = finite_interval(energy_difference.sub(gradient_displacement)?)?;
    let energy_balance_defect = finite_interval(
        energy_difference
            .sub(dissipation)?
            .sub(drive_work)?
            .sub(residual_work)?,
    )?;

    Ok(JointVerificationEnvelope {
        gradient,
        residual_components,
        residual_norm,
        energy_before,
        energy_after,
        energy_difference,
        gradient_displacement,
        dissipation,
        drive_work,
        residual_work,
        gradient_identity_defect,
        energy_balance_defect,
        operator_bounds: OperatorBounds {
            k_coercivity_lower,
            r_coercivity_lower,
            k_row_abs_upper,
            r_row_abs_upper,
            j_row_abs_upper,
            jr_operator_norm_upper,
            a_row_abs_upper,
        },
    })
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct LinearReadout {
    pub(crate) point: Interval,
    pub(crate) enclosure: Interval,
    /// -1: strictly below; 0: threshold may be crossed; 1: strictly above.
    pub(crate) threshold_relation: i32,
}

/// An arithmetic enclosure for c^T y and an externally supplied state error.
/// The caller's error provenance is not authenticated by this function.
pub(crate) fn linear_readout(
    y: &[f64],
    c: &[f64],
    error_upper: f64,
    threshold: f64,
) -> Result<LinearReadout, VerifierError> {
    if y.is_empty() || y.len() != c.len() || y.len() > MAX_VERIFIED_N {
        return Err(VerifierError::InvalidDimension);
    }
    validate_state(y)?;
    validate_state(c)?;
    if !error_upper.is_finite() || error_upper < 0.0 {
        return Err(VerifierError::InvalidInheritedError);
    }
    if !threshold.is_finite() {
        return Err(VerifierError::InvalidState);
    }
    let point = interval_dot(&point_vector(c)?, &point_vector(y)?)?;
    let radius =
        finite_interval(interval_l2_norm(&point_vector(c)?)?.mul(Interval::point(error_upper)?)?)?;
    let enclosure = finite_interval(point.add(Interval::new(-radius.upper(), radius.upper())?)?)?;
    let threshold_relation = if enclosure.upper() < threshold {
        -1
    } else if enclosure.lower() > threshold {
        1
    } else {
        0
    };
    Ok(LinearReadout {
        point,
        enclosure,
        threshold_relation,
    })
}

/// Derive error bounds from the verified operators, not caller-provided norms.
///
/// `inherited_error` must already be a trusted enclosure of the preceding
/// state error. This local function cannot authenticate that provenance, an
/// event boundary, or the surrounding ABI.
pub(crate) fn verify_joint_error_bounds(
    input: &JointVerificationInput<'_>,
    inherited_error: Interval,
) -> Result<JointErrorBounds, VerifierError> {
    if !inherited_error.lower().is_finite()
        || !inherited_error.upper().is_finite()
        || inherited_error.lower() < 0.0
    {
        return Err(VerifierError::InvalidInheritedError);
    }
    let envelope = verify_joint_step(input)?;
    let zero = Interval::point(0.0)?;
    let one = Interval::point(1.0)?;
    let step = Interval::point(input.h)?;
    let operator = Interval::point(envelope.operator_bounds.jr_operator_norm_upper)?;
    // Symmetric K has ||K||_2 bounded by its verified maximum absolute row sum.
    // The full J-R norm uses verified row and column sums. Each Hessian term
    // is alpha_l * a_l a_l^T, with spectral norm alpha_l * ||a_l||_2^2.
    let mut gradient_lipschitz = Interval::point(envelope.operator_bounds.k_row_abs_upper)?;
    for row in 0..input.a.rows {
        let mut squared_norm = zero;
        for position in input.a.row_range(row) {
            let value = Interval::point(input.a.values[position])?;
            let square = value.mul(value)?;
            squared_norm = finite_interval(
                squared_norm.add(Interval::new(square.lower().max(0.0), square.upper())?)?,
            )?;
        }
        gradient_lipschitz = finite_interval(
            gradient_lipschitz.add(Interval::point(input.alpha[row])?.mul(squared_norm)?)?,
        )?;
    }
    let vector_field_lipschitz = finite_interval(operator.mul(gradient_lipschitz)?)?;
    let q = finite_interval(
        step.mul(vector_field_lipschitz)?
            .mul(Interval::point(0.5)?)?,
    )?;
    // 0.8 is the design margin. Comparison is against the outward upper bound.
    if q.upper() > 0.8 {
        return Err(VerifierError::ContractionNotProven);
    }
    let one_minus_q = finite_interval(one.sub(Interval::new(0.0, q.upper())?)?)?;
    if one_minus_q.lower() <= 0.0 {
        return Err(VerifierError::ContractionNotProven);
    }
    let endpoint_upper =
        finite_interval(Interval::point(envelope.residual_norm.upper())?.div(one_minus_q)?)?
            .upper();
    let endpoint_error = Interval::new(0.0, endpoint_upper)?;

    // For zhat(t)=x+(t/h)(y-x), constant input and fixed parameters:
    // D <= ||(y-x)/h-F(x)|| + L ||y-x||. The complete CSR block is used.
    let x = point_vector(input.x)?;
    let y = point_vector(input.y)?;
    let drive = point_vector(input.drive)?;
    let mut displacement = Vec::with_capacity(x.len());
    for index in 0..x.len() {
        displacement.push(finite_interval(y[index].sub(x[index])?)?);
    }
    let mut gradient_at_x = matvec(input.k, &x)?;
    let ax = matvec(input.a, &x)?;
    for row in 0..input.a.rows {
        if ax[row].lower() < -17.0 / 4.0 || ax[row].upper() > 17.0 / 4.0 {
            return Err(VerifierError::NonlinearArgumentOutOfRange);
        }
        let coefficient =
            finite_interval(Interval::point(input.alpha[row])?.mul(ax[row].tanh()?)?)?;
        for position in input.a.row_range(row) {
            let column = input.a.indices[position] as usize;
            gradient_at_x[column] = finite_interval(
                gradient_at_x[column]
                    .add(coefficient.mul(Interval::point(input.a.values[position])?)?)?,
            )?;
        }
    }
    let j_gradient = matvec(input.j, &gradient_at_x)?;
    let r_gradient = matvec(input.r, &gradient_at_x)?;
    let mut defect_at_x = Vec::with_capacity(x.len());
    for index in 0..x.len() {
        let force = finite_interval(
            j_gradient[index]
                .sub(r_gradient[index])?
                .add(drive[index])?,
        )?;
        defect_at_x.push(finite_interval(displacement[index].div(step)?.sub(force)?)?);
    }
    let defect_upper = if input.a.rows == 0 {
        // With a quadratic potential and fixed drive, F is affine. Along the
        // linear reconstruction d(s)=(1-s)d(0)+s d(1); convexity of the norm
        // bounds its supremum by the larger endpoint norm. Both endpoint
        // forces are independently enclosed using the complete CSR block.
        let gradient_at_y = matvec(input.k, &y)?;
        let j_gradient_at_y = matvec(input.j, &gradient_at_y)?;
        let r_gradient_at_y = matvec(input.r, &gradient_at_y)?;
        let mut defect_at_y = Vec::with_capacity(x.len());
        for index in 0..x.len() {
            let force = finite_interval(
                j_gradient_at_y[index]
                    .sub(r_gradient_at_y[index])?
                    .add(drive[index])?,
            )?;
            defect_at_y.push(finite_interval(displacement[index].div(step)?.sub(force)?)?);
        }
        interval_l2_norm(&defect_at_x)?
            .upper()
            .max(interval_l2_norm(&defect_at_y)?.upper())
    } else {
        finite_interval(
            interval_l2_norm(&defect_at_x)?
                .add(vector_field_lipschitz.mul(interval_l2_norm(&displacement)?)?)?,
        )?
        .upper()
    };
    let reconstruction_defect = Interval::new(0.0, defect_upper)?;

    // Both analytic interval functions are valid through argument 2. The
    // integral factor is phi_1(Lh) = expm1(Lh)/(Lh), continuously one at L=0.
    // Its positive series and explicit tail avoid cancellation near zero.
    let lh = finite_interval(step.mul(vector_field_lipschitz)?)?;
    if lh.upper() > 2.0 {
        return Err(VerifierError::TemporalBoundUnavailable);
    }
    let amplification = finite_interval(Interval::new(0.0, lh.upper())?.exp()?)?;
    let integral_factor = finite_interval(Interval::new(0.0, lh.upper())?.exp_integral_factor()?)?;
    let time_upper = finite_interval(
        amplification
            .mul(inherited_error)?
            .add(step.mul(integral_factor)?.mul(reconstruction_defect)?)?,
    )?
    .upper();
    Ok(JointErrorBounds {
        gradient_lipschitz_upper: gradient_lipschitz.upper(),
        vector_field_lipschitz_upper: vector_field_lipschitz.upper(),
        contraction_upper: q.upper(),
        endpoint_error,
        reconstruction_defect,
        time_error: Interval::new(0.0, time_upper)?,
    })
}

fn validate_state(values: &[f64]) -> Result<(), VerifierError> {
    if values
        .iter()
        .any(|value| !value.is_finite() || value.abs() > MAX_ABS_INPUT)
    {
        Err(VerifierError::InvalidState)
    } else {
        Ok(())
    }
}

fn validate_csr(
    matrix: SparseMatrix<'_>,
    role: MatrixRole,
    rows: usize,
    cols: usize,
) -> Result<(), VerifierError> {
    let nnz = matrix.values.len();
    if matrix.rows != rows
        || matrix.cols != cols
        || matrix.offsets.len() != rows + 1
        || matrix.indices.len() != nnz
        || nnz > MAX_MATRIX_NNZ
        || matrix.offsets.first().copied() != Some(0)
        || matrix.offsets.last().copied().map(|value| value as usize) != Some(nnz)
    {
        return if nnz > MAX_MATRIX_NNZ {
            Err(VerifierError::CapacityExceeded)
        } else {
            Err(VerifierError::InvalidCsr(role))
        };
    }
    if matrix
        .values
        .iter()
        .any(|value| !value.is_finite() || value.abs() > MAX_ABS_INPUT)
    {
        return Err(VerifierError::CoefficientOutOfRange(role));
    }
    for row in 0..rows {
        let start = matrix.offsets[row] as usize;
        let end = matrix.offsets[row + 1] as usize;
        if start > end
            || end > nnz
            || matrix.indices[start..end]
                .iter()
                .any(|column| *column as usize >= cols)
            || matrix.indices[start..end]
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(VerifierError::InvalidCsr(role));
        }
    }
    Ok(())
}

fn validate_positive_operator(
    matrix: SparseMatrix<'_>,
    role: MatrixRole,
) -> Result<(f64, f64), VerifierError> {
    let mut coercivity_lower = f64::INFINITY;
    let mut norm_upper: f64 = 0.0;
    for row in 0..matrix.rows {
        let mut diagonal = None;
        let mut off_diagonal = Interval::point(0.0)?;
        let mut absolute_row = Interval::point(0.0)?;
        for position in matrix.row_range(row) {
            let column = matrix.indices[position] as usize;
            let value = matrix.values[position];
            absolute_row = absolute_row.add(Interval::point(value.abs())?)?;
            if column == row {
                diagonal = Some(value);
            } else {
                if matrix.entry(column, row) != Some(value) {
                    return Err(VerifierError::InvalidStructure(role));
                }
                off_diagonal = off_diagonal.add(Interval::point(value.abs())?)?;
            }
        }
        let Some(diagonal) = diagonal else {
            return Err(VerifierError::PositivityNotProven(role));
        };
        if diagonal <= 0.0 {
            return Err(VerifierError::PositivityNotProven(role));
        }
        // Absolute off-diagonal radius proves coercivity for symmetric K/R,
        // including positive couplings; the interval lower endpoint is outward.
        let margin = Interval::point(diagonal)?.sub(off_diagonal)?;
        if margin.lower() <= 0.0 || !margin.lower().is_finite() {
            return Err(VerifierError::PositivityNotProven(role));
        }
        coercivity_lower = coercivity_lower.min(margin.lower());
        norm_upper = norm_upper.max(absolute_row.upper());
    }
    Ok((coercivity_lower, norm_upper))
}

fn validate_skew_operator(matrix: SparseMatrix<'_>) -> Result<f64, VerifierError> {
    for row in 0..matrix.rows {
        for position in matrix.row_range(row) {
            let column = matrix.indices[position] as usize;
            let value = matrix.values[position];
            if (column == row && value != 0.0)
                || (column != row && matrix.entry(column, row) != Some(-value))
            {
                return Err(VerifierError::InvalidStructure(MatrixRole::J));
            }
        }
    }
    row_abs_upper(matrix)
}

fn row_abs_upper(matrix: SparseMatrix<'_>) -> Result<f64, VerifierError> {
    let mut maximum: f64 = 0.0;
    for row in 0..matrix.rows {
        let mut sum = Interval::point(0.0)?;
        for position in matrix.row_range(row) {
            sum = sum.add(Interval::point(matrix.values[position].abs())?)?;
        }
        maximum = maximum.max(sum.upper());
    }
    Ok(maximum)
}

/// Bound ||J-R||_2 from the complete sparse operator. For any matrix B,
/// ||B||_2 <= sqrt(||B||_1 ||B||_inf) <= max(||B||_1, ||B||_inf).
/// Both row and column sums use outward intervals, including J/R overlap.
fn combined_operator_norm_upper(
    j: SparseMatrix<'_>,
    r: SparseMatrix<'_>,
) -> Result<f64, VerifierError> {
    let mut column_sums = vec![Interval::point(0.0)?; j.cols];
    let mut row_max: f64 = 0.0;
    for row in 0..j.rows {
        let mut j_position = j.offsets[row] as usize;
        let j_end = j.offsets[row + 1] as usize;
        let mut r_position = r.offsets[row] as usize;
        let r_end = r.offsets[row + 1] as usize;
        let mut row_sum = Interval::point(0.0)?;
        while j_position < j_end || r_position < r_end {
            let j_column = if j_position < j_end {
                j.indices[j_position] as usize
            } else {
                j.cols
            };
            let r_column = if r_position < r_end {
                r.indices[r_position] as usize
            } else {
                r.cols
            };
            let column = j_column.min(r_column);
            let j_value = if j_column == column {
                let value = j.values[j_position];
                j_position += 1;
                value
            } else {
                0.0
            };
            let r_value = if r_column == column {
                let value = r.values[r_position];
                r_position += 1;
                value
            } else {
                0.0
            };
            let difference =
                finite_interval(Interval::point(j_value)?.sub(Interval::point(r_value)?)?)?;
            let absolute_upper = difference.lower().abs().max(difference.upper().abs());
            let absolute = Interval::new(0.0, absolute_upper)?;
            row_sum = finite_interval(row_sum.add(absolute)?)?;
            column_sums[column] = finite_interval(column_sums[column].add(absolute)?)?;
        }
        row_max = row_max.max(row_sum.upper());
    }
    let column_max = column_sums
        .iter()
        .map(|sum| sum.upper())
        .fold(0.0_f64, f64::max);
    Ok(row_max.max(column_max))
}

fn point_vector(values: &[f64]) -> Result<Vec<Interval>, VerifierError> {
    values
        .iter()
        .map(|value| Interval::point(*value).map_err(VerifierError::from))
        .collect()
}

fn matvec(matrix: SparseMatrix<'_>, vector: &[Interval]) -> Result<Vec<Interval>, VerifierError> {
    if vector.len() != matrix.cols {
        return Err(VerifierError::InvalidDimension);
    }
    let mut output = Vec::with_capacity(matrix.rows);
    for row in 0..matrix.rows {
        let mut sum = Interval::point(0.0)?;
        for position in matrix.row_range(row) {
            let column = matrix.indices[position] as usize;
            let term = Interval::point(matrix.values[position])?.mul(vector[column])?;
            sum = sum.add(term)?;
        }
        output.push(finite_interval(sum)?);
    }
    Ok(output)
}

fn energy(
    k: SparseMatrix<'_>,
    a: SparseMatrix<'_>,
    alpha: &[f64],
    state: &[Interval],
    a_state: &[Interval],
) -> Result<Interval, VerifierError> {
    let k_state = matvec(k, state)?;
    let mut quadratic = Interval::point(0.0)?;
    for index in 0..state.len() {
        quadratic = quadratic.add(state[index].mul(k_state[index])?)?;
    }
    let mut total = Interval::point(0.5)?.mul(quadratic)?;
    for row in 0..a.rows {
        if a_state[row].lower() < -17.0 / 4.0 || a_state[row].upper() > 17.0 / 4.0 {
            return Err(VerifierError::NonlinearArgumentOutOfRange);
        }
        let nonlinear = Interval::point(alpha[row])?.mul(a_state[row].log_cosh()?)?;
        total = total.add(nonlinear)?;
    }
    finite_interval(total)
}

fn interval_l2_norm(values: &[Interval]) -> Result<Interval, VerifierError> {
    let mut sum = Interval::point(0.0)?;
    for value in values {
        let square = value.mul(*value)?;
        let square = Interval::new(square.lower().max(0.0), square.upper())?;
        sum = sum.add(square)?;
        // Both operands are known nonnegative. Outward rounding of 0 + 0 can
        // nevertheless move the computed lower endpoint to -MIN_SUBNORMAL.
        // Restore the mathematical invariant before the final square root.
        sum = Interval::new(sum.lower().max(0.0), sum.upper())?;
    }
    finite_interval(sum.sqrt()?)
}

fn interval_dot(lhs: &[Interval], rhs: &[Interval]) -> Result<Interval, VerifierError> {
    if lhs.len() != rhs.len() {
        return Err(VerifierError::InvalidDimension);
    }
    let mut sum = Interval::point(0.0)?;
    for (left, right) in lhs.iter().zip(rhs) {
        sum = finite_interval(sum.add(left.mul(*right)?)?)?;
    }
    Ok(sum)
}

fn finite_interval(value: Interval) -> Result<Interval, VerifierError> {
    if value.lower().is_finite() && value.upper().is_finite() {
        Ok(value)
    } else {
        Err(VerifierError::Arithmetic(IntervalError::Indeterminate))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(interval: Interval, value: f64) {
        assert!(
            interval.lower() <= value && value <= interval.upper(),
            "{value:?} not contained in {interval:?}"
        );
    }

    fn scalar_matrix<'a>(value: &'a [f64]) -> SparseMatrix<'a> {
        SparseMatrix::new(1, 1, &[0, 1], &[0], value)
    }

    #[test]
    fn energy_ledger_and_readout_enclose_scalar_balance_and_crossing() {
        let k = [2.0];
        let r = [1.0];
        let input = JointVerificationInput {
            k: scalar_matrix(&k),
            r: scalar_matrix(&r),
            j: SparseMatrix::new(1, 1, &[0, 0], &[], &[]),
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[0.4],
            y: &[0.35],
            h: 0.1,
            drive: &[0.0],
        };
        let envelope = verify_joint_step(&input).unwrap();
        contains(
            envelope.energy_difference,
            0.35_f64.powi(2) - 0.4_f64.powi(2),
        );
        contains(envelope.gradient_displacement, 0.75 * -0.05);
        contains(envelope.dissipation, -0.1 * 0.75 * 0.75);
        contains(envelope.drive_work, 0.0);
        contains(envelope.residual_work, 0.75 * 0.025);
        contains(envelope.gradient_identity_defect, 0.0);
        contains(envelope.energy_balance_defect, 0.0);
        let readout = linear_readout(&[0.35], &[2.0], 0.1, 0.7).unwrap();
        contains(readout.point, 0.7);
        contains(readout.enclosure, 0.5);
        contains(readout.enclosure, 0.9);
        assert_eq!(readout.threshold_relation, 0);
        assert_eq!(
            linear_readout(&[0.35], &[2.0], 0.0, 1.0)
                .unwrap()
                .threshold_relation,
            -1
        );
    }

    #[test]
    fn scalar_nonlinear_gradient_residual_and_energy_are_enclosed() {
        let k_values = [2.0];
        let r_values = [3.0];
        let j_offsets = [0, 0];
        let a_values = [0.5];
        let input = JointVerificationInput {
            k: scalar_matrix(&k_values),
            r: scalar_matrix(&r_values),
            j: SparseMatrix::new(1, 1, &j_offsets, &[], &[]),
            a: scalar_matrix(&a_values),
            alpha: &[0.2],
            x: &[0.2],
            y: &[0.3],
            h: 0.1,
            drive: &[0.1],
        };

        let envelope = verify_joint_step(&input).unwrap();
        let ax = 0.5_f64 * 0.2;
        let ay = 0.5_f64 * 0.3;
        let quotient = (ay.cosh().ln() - ax.cosh().ln()) / (ay - ax);
        let gradient = 2.0 * 0.25 + 0.2 * 0.5 * quotient;
        let residual = 0.3 - 0.2 - 0.1 * (-3.0 * gradient + 0.1);
        let energy_before = 0.5 * 2.0 * 0.2 * 0.2 + 0.2 * ax.cosh().ln();
        let energy_after = 0.5 * 2.0 * 0.3 * 0.3 + 0.2 * ay.cosh().ln();

        contains(envelope.gradient[0], gradient);
        contains(envelope.residual_components[0], residual);
        contains(envelope.residual_norm, residual.abs());
        contains(envelope.energy_before, energy_before);
        contains(envelope.energy_after, energy_after);
        contains(envelope.energy_difference, energy_after - energy_before);
        let avf_work = envelope.gradient[0]
            .mul(Interval::point(0.3 - 0.2).unwrap())
            .unwrap();
        contains(avf_work, energy_after - energy_before);
        assert!(envelope.operator_bounds.k_coercivity_lower > 0.0);
        assert!(envelope.operator_bounds.r_coercivity_lower > 0.0);
    }

    #[test]
    fn nonlinear_energy_and_gradient_cover_four_unit_latent_state() {
        let values = [1.0];
        let input = JointVerificationInput {
            k: scalar_matrix(&values),
            r: scalar_matrix(&values),
            j: SparseMatrix::new(1, 1, &[0, 0], &[], &[]),
            a: scalar_matrix(&values),
            alpha: &[0.25],
            x: &[4.0],
            y: &[3.9],
            h: 0.02,
            drive: &[0.0],
        };
        let envelope = verify_joint_step(&input).unwrap();
        let exact_before = 0.5 * 4.0 * 4.0 + 0.25 * 4.0_f64.cosh().ln();
        let exact_after = 0.5 * 3.9 * 3.9 + 0.25 * 3.9_f64.cosh().ln();
        let midpoint_gradient = 3.95 + 0.25 * (4.0_f64.cosh().ln() - 3.9_f64.cosh().ln()) / 0.1;
        contains(envelope.energy_before, exact_before);
        contains(envelope.energy_after, exact_after);
        contains(envelope.energy_difference, exact_after - exact_before);
        contains(envelope.gradient[0], midpoint_gradient);
    }

    #[test]
    fn coincident_nonlinear_arguments_use_tanh_hull_without_a_difference() {
        let k_values = [1.0];
        let r_values = [1.0];
        let j_offsets = [0, 0];
        let a_values = [0.5];
        let input = JointVerificationInput {
            k: scalar_matrix(&k_values),
            r: scalar_matrix(&r_values),
            j: SparseMatrix::new(1, 1, &j_offsets, &[], &[]),
            a: scalar_matrix(&a_values),
            alpha: &[0.4],
            x: &[0.25],
            y: &[0.25],
            h: 0.1,
            drive: &[0.0],
        };

        let envelope = verify_joint_step(&input).unwrap();
        let argument = 0.125_f64;
        let exact = 0.25 + 0.4 * 0.5 * argument.tanh();
        contains(envelope.gradient[0], exact);
    }

    #[test]
    fn zero_residual_norm_preserves_the_known_nonnegative_sum() {
        let values = [1.0];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let input = JointVerificationInput {
            k: scalar_matrix(&values),
            r: scalar_matrix(&values),
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[0.0],
            y: &[0.0],
            h: 0.1,
            drive: &[0.0],
        };

        let envelope = verify_joint_step(&input).unwrap();
        contains(envelope.residual_norm, 0.0);
        assert!(envelope.residual_norm.lower() >= 0.0);
    }

    #[test]
    fn linear_scalar_error_bounds_cover_independent_endpoint_and_flow() {
        let values = [1.0];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let input = JointVerificationInput {
            k: scalar_matrix(&values),
            r: scalar_matrix(&values),
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[1.0],
            y: &[0.9],
            h: 0.1,
            drive: &[0.0],
        };
        let previous = Interval::point(0.01).unwrap();
        let bounds = verify_joint_error_bounds(&input, previous).unwrap();
        let exact_discrete = (1.0 - input.h / 2.0) / (1.0 + input.h / 2.0);
        let exact_flow = (-input.h).exp(); // Independent test oracle, not verifier code.
        assert!(bounds.contraction_upper >= 0.05);
        assert!(bounds.contraction_upper < 0.8);
        assert!(bounds.endpoint_error.upper() >= (input.y[0] - exact_discrete).abs());
        assert!(bounds.reconstruction_defect.upper() >= 0.1);
        assert!(
            bounds.time_error.upper() >= (input.y[0] - exact_flow).abs() + (-input.h).exp() * 0.01
        );
        assert!(bounds.time_error.lower() >= 0.0);
    }

    #[test]
    fn coupled_quadratic_reconstruction_uses_endpoint_defects() {
        // For constant forcing and a quadratic potential, F is affine. The
        // midpoint candidate makes endpoint defects almost opposite, so the
        // generic Lipschitz path bound is roughly three times too wide.
        let diagonal = [1.0, 1.0];
        let j_values = [0.2, -0.2];
        let x = [1.0, 0.0];
        let h = 0.1;
        let denominator = 1.05_f64.powi(2) + 0.01_f64.powi(2);
        let y = [
            (1.05 * 0.95 - 0.0001) / denominator,
            (-0.01 * 0.95 - 1.05 * 0.01) / denominator,
        ];
        let input = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &[0, 1, 2], &[0, 1], &diagonal),
            r: SparseMatrix::new(2, 2, &[0, 1, 2], &[0, 1], &diagonal),
            j: SparseMatrix::new(2, 2, &[0, 1, 2], &[1, 0], &j_values),
            a: SparseMatrix::new(0, 2, &[0], &[], &[]),
            alpha: &[],
            x: &x,
            y: &y,
            h,
            drive: &[0.0, 0.0],
        };
        let bounds = verify_joint_error_bounds(&input, Interval::point(0.0).unwrap()).unwrap();
        for index in 0..=100 {
            let s = index as f64 / 100.0;
            let z = [x[0] + s * (y[0] - x[0]), x[1] + s * (y[1] - x[1])];
            let force = [-z[0] + 0.2 * z[1], -0.2 * z[0] - z[1]];
            let defect = (((y[0] - x[0]) / h - force[0]).powi(2)
                + ((y[1] - x[1]) / h - force[1]).powi(2))
            .sqrt();
            assert!(bounds.reconstruction_defect.upper() >= defect);
        }
        assert!(bounds.reconstruction_defect.upper() < 0.08);
        let exact = [(-h).exp() * (0.2 * h).cos(), -(-h).exp() * (0.2 * h).sin()];
        let endpoint_error = ((y[0] - exact[0]).powi(2) + (y[1] - exact[1]).powi(2)).sqrt();
        assert!(bounds.time_error.upper() >= endpoint_error);
    }

    #[test]
    fn fixed_trajectory_inherits_error_and_rejects_state_reset() {
        let values = [1.0];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let first = JointVerificationInput {
            k: scalar_matrix(&values),
            r: scalar_matrix(&values),
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[1.0],
            y: &[0.9],
            h: 0.1,
            drive: &[0.0],
        };
        let second = JointVerificationInput {
            x: &[0.9],
            y: &[0.82],
            ..first
        };
        let chain = verify_fixed_trajectory(&[first, second]).unwrap();
        let repeated = verify_fixed_trajectory(&[first, second]).unwrap();
        let reset = verify_joint_error_bounds(&second, Interval::point(0.0).unwrap()).unwrap();
        assert_eq!(chain.steps.len(), 2);
        assert_eq!(chain.input_sha256, repeated.input_sha256);
        assert!(chain.final_time_error.upper() > reset.time_error.upper());
        assert!(chain.final_time_error.upper() >= (0.82 - (-0.2_f64).exp()).abs());
        let changed_endpoint = JointVerificationInput {
            y: &[0.83],
            ..second
        };
        assert_ne!(
            chain.input_sha256,
            verify_fixed_trajectory(&[first, changed_endpoint])
                .unwrap()
                .input_sha256
        );

        let forged_previous = JointVerificationInput {
            x: &[1.0],
            ..second
        };
        assert_eq!(
            verify_fixed_trajectory(&[first, forged_previous]),
            Err(VerifierError::TrajectorySourceMismatch)
        );
        let changed_drive = JointVerificationInput {
            drive: &[0.1],
            ..second
        };
        assert_eq!(
            verify_fixed_trajectory(&[first, changed_drive]),
            Err(VerifierError::TrajectorySourceMismatch)
        );
    }

    #[test]
    fn affine_switch_computes_amplification_and_carries_error_into_new_model() {
        let unit = [1.0];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let first = JointVerificationInput {
            k: scalar_matrix(&unit),
            r: scalar_matrix(&unit),
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[1.0],
            y: &[0.9],
            h: 0.1,
            drive: &[0.0],
        };
        let before = verify_joint_error_bounds(&first, Interval::point(0.0).unwrap()).unwrap();
        let map_values = [2.0];
        let map = scalar_matrix(&map_values);
        let switched =
            verify_affine_parameter_switch(map, &[0.0], first.y, &[1.8], before.time_error)
                .unwrap();
        assert!(switched.mapping_lipschitz_upper >= 2.0);
        assert!(switched.mapped_error.upper() >= 2.0 * before.time_error.upper());

        // A new parameter interval must inherit the amplified envelope. Resetting
        // it at the switch would produce a demonstrably smaller false bound.
        let new_r = [0.5];
        let second = JointVerificationInput {
            r: scalar_matrix(&new_r),
            x: &[1.8],
            y: &[1.7],
            ..first
        };
        let inherited = verify_joint_error_bounds(&second, switched.mapped_error).unwrap();
        let reset = verify_joint_error_bounds(&second, Interval::point(0.0).unwrap()).unwrap();
        assert!(inherited.time_error.upper() > reset.time_error.upper());

        // A migration offset is part of the map; an unexplained nominal jump
        // is charged to the error ball instead of being silently discarded.
        let offset =
            verify_affine_parameter_switch(map, &[0.25], first.y, &[2.05], before.time_error)
                .unwrap();
        let unexplained =
            verify_affine_parameter_switch(map, &[0.0], first.y, &[2.05], before.time_error)
                .unwrap();
        assert!(unexplained.mapped_error.upper() > offset.mapped_error.upper() + 0.24);
    }

    #[test]
    fn affine_switch_rejects_missing_mapping_and_unknown_error() {
        let missing = SparseMatrix::new(1, 1, &[0, 1], &[1], &[2.0]);
        assert_eq!(
            verify_affine_parameter_switch(
                missing,
                &[0.0],
                &[1.0],
                &[2.0],
                Interval::point(0.1).unwrap(),
            ),
            Err(VerifierError::InvalidCsr(MatrixRole::A))
        );
        let map_values = [2.0];
        assert_eq!(
            verify_affine_parameter_switch(
                scalar_matrix(&map_values),
                &[0.0],
                &[1.0],
                &[2.0],
                Interval::point(f64::INFINITY).unwrap(),
            ),
            Err(VerifierError::InvalidInheritedError)
        );
    }

    #[test]
    fn near_critical_q_and_untrusted_previous_error_fail_closed() {
        let k_values = [2.0];
        let r_values = [1.0];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let base = JointVerificationInput {
            k: scalar_matrix(&k_values),
            r: scalar_matrix(&r_values),
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[0.0],
            y: &[0.0],
            h: 0.81,
            drive: &[0.0],
        };
        assert_eq!(
            verify_joint_error_bounds(&base, Interval::point(0.0).unwrap()),
            Err(VerifierError::ContractionNotProven)
        );
        let short = JointVerificationInput { h: 0.79, ..base };
        let certified = verify_joint_error_bounds(&short, Interval::point(0.0).unwrap()).unwrap();
        assert!(certified.contraction_upper < 0.8);
        assert_eq!(
            verify_joint_error_bounds(&short, Interval::new(-0.1, 0.1).unwrap()),
            Err(VerifierError::InvalidInheritedError)
        );
        assert_eq!(
            verify_joint_error_bounds(&short, Interval::new(0.0, f64::INFINITY).unwrap()),
            Err(VerifierError::InvalidInheritedError)
        );
    }

    #[test]
    fn full_coupling_controls_q_instead_of_diagonal_blocks() {
        let identity_offsets = [0, 1, 2];
        let identity_indices = [0, 1];
        let identity_values = [1.0, 1.0];
        let j_offsets = [0, 1, 2];
        let j_indices = [1, 0];
        let j_values = [10.0, -10.0];
        let input = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &identity_offsets, &identity_indices, &identity_values),
            r: SparseMatrix::new(2, 2, &identity_offsets, &identity_indices, &identity_values),
            j: SparseMatrix::new(2, 2, &j_offsets, &j_indices, &j_values),
            a: SparseMatrix::new(0, 2, &[0], &[], &[]),
            alpha: &[],
            x: &[0.0, 0.0],
            y: &[0.0, 0.0],
            h: 0.2,
            drive: &[0.0, 0.0],
        };
        // Each isolated diagonal block has q=0.1. The complete J coupling
        // makes the verified norm bound exceed the design margin.
        assert_eq!(
            verify_joint_error_bounds(&input, Interval::point(0.0).unwrap()),
            Err(VerifierError::ContractionNotProven)
        );
    }

    #[test]
    fn complete_operator_bound_admits_disjoint_damping_and_coupling() {
        let identity_offsets = [0, 1, 2, 3];
        let identity_indices = [0, 1, 2];
        let identity_values = [1.0, 1.0, 1.0];
        let damping_values = [0.1, 0.1, 1.0];
        let input = JointVerificationInput {
            k: SparseMatrix::new(3, 3, &identity_offsets, &identity_indices, &identity_values),
            r: SparseMatrix::new(3, 3, &identity_offsets, &identity_indices, &damping_values),
            j: SparseMatrix::new(3, 3, &[0, 1, 2, 2], &[1, 0], &[1.0, -1.0]),
            a: SparseMatrix::new(1, 3, &[0, 1], &[0], &[0.25]),
            alpha: &[0.2],
            x: &[0.2, 0.0, 0.0],
            y: &[0.18, 0.0, 0.0],
            h: 1.0,
            drive: &[0.0, 0.0, 0.0],
        };

        let envelope = verify_joint_step(&input).unwrap();
        // Separate maxima give ||J||_inf + ||R||_inf = 2 and q >= 1.
        // The complete J-R has absolute row and column sums at most 1.1;
        // its exact 2-norm is sqrt(1.01), so the new upper bound is safe.
        assert!(envelope.operator_bounds.jr_operator_norm_upper >= 1.01_f64.sqrt());
        assert!(envelope.operator_bounds.jr_operator_norm_upper < 1.2);
        let bounds = verify_joint_error_bounds(&input, Interval::point(0.0).unwrap()).unwrap();
        assert!(bounds.contraction_upper < 0.8);
        assert!(bounds.gradient_lipschitz_upper >= 1.0125);
        assert!(bounds.vector_field_lipschitz_upper >= 1.01_f64.sqrt());
        assert!(bounds.time_error.upper().is_finite());
    }

    #[test]
    fn nonlinear_reconstruction_defect_encloses_sampled_full_flow() {
        let k_values = [2.0];
        let r_values = [1.0];
        let a_values = [0.5];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let input = JointVerificationInput {
            k: scalar_matrix(&k_values),
            r: scalar_matrix(&r_values),
            j: empty,
            a: scalar_matrix(&a_values),
            alpha: &[0.4],
            x: &[0.2],
            y: &[0.18],
            h: 0.1,
            drive: &[0.01],
        };
        let bounds = verify_joint_error_bounds(&input, Interval::point(0.0).unwrap()).unwrap();
        for index in 0..=100 {
            let s = index as f64 / 100.0;
            let z = input.x[0] + s * (input.y[0] - input.x[0]);
            let force = -(2.0 * z + 0.4 * 0.5 * (0.5 * z).tanh()) + 0.01;
            let actual_defect = ((input.y[0] - input.x[0]) / input.h - force).abs();
            assert!(bounds.reconstruction_defect.upper() >= actual_defect);
        }
        assert!(bounds.gradient_lipschitz_upper >= 2.1);
        assert!(bounds.vector_field_lipschitz_upper >= 2.1);
    }

    #[test]
    fn coupled_sparse_operators_are_all_consumed() {
        let offsets = [0, 2, 4];
        let indices = [0, 1, 0, 1];
        let k_values = [2.0, -0.25, -0.25, 1.5];
        let r_values = [1.0, -0.1, -0.1, 1.2];
        let j_offsets = [0, 1, 2];
        let j_indices = [1, 0];
        let j_values = [0.2, -0.2];
        let a_values = [0.5, -0.25, 0.1, 0.2];
        let input = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &k_values),
            r: SparseMatrix::new(2, 2, &offsets, &indices, &r_values),
            j: SparseMatrix::new(2, 2, &j_offsets, &j_indices, &j_values),
            a: SparseMatrix::new(2, 2, &offsets, &indices, &a_values),
            alpha: &[0.2, 0.3],
            x: &[0.2, -0.1],
            y: &[0.25, -0.05],
            h: 0.1,
            drive: &[0.01, -0.02],
        };

        let envelope = verify_joint_step(&input).unwrap();
        assert_eq!(envelope.gradient.len(), 2);
        assert_eq!(envelope.residual_components.len(), 2);
        assert!(envelope.operator_bounds.j_row_abs_upper >= 0.2);
        assert!(envelope.operator_bounds.a_row_abs_upper >= 0.4);
        assert!(envelope.energy_difference.lower().is_finite());
        assert!(envelope.energy_difference.upper().is_finite());
    }

    #[test]
    fn positive_off_diagonals_use_absolute_gershgorin_radius() {
        let offsets = [0, 2, 4];
        let indices = [0, 1, 0, 1];
        let k_values = [2.0, 1.0, 1.0, 2.0];
        let r_values = [1.5, 0.25, 0.25, 1.25];
        let input = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &k_values),
            r: SparseMatrix::new(2, 2, &offsets, &indices, &r_values),
            j: SparseMatrix::new(2, 2, &[0, 1, 2], &[1, 0], &[0.2, -0.2]),
            a: SparseMatrix::new(1, 2, &[0, 2], &[0, 1], &[0.5, -0.25]),
            alpha: &[0.2],
            x: &[0.2, -0.1],
            y: &[0.19, -0.1],
            h: 0.02,
            drive: &[0.01, -0.02],
        };
        let envelope = verify_joint_step(&input).unwrap();
        assert!(envelope.operator_bounds.k_coercivity_lower > 0.0);
        assert!(envelope.operator_bounds.k_coercivity_lower <= 1.0);
        assert!(envelope.operator_bounds.r_coercivity_lower > 0.0);
        assert!(envelope.operator_bounds.r_coercivity_lower <= 1.0);
        assert!(envelope.operator_bounds.k_row_abs_upper >= 3.0);
        assert!(verify_joint_error_bounds(&input, Interval::point(0.0).unwrap()).is_ok());

        let asymmetric_k = [2.0, 1.0, 0.5, 2.0];
        let asymmetric = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &asymmetric_k),
            ..input
        };
        assert_eq!(
            verify_joint_step(&asymmetric),
            Err(VerifierError::InvalidStructure(MatrixRole::K))
        );
        let weak_k = [1.0, 1.0, 1.0, 1.0];
        let weak = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &weak_k),
            ..input
        };
        assert_eq!(
            verify_joint_step(&weak),
            Err(VerifierError::PositivityNotProven(MatrixRole::K))
        );
    }

    #[test]
    fn malformed_csr_and_capacity_are_rejected() {
        let values = [1.0, 1.0];
        let malformed = SparseMatrix::new(1, 1, &[0, 2], &[0, 0], &values);
        let valid_values = [1.0];
        let valid = scalar_matrix(&valid_values);
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let input = JointVerificationInput {
            k: malformed,
            r: valid,
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &[0.0],
            y: &[0.0],
            h: 0.1,
            drive: &[0.0],
        };
        assert_eq!(
            verify_joint_step(&input),
            Err(VerifierError::InvalidCsr(MatrixRole::K))
        );

        let states = [0.0; MAX_VERIFIED_N + 1];
        let oversized = JointVerificationInput {
            k: valid,
            r: valid,
            j: empty,
            a: SparseMatrix::new(0, 1, &[0], &[], &[]),
            alpha: &[],
            x: &states,
            y: &states,
            h: 0.1,
            drive: &states,
        };
        assert_eq!(
            verify_joint_step(&oversized),
            Err(VerifierError::CapacityExceeded)
        );
    }

    #[test]
    fn operator_structure_and_positivity_fail_closed() {
        let offsets = [0, 2, 4];
        let indices = [0, 1, 0, 1];
        let bad_k_values = [1.0, 0.25, 0.2, 1.0];
        let r_values = [1.0, -0.1, -0.1, 1.0];
        let bad_j_values = [0.2, 0.2];
        let j_offsets = [0, 1, 2];
        let j_indices = [1, 0];
        let empty_a = SparseMatrix::new(0, 2, &[0], &[], &[]);
        let base = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &bad_k_values),
            r: SparseMatrix::new(2, 2, &offsets, &indices, &r_values),
            j: SparseMatrix::new(2, 2, &j_offsets, &j_indices, &[-0.2, 0.2]),
            a: empty_a,
            alpha: &[],
            x: &[0.0, 0.0],
            y: &[0.0, 0.0],
            h: 0.1,
            drive: &[0.0, 0.0],
        };
        assert_eq!(
            verify_joint_step(&base),
            Err(VerifierError::InvalidStructure(MatrixRole::K))
        );

        let good_k_values = [1.0, -0.25, -0.25, 1.0];
        let bad_j = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &good_k_values),
            j: SparseMatrix::new(2, 2, &j_offsets, &j_indices, &bad_j_values),
            ..base
        };
        assert_eq!(
            verify_joint_step(&bad_j),
            Err(VerifierError::InvalidStructure(MatrixRole::J))
        );

        let weak_values = [0.25, -0.25, -0.25, 0.25];
        let weak = JointVerificationInput {
            k: SparseMatrix::new(2, 2, &offsets, &indices, &weak_values),
            j: SparseMatrix::new(2, 2, &j_offsets, &j_indices, &[-0.2, 0.2]),
            ..base
        };
        assert_eq!(
            verify_joint_step(&weak),
            Err(VerifierError::PositivityNotProven(MatrixRole::K))
        );
    }

    #[test]
    fn scalar_ranges_and_nonlinear_domain_are_rejected() {
        let values = [1.0];
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let a_values = [1.0];
        let base = JointVerificationInput {
            k: scalar_matrix(&values),
            r: scalar_matrix(&values),
            j: empty,
            a: scalar_matrix(&a_values),
            alpha: &[0.1],
            x: &[5.0],
            y: &[5.0],
            h: 0.1,
            drive: &[0.0],
        };
        assert_eq!(
            verify_joint_step(&base),
            Err(VerifierError::NonlinearArgumentOutOfRange)
        );

        let negative_alpha = JointVerificationInput {
            alpha: &[-0.1],
            x: &[0.0],
            y: &[0.0],
            ..base
        };
        assert_eq!(
            verify_joint_step(&negative_alpha),
            Err(VerifierError::InvalidAlpha)
        );

        let invalid_h = JointVerificationInput {
            alpha: &[0.1],
            x: &[0.0],
            y: &[0.0],
            h: 2.0,
            ..base
        };
        assert_eq!(
            verify_joint_step(&invalid_h),
            Err(VerifierError::InvalidStep)
        );
    }

    #[test]
    fn nonfinite_coefficients_states_and_dimension_mismatches_are_rejected() {
        let valid_values = [1.0];
        let invalid_values = [f64::NAN];
        let valid = scalar_matrix(&valid_values);
        let empty = SparseMatrix::new(1, 1, &[0, 0], &[], &[]);
        let empty_a = SparseMatrix::new(0, 1, &[0], &[], &[]);
        let base = JointVerificationInput {
            k: valid,
            r: valid,
            j: empty,
            a: empty_a,
            alpha: &[],
            x: &[0.0],
            y: &[0.0],
            h: 0.1,
            drive: &[0.0],
        };

        let bad_coefficient = JointVerificationInput {
            k: scalar_matrix(&invalid_values),
            ..base
        };
        assert_eq!(
            verify_joint_step(&bad_coefficient),
            Err(VerifierError::CoefficientOutOfRange(MatrixRole::K))
        );

        let bad_state = JointVerificationInput {
            x: &[f64::INFINITY],
            ..base
        };
        assert_eq!(
            verify_joint_step(&bad_state),
            Err(VerifierError::InvalidState)
        );

        let bad_dimension = JointVerificationInput { y: &[], ..base };
        assert_eq!(
            verify_joint_step(&bad_dimension),
            Err(VerifierError::InvalidDimension)
        );
    }
}
