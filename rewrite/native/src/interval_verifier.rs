//! Independent outward-interval verification kernel for the bounded ABI 2
//! sparse nonlinear step. This module does not enable any ABI certificate bit.

use crate::interval::{environment_supported, Interval, IntervalError};

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
/// These values are verifier diagnostics; ABI 2 certificate flags remain zero.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct JointErrorBounds {
    pub(crate) gradient_lipschitz_upper: f64,
    pub(crate) vector_field_lipschitz_upper: f64,
    pub(crate) contraction_upper: f64,
    pub(crate) endpoint_error: Interval,
    pub(crate) reconstruction_defect: Interval,
    pub(crate) time_error: Interval,
}

/// Independently reconstruct the bounded nonlinear discrete gradient, fixed-point
/// residual and endpoint energy difference using outward interval arithmetic.
///
/// This is only a local arithmetic foundation. It does not prove the contraction
/// factor, temporal defect, inherited initial error, omitted-boundary closure or
/// build provenance required by a complete ABI 2 certificate.
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
        if hull.lower() < -1.0 || hull.upper() > 1.0 {
            return Err(VerifierError::NonlinearArgumentOutOfRange);
        }
        // The AVF quotient equals the integral mean of tanh along the segment
        // between A*x and A*y. Monotonicity puts that mean inside tanh(hull),
        // including the coincident and near-coincident cases without subtraction.
        let quotient = finite_interval(hull.tanh()?)?;
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
/// event boundary, or the surrounding ABI. It makes no production certificate.
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
    let operator = finite_interval(
        Interval::point(envelope.operator_bounds.j_row_abs_upper)?
            .add(Interval::point(envelope.operator_bounds.r_row_abs_upper)?)?,
    )?;
    // K is symmetric and J is skew-symmetric; for either, ||.||_2 is bounded
    // by the verified maximum absolute row sum. Each nonlinear Hessian term
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
        if ax[row].lower() < -1.0 || ax[row].upper() > 1.0 {
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
    let defect = finite_interval(
        interval_l2_norm(&defect_at_x)?
            .add(vector_field_lipschitz.mul(interval_l2_norm(&displacement)?)?)?,
    )?;
    let reconstruction_defect = Interval::new(0.0, defect.upper())?;

    // Existing analytic Interval::exp is valid only through argument 2.
    // Integral_0^h exp(Ls) ds <= h exp(Lh), including L=0. This is wider than
    // expm1(Lh)/L but avoids an unbounded platform transcendental or cancellation.
    let lh = finite_interval(step.mul(vector_field_lipschitz)?)?;
    if lh.upper() > 2.0 {
        return Err(VerifierError::TemporalBoundUnavailable);
    }
    let amplification = finite_interval(Interval::new(0.0, lh.upper())?.exp()?)?;
    let time_upper = finite_interval(
        amplification.mul(inherited_error.add(step.mul(reconstruction_defect)?)?)?,
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
                if value > 0.0 || matrix.entry(column, row) != Some(value) {
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
        if a_state[row].lower() < -1.0 || a_state[row].upper() > 1.0 {
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
        let bad_k_values = [1.0, 0.25, 0.25, 1.0];
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
            x: &[2.0],
            y: &[2.0],
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
