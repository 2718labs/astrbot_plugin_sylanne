//! Outward-rounded binary64 interval arithmetic for certificate verification.
//!
//! This module deliberately does not use platform transcendental functions for
//! certified bounds. Its tests exercise the arithmetic contract before the
//! implementation is connected to ABI 2.

use std::hint::black_box;

/// Why an outward interval operation could not produce a usable enclosure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntervalError {
    UnsupportedEnvironment,
    NaN,
    InvalidBounds,
    Indeterminate,
    DivisionByZero,
    NegativeSquareRoot,
    UnsupportedTranscendental,
}

/// A closed interval over the extended binary64 numbers.
///
/// Bounds may be infinite, but never NaN. Arithmetic which is indeterminate in
/// the extended reals (for example, zero times infinity) returns an error rather
/// than manufacturing a certificate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Interval {
    lower: f64,
    upper: f64,
}

/// Returns whether the target and observable floating-point environment meet
/// the runtime assumptions used by this module.
///
/// The architecture restriction excludes x87 excess precision. Normal Rust
/// scalar `f64` operations on the admitted targets use strict binary64
/// round-to-nearest-even semantics. Each primitive is kept in its own
/// expression, so there is no multiply-add contraction opportunity. The runtime
/// probes additionally reject observable non-nearest rounding and
/// flush-to-zero/denormals-are-zero.
///
/// A `true` result cannot detect hostile or nonstandard external LLVM options.
/// The release build must separately enforce that no fast-math, `nnan`, `ninf`,
/// `afn`, reciprocal approximation, or denormal-mode attributes are present.
pub(crate) fn environment_supported() -> bool {
    let supported_target = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
        && cfg!(any(
            target_os = "windows",
            target_os = "linux",
            target_os = "macos"
        ));
    if !supported_target
        || f64::RADIX != 2
        || f64::MANTISSA_DIGITS != 53
        || f64::MIN_EXP != -1021
        || f64::MAX_EXP != 1024
    {
        return false;
    }

    // black_box prevents these checks from becoming compile-time constants.
    let one = black_box(1.0_f64);
    let half_ulp = black_box(f64::EPSILON / 2.0);
    let three_half_ulps = black_box(3.0 * f64::EPSILON / 2.0);
    let min_normal = black_box(f64::MIN_POSITIVE);
    let half = black_box(0.5_f64);
    let min_subnormal = black_box(f64::from_bits(1));
    let ten = black_box(10.0_f64);
    let two = black_box(2.0_f64);

    (one + half_ulp).to_bits() == one.to_bits()
        && (one + three_half_ulps).to_bits() == 0x3ff0_0000_0000_0002
        && (min_normal * half).to_bits() == (1_u64 << 51)
        && (min_subnormal + min_subnormal).to_bits() == 2
        && (one / ten).to_bits() == 0x3fb9_9999_9999_999a
        && two.sqrt().to_bits() == 0x3ff6_a09e_667f_3bcd
}

fn require_environment() -> Result<(), IntervalError> {
    if environment_supported() {
        Ok(())
    } else {
        Err(IntervalError::UnsupportedEnvironment)
    }
}

/// The least representable binary64 number strictly greater than `value`.
/// NaN and positive infinity are returned unchanged.
pub(crate) fn next_up(value: f64) -> f64 {
    if value.is_nan() || value == f64::INFINITY {
        return value;
    }
    if value == 0.0 {
        return f64::from_bits(1);
    }
    let bits = value.to_bits();
    if value > 0.0 {
        f64::from_bits(bits + 1)
    } else {
        f64::from_bits(bits - 1)
    }
}

/// The greatest representable binary64 number strictly less than `value`.
/// NaN and negative infinity are returned unchanged.
pub(crate) fn next_down(value: f64) -> f64 {
    if value.is_nan() || value == f64::NEG_INFINITY {
        return value;
    }
    if value == 0.0 {
        return -f64::from_bits(1);
    }
    let bits = value.to_bits();
    if value > 0.0 {
        f64::from_bits(bits - 1)
    } else {
        f64::from_bits(bits + 1)
    }
}

impl Interval {
    pub(crate) fn new(lower: f64, upper: f64) -> Result<Self, IntervalError> {
        require_environment()?;
        Self::from_validated_bounds(lower, upper)
    }

    pub(crate) fn point(value: f64) -> Result<Self, IntervalError> {
        Self::new(value, value)
    }

    pub(crate) fn lower(self) -> f64 {
        self.lower
    }

    pub(crate) fn upper(self) -> f64 {
        self.upper
    }

    pub(crate) fn add(self, rhs: Self) -> Result<Self, IntervalError> {
        require_environment()?;
        Self::outward_pair(self.lower + rhs.lower, self.upper + rhs.upper)
    }

    pub(crate) fn sub(self, rhs: Self) -> Result<Self, IntervalError> {
        require_environment()?;
        Self::outward_pair(self.lower - rhs.upper, self.upper - rhs.lower)
    }

    pub(crate) fn mul(self, rhs: Self) -> Result<Self, IntervalError> {
        require_environment()?;
        let candidates = [
            self.lower * rhs.lower,
            self.lower * rhs.upper,
            self.upper * rhs.lower,
            self.upper * rhs.upper,
        ];
        Self::outward_extrema(candidates)
    }

    pub(crate) fn div(self, rhs: Self) -> Result<Self, IntervalError> {
        require_environment()?;
        if rhs.lower <= 0.0 && rhs.upper >= 0.0 {
            return Err(IntervalError::DivisionByZero);
        }
        let candidates = [
            self.lower / rhs.lower,
            self.lower / rhs.upper,
            self.upper / rhs.lower,
            self.upper / rhs.upper,
        ];
        Self::outward_extrema(candidates)
    }

    pub(crate) fn sqrt(self) -> Result<Self, IntervalError> {
        require_environment()?;
        if self.lower < 0.0 {
            return Err(IntervalError::NegativeSquareRoot);
        }
        let lower = next_down(self.lower.sqrt()).max(0.0);
        let upper = next_up(self.upper.sqrt());
        Self::from_validated_bounds(lower, upper)
    }

    /// Analytic enclosure of `exp(self)` for finite `self` within `[-2, 2]`.
    ///
    /// Each endpoint uses the degree-25 Taylor polynomial at zero. The Lagrange
    /// remainder is bounded by `9 * 2^26 / 26!`: `e < 3` follows from
    /// `n! >= 2^(n-1)` for `n >= 2`, hence `e^|x| < 9` on this domain. Every
    /// polynomial and remainder operation goes through outward interval
    /// arithmetic; no platform exponential is used.
    pub(crate) fn exp(self) -> Result<Self, IntervalError> {
        require_environment()?;
        if !self.lower.is_finite()
            || !self.upper.is_finite()
            || self.lower < -2.0
            || self.upper > 2.0
        {
            return Err(IntervalError::UnsupportedTranscendental);
        }
        let lower = Self::exp_scalar(self.lower)?;
        let upper = Self::exp_scalar(self.upper)?;
        Self::from_validated_bounds(lower.lower.max(0.0), upper.upper)
    }

    /// Analytic enclosure of `tanh(self)` for finite `self` within `[-1, 1]`.
    ///
    /// For a nonnegative endpoint this evaluates
    /// `(1 - exp(-2x)) / (1 + exp(-2x))` using the certified exponential above;
    /// oddness handles negative endpoints. No platform hyperbolic function is
    /// used.
    pub(crate) fn tanh(self) -> Result<Self, IntervalError> {
        require_environment()?;
        if !self.lower.is_finite()
            || !self.upper.is_finite()
            || self.lower < -1.0
            || self.upper > 1.0
        {
            return Err(IntervalError::UnsupportedTranscendental);
        }
        let lower = Self::tanh_scalar(self.lower)?;
        let upper = Self::tanh_scalar(self.upper)?;
        Self::from_validated_bounds(lower.lower.max(-1.0), upper.upper.min(1.0))
    }

    /// Analytic enclosure of `ln(cosh(self))` on finite `self` within `[-1, 1]`.
    ///
    /// `cosh(x) - 1` is first enclosed using certified exponentials, then
    /// `log1p(v) = 2 * atanh(v / (2 + v))` is evaluated for `v in [0, 1]`.
    /// The positive atanh tail is bounded by a geometric series with an explicit
    /// denominator. No platform logarithm or hyperbolic function is used.
    pub(crate) fn log_cosh(self) -> Result<Self, IntervalError> {
        require_environment()?;
        if !self.lower.is_finite()
            || !self.upper.is_finite()
            || self.lower < -1.0
            || self.upper > 1.0
        {
            return Err(IntervalError::UnsupportedTranscendental);
        }

        let minimum_abs = if self.lower <= 0.0 && self.upper >= 0.0 {
            0.0
        } else {
            self.lower.abs().min(self.upper.abs())
        };
        let maximum_abs = self.lower.abs().max(self.upper.abs());
        let lower = Self::log_cosh_nonnegative_scalar(minimum_abs)?;
        let upper = Self::log_cosh_nonnegative_scalar(maximum_abs)?;
        Self::from_validated_bounds(lower.lower.max(0.0), upper.upper)
    }

    fn exp_scalar(value: f64) -> Result<Self, IntervalError> {
        if value == 0.0 {
            return Self::point(1.0);
        }

        let x = Self::point(value)?;
        let mut term = Self::point(1.0)?;
        let mut sum = term;
        for denominator in 1..=25 {
            term = term.mul(x)?.div(Self::point(denominator as f64)?)?;
            sum = sum.add(term)?;
        }

        let remainder = Self::exp_remainder_bound()?;
        sum.add(Self::new(-remainder, remainder)?)
    }

    fn exp_remainder_bound() -> Result<f64, IntervalError> {
        let mut remainder = Self::point(9.0)?;
        for denominator in 1..=26 {
            remainder = remainder
                .mul(Self::point(2.0)?)?
                .div(Self::point(denominator as f64)?)?;
        }
        Ok(remainder.upper)
    }

    fn tanh_scalar(value: f64) -> Result<Self, IntervalError> {
        if value == 0.0 {
            return Self::point(0.0);
        }

        let magnitude = value.abs();
        // Multiplication by two is exact throughout the admitted domain.
        let exponential = Self::exp_scalar(-2.0 * magnitude)?;
        let one = Self::point(1.0)?;
        let numerator = one.sub(exponential)?;
        let denominator = one.add(exponential)?;
        let positive = numerator.div(denominator)?;
        let positive =
            Self::from_validated_bounds(positive.lower.max(0.0), positive.upper.min(1.0))?;
        if value > 0.0 {
            Ok(positive)
        } else {
            Self::from_validated_bounds(-positive.upper, -positive.lower)
        }
    }

    fn log_cosh_nonnegative_scalar(value: f64) -> Result<Self, IntervalError> {
        if value == 0.0 {
            return Self::point(0.0);
        }

        let positive = Self::exp_scalar(value)?;
        let negative = Self::exp_scalar(-value)?;
        let cosh = positive.add(negative)?.div(Self::point(2.0)?)?;
        let shifted = cosh.sub(Self::point(1.0)?)?;
        if shifted.upper > 1.0 {
            return Err(IntervalError::UnsupportedTranscendental);
        }
        let shifted = Self::from_validated_bounds(shifted.lower.max(0.0), shifted.upper)?;
        Self::log1p_nonnegative(shifted)
    }

    fn log1p_nonnegative(value: Self) -> Result<Self, IntervalError> {
        if !value.lower.is_finite()
            || !value.upper.is_finite()
            || value.lower < 0.0
            || value.upper > 1.0
        {
            return Err(IntervalError::UnsupportedTranscendental);
        }
        let lower = Self::log1p_nonnegative_scalar(value.lower)?;
        let upper = Self::log1p_nonnegative_scalar(value.upper)?;
        Self::from_validated_bounds(lower.lower.max(0.0), upper.upper)
    }

    fn log1p_nonnegative_scalar(value: f64) -> Result<Self, IntervalError> {
        if value == 0.0 {
            return Self::point(0.0);
        }

        let v = Self::point(value)?;
        let z = v.div(Self::point(2.0)?.add(v)?)?;
        let z_squared = z.mul(z)?;
        let mut power = z;
        let mut sum = Self::point(0.0)?;
        const TERMS: usize = 18;
        for index in 0..TERMS {
            let denominator = (2 * index + 1) as f64;
            sum = sum.add(power.div(Self::point(denominator)?)?)?;
            power = power.mul(z_squared)?;
        }

        let polynomial = Self::point(2.0)?.mul(sum)?;
        let tail_denominator =
            Self::point((2 * TERMS + 1) as f64)?.mul(Self::point(1.0)?.sub(z_squared)?)?;
        let tail = Self::point(2.0)?.mul(power)?.div(tail_denominator)?;
        polynomial.add(Self::new(0.0, tail.upper.max(0.0))?)
    }

    fn outward_pair(lower_nearest: f64, upper_nearest: f64) -> Result<Self, IntervalError> {
        if lower_nearest.is_nan() || upper_nearest.is_nan() {
            return Err(IntervalError::Indeterminate);
        }
        Self::from_validated_bounds(next_down(lower_nearest), next_up(upper_nearest))
    }

    fn outward_extrema(candidates: [f64; 4]) -> Result<Self, IntervalError> {
        if candidates.iter().any(|candidate| candidate.is_nan()) {
            return Err(IntervalError::Indeterminate);
        }
        let mut minimum = candidates[0];
        let mut maximum = candidates[0];
        for candidate in candidates.into_iter().skip(1) {
            minimum = minimum.min(candidate);
            maximum = maximum.max(candidate);
        }
        Self::from_validated_bounds(next_down(minimum), next_up(maximum))
    }

    fn from_validated_bounds(lower: f64, upper: f64) -> Result<Self, IntervalError> {
        if lower.is_nan() || upper.is_nan() {
            return Err(IntervalError::NaN);
        }
        if lower > upper {
            return Err(IntervalError::InvalidBounds);
        }
        Ok(Self { lower, upper })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_contains(interval: Interval, value: f64) {
        assert!(
            interval.lower() <= value && value <= interval.upper(),
            "{value:?} not contained in {interval:?}"
        );
    }

    #[test]
    fn recognizes_required_binary64_environment() {
        assert!(environment_supported());
    }

    #[test]
    fn adjacent_values_cross_signed_zero_and_stop_at_infinity() {
        assert_eq!(next_up(0.0), f64::from_bits(1));
        assert_eq!(next_up(-0.0), f64::from_bits(1));
        assert_eq!(next_down(0.0), -f64::from_bits(1));
        assert_eq!(next_down(-0.0), -f64::from_bits(1));
        assert_eq!(next_up(f64::INFINITY), f64::INFINITY);
        assert_eq!(next_down(f64::NEG_INFINITY), f64::NEG_INFINITY);
        assert_eq!(next_down(f64::INFINITY), f64::MAX);
        assert_eq!(next_up(f64::NEG_INFINITY), -f64::MAX);
        assert_eq!(next_up(-f64::from_bits(1)).to_bits(), (-0.0_f64).to_bits());
        assert_eq!(next_down(f64::from_bits(1)).to_bits(), 0.0_f64.to_bits());
    }

    #[test]
    fn construction_rejects_nan_and_reversed_bounds() {
        assert_eq!(Interval::new(f64::NAN, 1.0), Err(IntervalError::NaN));
        assert_eq!(Interval::new(2.0, 1.0), Err(IntervalError::InvalidBounds));
        assert_eq!(Interval::point(f64::NAN), Err(IntervalError::NaN));
    }

    #[test]
    fn addition_encloses_half_ulp_tie() {
        let one = Interval::point(1.0).unwrap();
        let half_ulp = Interval::point(f64::EPSILON / 2.0).unwrap();
        let sum = one.add(half_ulp).unwrap();
        assert_eq!(sum.lower(), next_down(1.0));
        assert_eq!(sum.upper(), next_up(1.0));
        assert!(sum.lower() < 1.0);
        assert!(sum.upper() > 1.0);
    }

    #[test]
    fn subtraction_widens_exact_cancellation() {
        let value = Interval::point(7.0).unwrap();
        let difference = value.sub(value).unwrap();
        assert_eq!(difference.lower(), -f64::from_bits(1));
        assert_eq!(difference.upper(), f64::from_bits(1));
        assert_contains(difference, 0.0);
    }

    #[test]
    fn multiplication_selects_all_endpoint_combinations() {
        let lhs = Interval::new(-2.0, 3.0).unwrap();
        let rhs = Interval::new(-5.0, 7.0).unwrap();
        let product = lhs.mul(rhs).unwrap();
        assert_eq!(product.lower(), next_down(-15.0));
        assert_eq!(product.upper(), next_up(21.0));
        assert_contains(product, -15.0);
        assert_contains(product, 21.0);
    }

    #[test]
    fn multiplication_handles_gradual_underflow_and_overflow() {
        let half_min_normal = Interval::point(f64::MIN_POSITIVE)
            .unwrap()
            .mul(Interval::point(0.5).unwrap())
            .unwrap();
        let exact_subnormal = f64::from_bits(1_u64 << 51);
        assert_contains(half_min_normal, exact_subnormal);
        assert!(half_min_normal.lower() < exact_subnormal);
        assert!(half_min_normal.upper() > exact_subnormal);

        let overflow = Interval::point(f64::MAX)
            .unwrap()
            .mul(Interval::point(2.0).unwrap())
            .unwrap();
        assert_eq!(overflow.lower(), f64::MAX);
        assert_eq!(overflow.upper(), f64::INFINITY);

        let negative_overflow = Interval::point(-f64::MAX)
            .unwrap()
            .mul(Interval::point(2.0).unwrap())
            .unwrap();
        assert_eq!(negative_overflow.lower(), f64::NEG_INFINITY);
        assert_eq!(negative_overflow.upper(), -f64::MAX);
    }

    #[test]
    fn division_encloses_sign_extrema_and_rejects_zero_crossing() {
        let quotient = Interval::new(-6.0, 9.0)
            .unwrap()
            .div(Interval::new(2.0, 3.0).unwrap())
            .unwrap();
        assert_contains(quotient, -3.0);
        assert_contains(quotient, 4.5);

        let negative_denominator = Interval::new(-6.0, 9.0)
            .unwrap()
            .div(Interval::new(-3.0, -2.0).unwrap())
            .unwrap();
        assert_contains(negative_denominator, -4.5);
        assert_contains(negative_denominator, 3.0);

        assert_eq!(
            Interval::point(1.0)
                .unwrap()
                .div(Interval::new(-1.0, 1.0).unwrap()),
            Err(IntervalError::DivisionByZero)
        );
        for zero in [0.0, -0.0] {
            assert_eq!(
                Interval::point(1.0)
                    .unwrap()
                    .div(Interval::point(zero).unwrap()),
                Err(IntervalError::DivisionByZero)
            );
        }
    }

    #[test]
    fn division_handles_tie_underflow_and_overflow() {
        let underflow = Interval::point(f64::from_bits(1))
            .unwrap()
            .div(Interval::point(2.0).unwrap())
            .unwrap();
        assert_eq!(underflow.lower(), -f64::from_bits(1));
        assert_eq!(underflow.upper(), f64::from_bits(1));

        let overflow = Interval::point(f64::MAX)
            .unwrap()
            .div(Interval::point(f64::from_bits(1)).unwrap())
            .unwrap();
        assert_eq!(overflow.lower(), f64::MAX);
        assert_eq!(overflow.upper(), f64::INFINITY);
    }

    #[test]
    fn sqrt_encloses_irrational_result_and_rejects_negative_domain() {
        let root = Interval::point(2.0).unwrap().sqrt().unwrap();
        let candidate = 2.0_f64.sqrt();
        assert_eq!(root.lower(), next_down(candidate));
        assert_eq!(root.upper(), next_up(candidate));
        assert_contains(root, candidate);
        assert_eq!(
            Interval::new(-1.0, 4.0).unwrap().sqrt(),
            Err(IntervalError::NegativeSquareRoot)
        );

        let negative_zero = Interval::point(-0.0).unwrap().sqrt().unwrap();
        assert_eq!(negative_zero.lower().to_bits(), 0.0_f64.to_bits());
        assert_eq!(negative_zero.upper(), f64::from_bits(1));

        let infinite = Interval::point(f64::INFINITY).unwrap().sqrt().unwrap();
        assert_eq!(infinite.lower(), f64::MAX);
        assert_eq!(infinite.upper(), f64::INFINITY);

        let smallest = Interval::point(f64::from_bits(1)).unwrap().sqrt().unwrap();
        assert!(smallest.lower() > 0.0);
        assert!(smallest.lower() < smallest.upper());
        assert_contains(smallest, f64::from_bits(1).sqrt());
    }

    #[test]
    fn addition_and_subtraction_enclose_both_overflow_signs() {
        let positive = Interval::point(f64::MAX)
            .unwrap()
            .add(Interval::point(f64::MAX).unwrap())
            .unwrap();
        assert_eq!(positive.lower(), f64::MAX);
        assert_eq!(positive.upper(), f64::INFINITY);

        let negative = Interval::point(-f64::MAX)
            .unwrap()
            .sub(Interval::point(f64::MAX).unwrap())
            .unwrap();
        assert_eq!(negative.lower(), f64::NEG_INFINITY);
        assert_eq!(negative.upper(), -f64::MAX);
    }

    #[test]
    fn indeterminate_extended_operations_fail_closed() {
        assert_eq!(
            Interval::point(0.0)
                .unwrap()
                .mul(Interval::point(f64::INFINITY).unwrap()),
            Err(IntervalError::Indeterminate)
        );
        assert_eq!(
            Interval::point(f64::INFINITY)
                .unwrap()
                .add(Interval::point(f64::NEG_INFINITY).unwrap()),
            Err(IntervalError::Indeterminate)
        );
    }

    #[test]
    fn analytic_exp_encloses_supported_points_and_intervals() {
        let zero = Interval::point(0.0).unwrap().exp().unwrap();
        assert_contains(zero, 1.0);

        for value in [-2.0_f64, -1.0, -0.125, 0.125, 1.0, 2.0] {
            let enclosure = Interval::point(value).unwrap().exp().unwrap();
            assert_contains(enclosure, value.exp());
            assert!(enclosure.upper() - enclosure.lower() < 1.0e-12);
        }

        let enclosure = Interval::new(-1.0, 1.0).unwrap().exp().unwrap();
        assert_contains(enclosure, (-1.0_f64).exp());
        assert_contains(enclosure, 1.0_f64.exp());
    }

    #[test]
    fn analytic_tanh_encloses_supported_points_and_preserves_oddness() {
        let zero = Interval::point(0.0).unwrap().tanh().unwrap();
        assert_contains(zero, 0.0);

        for value in [-1.0_f64, -0.5, -0.125, 0.125, 0.5, 1.0] {
            let enclosure = Interval::point(value).unwrap().tanh().unwrap();
            assert_contains(enclosure, value.tanh());
            assert!(enclosure.upper() - enclosure.lower() < 1.0e-11);
        }

        let positive = Interval::point(0.75).unwrap().tanh().unwrap();
        let negative = Interval::point(-0.75).unwrap().tanh().unwrap();
        assert_eq!(negative.lower(), -positive.upper());
        assert_eq!(negative.upper(), -positive.lower());
    }

    #[test]
    fn analytic_log_cosh_encloses_supported_points_and_cross_zero_interval() {
        let zero = Interval::point(0.0).unwrap().log_cosh().unwrap();
        assert_contains(zero, 0.0);

        for value in [-1.0_f64, -0.5, 0.5, 1.0] {
            let enclosure = Interval::point(value).unwrap().log_cosh().unwrap();
            let oracle = value.cosh().ln();
            assert_contains(enclosure, oracle);
            assert!(enclosure.upper() - enclosure.lower() < 1.0e-10);
        }

        let crossing = Interval::new(-0.75, 0.25).unwrap().log_cosh().unwrap();
        assert_contains(crossing, 0.0);
        assert_contains(crossing, 0.75_f64.cosh().ln());
    }

    #[test]
    fn analytic_transcendentals_reject_inputs_outside_validated_domains() {
        for bounds in [(2.0, next_up(2.0)), (-3.0, -2.0), (1.0, f64::INFINITY)] {
            assert_eq!(
                Interval::new(bounds.0, bounds.1).unwrap().exp(),
                Err(IntervalError::UnsupportedTranscendental)
            );
        }
        for value in [next_up(1.0), -next_up(1.0), f64::INFINITY] {
            let interval = Interval::point(value).unwrap();
            assert_eq!(
                interval.tanh(),
                Err(IntervalError::UnsupportedTranscendental)
            );
            assert_eq!(
                interval.log_cosh(),
                Err(IntervalError::UnsupportedTranscendental)
            );
        }
    }

    #[test]
    fn analytic_transcendentals_enclose_dense_platform_oracles() {
        // Platform functions are test oracles only; production enclosures above
        // do not call them. The proof obligation remains the analytic remainder.
        for index in 0..=512 {
            let x = -2.0 + 4.0 * (index as f64) / 512.0;
            assert_contains(Interval::point(x).unwrap().exp().unwrap(), x.exp());
            if (-1.0..=1.0).contains(&x) {
                assert_contains(Interval::point(x).unwrap().tanh().unwrap(), x.tanh());
                assert_contains(
                    Interval::point(x).unwrap().log_cosh().unwrap(),
                    x.cosh().ln(),
                );
            }
        }

        for x in [f64::from_bits(1), -f64::from_bits(1)] {
            assert_contains(Interval::point(x).unwrap().exp().unwrap(), x.exp());
            assert_contains(Interval::point(x).unwrap().tanh().unwrap(), x.tanh());
            assert_contains(
                Interval::point(x).unwrap().log_cosh().unwrap(),
                x.cosh().ln(),
            );
        }
    }
}
