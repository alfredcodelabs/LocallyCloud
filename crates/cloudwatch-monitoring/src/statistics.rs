//! Period bucketing and statistics shared by `GetMetricStatistics` and `GetMetricData`.
use super::*;

/// A CloudWatch statistic parsed at the API boundary.
///
/// Percentiles use the nearest-rank method over the raw samples stored in the period:
/// the samples are sorted ascending and the value at rank `ceil(p / 100 * n)` (clamped to
/// `1..=n`) is returned. No interpolation is performed, so the result is always one of the
/// published samples.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Statistic {
    SampleCount,
    Sum,
    Average,
    Minimum,
    Maximum,
    Percentile(f64),
}

impl Statistic {
    /// Parse one of the five basic statistics accepted by `GetMetricStatistics`.
    pub(crate) fn parse_basic(value: &str) -> Option<Self> {
        match value {
            "SampleCount" => Some(Self::SampleCount),
            "Sum" => Some(Self::Sum),
            "Average" => Some(Self::Average),
            "Minimum" => Some(Self::Minimum),
            "Maximum" => Some(Self::Maximum),
            _ => None,
        }
    }

    /// Parse a basic statistic or a percentile such as `p90` or `p99.9`.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Self::parse_basic(value).or_else(|| parse_percentile(value).map(Self::Percentile))
    }

    /// Compute the statistic; returns `None` for an empty sample set.
    pub(crate) fn compute(self, values: &[f64]) -> Option<f64> {
        if values.is_empty() {
            return None;
        }
        let sum = || values.iter().sum::<f64>();
        Some(match self {
            Self::SampleCount => values.len() as f64,
            Self::Sum => sum(),
            Self::Average => sum() / values.len() as f64,
            Self::Minimum => values.iter().copied().fold(f64::INFINITY, f64::min),
            Self::Maximum => values.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            Self::Percentile(percentile) => {
                let mut sorted = values.to_vec();
                sorted.sort_by(f64::total_cmp);
                // Exact integer arithmetic: `p / 100 * n` in floating point overshoots whole
                // ranks (p7 with n = 100 would give rank 8). Parsing allows at most 10
                // decimals, so the scaled percentile is exact.
                let scaled = (percentile * PERCENTILE_SCALE as f64).round() as u128;
                let denominator = 100 * PERCENTILE_SCALE;
                let rank = (scaled * sorted.len() as u128).div_ceil(denominator) as usize;
                let index = rank.clamp(1, sorted.len()) - 1;
                sorted.get(index).copied()?
            }
        })
    }
}

/// 10^10: percentiles carry at most 10 decimal places.
const PERCENTILE_SCALE: u128 = 10_000_000_000;

/// Accept `pNN`, `pNN.N` (up to 10 decimal places) with a value between 0 and 100.
fn parse_percentile(value: &str) -> Option<f64> {
    let number = value.strip_prefix('p')?;
    let (integer, fraction) = match number.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (number, None),
    };
    let digits = |part: &str, max: usize| {
        !part.is_empty() && part.len() <= max && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !digits(integer, 3) || fraction.is_some_and(|fraction| !digits(fraction, 10)) {
        return None;
    }
    number
        .parse::<f64>()
        .ok()
        .filter(|percentile| (0.0..=100.0).contains(percentile))
}

/// Convert a validated period in seconds into milliseconds.
pub(crate) fn period_millis(period: u64) -> Result<i64, MonitoringError> {
    if period == 0 {
        return Err(MonitoringError::InvalidParameter(
            "Period must be positive".into(),
        ));
    }
    i64::try_from(period)
        .ok()
        .and_then(|period| period.checked_mul(1_000))
        .ok_or_else(|| MonitoringError::InvalidParameter("Period is too large".into()))
}

/// Group samples into epoch-aligned periods. With `by_unit`, samples published with different
/// units land in separate buckets (as `GetMetricStatistics` reports them); otherwise every
/// sample in the period is aggregated together and the unit key is `None`.
pub(crate) fn bucket_values(
    points: Vec<MetricPoint>,
    period_ms: i64,
    by_unit: bool,
) -> BTreeMap<(i64, Option<&'static str>), Vec<f64>> {
    let mut buckets: BTreeMap<(i64, Option<&'static str>), Vec<f64>> = BTreeMap::new();
    for point in points {
        let bucket = point.timestamp_ms.div_euclid(period_ms) * period_ms;
        let unit = by_unit.then(|| point.unit.map(MetricUnit::as_str).unwrap_or("None"));
        buckets.entry((bucket, unit)).or_default().push(point.value);
    }
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_parsing_accepts_only_documented_shapes() {
        assert_eq!(Statistic::parse("p99"), Some(Statistic::Percentile(99.0)));
        assert_eq!(Statistic::parse("p99.9"), Some(Statistic::Percentile(99.9)));
        assert_eq!(Statistic::parse("p100"), Some(Statistic::Percentile(100.0)));
        assert_eq!(Statistic::parse("p0"), Some(Statistic::Percentile(0.0)));
        for invalid in [
            "p",
            "p101",
            "p-1",
            "p9.",
            "p.9",
            "P90",
            "p1e2",
            "p99.12345678901",
            "pNaN",
            "tm99",
            "Median",
        ] {
            assert_eq!(Statistic::parse(invalid), None, "{invalid}");
        }
        assert_eq!(Statistic::parse_basic("p90"), None);
    }

    #[test]
    fn nearest_rank_percentiles() {
        let values: Vec<f64> = (1..=10).rev().map(f64::from).collect();
        let percentile = |p| Statistic::Percentile(p).compute(&values).unwrap();
        assert_eq!(percentile(50.0), 5.0);
        assert_eq!(percentile(90.0), 9.0);
        assert_eq!(percentile(91.0), 10.0);
        assert_eq!(percentile(99.9), 10.0);
        assert_eq!(percentile(100.0), 10.0);
        assert_eq!(percentile(0.0), 1.0);
        assert_eq!(percentile(10.0), 1.0);
        assert_eq!(percentile(10.5), 2.0);
        assert_eq!(Statistic::Percentile(50.0).compute(&[]), None);
        // Cases where `p / 100 * n` overshoots a whole rank in floating point.
        for (p, n, rank) in [(7.0, 100, 7), (14.0, 50, 7), (3.5, 200, 7), (7.2, 125, 9)] {
            let values: Vec<f64> = (1..=n).map(f64::from).collect();
            assert_eq!(
                Statistic::Percentile(p).compute(&values),
                Some(f64::from(rank)),
                "p{p} n={n}"
            );
        }
        assert_eq!(Statistic::Average.compute(&values), Some(5.5));
    }
}
