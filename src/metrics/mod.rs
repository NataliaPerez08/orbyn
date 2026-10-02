//! Capacity and utilization processing.
//!
//! Capacity is a current allocation (CPU model/cores, RAM). Utilization is a
//! time-series of samples. A single sample is always a snapshot and must never
//! be presented as sufficient historical evidence for right-sizing.
//!
//! Windows are summarized into avg/p95/p99/peak statistics and assigned a
//! [`SampleConfidence`] tier from the number of samples and their validity,
//! so consumers (CLI reports, right-sizing rules) can weigh evidence
//! instead of trusting any single sample. The window also carries its
//! temporal span: right-sizing requires both high-confidence samples and
//! an observation window of at least
//! [`MIN_WINDOW_HOURS_FOR_RIGHT_SIZING`] hours (one meeting week).
//!
//! A window long enough to hold two right-sizing windows is additionally
//! split into a prior and a recent half ([`WindowComparison`]) so a trend can
//! be read without treating one busy week as a permanent baseline.

use chrono::{DateTime, Utc};

use crate::domain::MetricSample;

/// Aggregation over a batch of resource samples within an observation window.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct WindowStats {
    pub sample_count: usize,
    /// Oldest valid sample time in the window.
    pub window_start: Option<DateTime<Utc>>,
    /// Newest valid sample time in the window.
    pub window_end: Option<DateTime<Utc>>,
    /// `(end - start)` in hours; `None` when the window has no span.
    pub span_hours: Option<f64>,
    pub cpu_avg_percent: Option<f64>,
    pub cpu_p95_percent: Option<f64>,
    pub cpu_p99_percent: Option<f64>,
    pub cpu_peak_percent: Option<f64>,
    pub ram_avg_mb: Option<f64>,
    pub ram_p95_mb: Option<f64>,
    pub ram_p99_mb: Option<f64>,
    pub ram_peak_mb: Option<f64>,
    /// Swap utilization, the paging signal behind `rs.swap-pressure`.
    pub swap_avg_mb: Option<f64>,
    pub swap_p95_mb: Option<f64>,
    pub swap_p99_mb: Option<f64>,
    pub swap_peak_mb: Option<f64>,
    pub confidence: SampleConfidence,
    /// Week-over-week split, present only when the window spans two full
    /// right-sizing windows and both halves carry enough samples.
    pub comparison: Option<WindowComparison>,
}

/// A window split into a prior and a recent half, both one right-sizing week
/// long, so a change in utilization can be shown with the numbers behind it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct WindowComparison {
    /// Length of each compared half, in hours.
    pub sub_window_hours: f64,
    pub prior_sample_count: usize,
    pub recent_sample_count: usize,
    pub prior_span_hours: Option<f64>,
    pub recent_span_hours: Option<f64>,
    pub cpu_p95_prior_percent: Option<f64>,
    pub cpu_p95_recent_percent: Option<f64>,
    pub ram_p95_prior_mb: Option<f64>,
    pub ram_p95_recent_mb: Option<f64>,
    pub swap_p95_prior_mb: Option<f64>,
    pub swap_p95_recent_mb: Option<f64>,
}

/// Strength of the evidence behind a summarized window.
///
/// Depends only on inputs Orbyn can observe (sample count + validity ratio),
/// never on a guess about the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum SampleConfidence {
    /// 2–4 valid samples, or fewer than half the samples valid.
    Low,
    /// 5–11 valid samples, at least half valid.
    Medium,
    /// 12+ valid samples, at least half valid.
    High,
}

impl std::fmt::Display for SampleConfidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SampleConfidence::Low => write!(f, "low"),
            SampleConfidence::Medium => write!(f, "medium"),
            SampleConfidence::High => write!(f, "high"),
        }
    }
}

/// Guard condition: a window needs a minimum number of samples before it can
/// support any utilization claims.
pub const MIN_SAMPLES_FOR_STATS: usize = 2;

/// Minimum observation window (in hours) before utilization evidence can
/// support a right-sizing recommendation: one meeting week. Sample count
/// alone is not enough — three snapshots seconds apart are still one
/// moment in time.
pub const MIN_WINDOW_HOURS_FOR_RIGHT_SIZING: f64 = 168.0;

/// Minimum span (in hours) before a window is split for a week-over-week
/// comparison: two right-sizing windows, so each half carries a full week of
/// its own instead of a busy afternoon against a quiet month.
pub const MIN_SPAN_HOURS_FOR_COMPARISON: f64 = 2.0 * MIN_WINDOW_HOURS_FOR_RIGHT_SIZING;

/// Minimum samples in each compared half, so a sub-window p95 is never read
/// off a handful of points.
pub const MIN_SAMPLES_PER_SUB_WINDOW: usize = 5;

impl WindowStats {
    /// Whether this window is strong enough to support a right-sizing
    /// recommendation: high sample confidence over an observation window
    /// of at least [`MIN_WINDOW_HOURS_FOR_RIGHT_SIZING`] hours.
    pub fn right_sizing_ready(&self) -> bool {
        self.confidence == SampleConfidence::High
            && self
                .span_hours
                .map(|h| h >= MIN_WINDOW_HOURS_FOR_RIGHT_SIZING)
                .unwrap_or(false)
    }
}

/// Samples with plausible values. A sample is *valid* when every field it
/// carries is inside its physical range; samples that carry nothing usable are
/// invalid noise that would corrupt percentiles.
pub fn valid_sample(s: &MetricSample) -> bool {
    let cpu_ok = s
        .cpu_usage_percent
        .map(|v| (0.0..=100.0).contains(&v))
        .unwrap_or(true);
    let ram_usable = s.ram_used_mb.is_some()
        || s.ram_available_mb.is_some()
        || s.swap_used_mb.is_some()
        || s.load_1m.is_some();
    cpu_ok && ram_usable
}

pub fn summarize(samples: &[MetricSample]) -> Option<WindowStats> {
    if samples.len() < MIN_SAMPLES_FOR_STATS {
        return None;
    }

    let valid: Vec<&MetricSample> = samples.iter().filter(|s| valid_sample(s)).collect();
    let cpu: Vec<f64> = valid
        .iter()
        .filter_map(|s| s.cpu_usage_percent.map(f64::from))
        .collect();
    let ram: Vec<f64> = valid
        .iter()
        .filter_map(|s| s.ram_used_mb.map(|mb| mb as f64))
        .collect();
    let swap: Vec<f64> = valid
        .iter()
        .filter_map(|s| s.swap_used_mb.map(|mb| mb as f64))
        .collect();

    let (cpu_avg, cpu_p95, cpu_p99, cpu_peak) = percentile_bundle(&cpu);
    let (ram_avg, ram_p95, ram_p99, ram_peak) = percentile_bundle(&ram);
    let (swap_avg, swap_p95, swap_p99, swap_peak) = percentile_bundle(&swap);

    let validity = cpu
        .len()
        .max(ram.len())
        .max(swap.len())
        .min(if valid.is_empty() { 0 } else { valid.len() });

    let window_start = valid.iter().map(|s| s.sampled_at).min();
    let window_end = valid.iter().map(|s| s.sampled_at).max();
    let span_hours = span_between(window_start, window_end);

    Some(WindowStats {
        sample_count: samples.len(),
        window_start,
        window_end,
        span_hours,
        cpu_avg_percent: cpu_avg,
        cpu_p95_percent: cpu_p95,
        cpu_p99_percent: cpu_p99,
        cpu_peak_percent: cpu_peak,
        ram_avg_mb: ram_avg,
        ram_p95_mb: ram_p95,
        ram_p99_mb: ram_p99,
        ram_peak_mb: ram_peak,
        swap_avg_mb: swap_avg,
        swap_p95_mb: swap_p95,
        swap_p99_mb: swap_p99,
        swap_peak_mb: swap_peak,
        confidence: confidence_for(valid.len(), validity),
        comparison: window_end.and_then(|end| compare_sub_windows(&valid, end, span_hours)),
    })
}

/// Split a window into a prior and a recent half and compare their p95s.
///
/// Returns `None` unless the window spans
/// [`MIN_SPAN_HOURS_FOR_COMPARISON`] hours and both halves carry at least
/// [`MIN_SAMPLES_PER_SUB_WINDOW`] valid samples: a half-week is not a trend,
/// it is a shorter window wearing a trend's name.
fn compare_sub_windows(
    valid: &[&MetricSample],
    end: DateTime<Utc>,
    span_hours: Option<f64>,
) -> Option<WindowComparison> {
    if span_hours.unwrap_or(0.0) < MIN_SPAN_HOURS_FOR_COMPARISON {
        return None;
    }
    let half = chrono::Duration::hours(MIN_WINDOW_HOURS_FOR_RIGHT_SIZING.round() as i64);
    let split = end - half;
    let (prior, recent): (Vec<&MetricSample>, Vec<&MetricSample>) =
        valid.iter().partition(|s| s.sampled_at < split);
    if prior.len() < MIN_SAMPLES_PER_SUB_WINDOW || recent.len() < MIN_SAMPLES_PER_SUB_WINDOW {
        return None;
    }

    let field = |samples: &[&MetricSample], pick: fn(&MetricSample) -> Option<f64>| -> Vec<f64> {
        samples.iter().filter_map(|s| pick(s)).collect()
    };

    Some(WindowComparison {
        sub_window_hours: MIN_WINDOW_HOURS_FOR_RIGHT_SIZING,
        prior_sample_count: prior.len(),
        recent_sample_count: recent.len(),
        prior_span_hours: span_between(
            prior.iter().map(|s| s.sampled_at).min(),
            prior.iter().map(|s| s.sampled_at).max(),
        ),
        recent_span_hours: span_between(
            recent.iter().map(|s| s.sampled_at).min(),
            recent.iter().map(|s| s.sampled_at).max(),
        ),
        cpu_p95_prior_percent: p95_of(&field(&prior, |s| s.cpu_usage_percent.map(f64::from))),
        cpu_p95_recent_percent: p95_of(&field(&recent, |s| s.cpu_usage_percent.map(f64::from))),
        ram_p95_prior_mb: p95_of(&field(&prior, |s| s.ram_used_mb.map(|mb| mb as f64))),
        ram_p95_recent_mb: p95_of(&field(&recent, |s| s.ram_used_mb.map(|mb| mb as f64))),
        swap_p95_prior_mb: p95_of(&field(&prior, |s| s.swap_used_mb.map(|mb| mb as f64))),
        swap_p95_recent_mb: p95_of(&field(&recent, |s| s.swap_used_mb.map(|mb| mb as f64))),
    })
}

/// `(end - start)` in hours, `None` when either end is missing.
fn span_between(start: Option<DateTime<Utc>>, end: Option<DateTime<Utc>>) -> Option<f64> {
    match (start, end) {
        (Some(start), Some(end)) => Some((end - start).num_seconds() as f64 / 3600.0),
        _ => None,
    }
}

/// Confidence from the number of valid samples and their share of the window.
pub fn confidence_for(valid_count: usize, window_size: usize) -> SampleConfidence {
    if window_size == 0 || (valid_count as f64 / window_size as f64) < 0.5 || valid_count < 5 {
        SampleConfidence::Low
    } else if valid_count < 12 {
        SampleConfidence::Medium
    } else {
        SampleConfidence::High
    }
}

/// Sorted-percentile bundle: average, p95, p99 and peak of `values`.
fn percentile_bundle(values: &[f64]) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    if values.is_empty() {
        return (None, None, None, None);
    }
    let sorted = sorted_values(values);
    let avg = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let peak = sorted[sorted.len() - 1];
    (
        Some(avg),
        Some(percentile_at(&sorted, 0.95)),
        Some(percentile_at(&sorted, 0.99)),
        Some(peak),
    )
}

/// p95 of `values`, with the same nearest-rank definition the window bundle
/// uses, so a comparison never quotes a different statistic than the window
/// it belongs to.
fn p95_of(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let sorted = sorted_values(values);
    Some(percentile_at(&sorted, 0.95))
}

fn sorted_values(values: &[f64]) -> Vec<f64> {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    sorted
}

fn percentile_at(sorted: &[f64], quantile: f64) -> f64 {
    sorted[((sorted.len() as f64 - 1.0) * quantile).round() as usize]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample(cpu: f32, ram_mb: u64) -> MetricSample {
        sample_at(cpu, ram_mb, Utc::now())
    }

    fn sample_at(cpu: f32, ram_mb: u64, at: DateTime<Utc>) -> MetricSample {
        MetricSample {
            asset_id: "a1".into(),
            sampled_at: at,
            cpu_usage_percent: Some(cpu),
            ram_used_mb: Some(ram_mb),
            ram_available_mb: None,
            swap_used_mb: None,
            load_1m: None,
            load_5m: None,
            load_15m: None,
        }
    }

    #[test]
    fn single_sample_is_not_a_window() {
        assert!(summarize(&[sample(10.0, 1024)]).is_none());
    }

    #[test]
    fn aggregates_a_window_with_p99() {
        let stats = summarize(&[sample(10.0, 1024), sample(20.0, 2048), sample(40.0, 3072)])
            .expect("window exists");
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.cpu_avg_percent, Some(23.333333333333332));
        assert_eq!(stats.cpu_p95_percent, Some(40.0));
        assert_eq!(stats.cpu_p99_percent, Some(40.0));
        assert_eq!(stats.cpu_peak_percent, Some(40.0));
        assert_eq!(stats.ram_avg_mb, Some(2048.0));
        assert_eq!(stats.ram_p99_mb, Some(3072.0));
        assert_eq!(stats.confidence, SampleConfidence::Low);
    }

    #[test]
    fn many_samples_raise_confidence() {
        let many: Vec<MetricSample> = (0..12).map(|i| sample(i as f32, 1024)).collect();
        let stats = summarize(&many).expect("window exists");
        assert_eq!(stats.confidence, SampleConfidence::High);
        assert_eq!(stats.cpu_peak_percent, Some(11.0));
    }

    #[test]
    fn invalid_samples_do_not_dominate() {
        let mut bad = sample(999.0, 1024);
        bad.cpu_usage_percent = Some(220.0);
        let stats =
            summarize(&[bad, sample(10.0, 1024), sample(20.0, 1024)]).expect("window exists");
        // cpu percentile only from the two valid samples.
        assert_eq!(stats.cpu_avg_percent, Some(15.0));
    }

    #[test]
    fn nan_and_infinite_samples_are_invalid() {
        let mut nan = sample(f32::NAN, 1024);
        let stats =
            summarize(&[nan.clone(), sample(10.0, 1024), sample(20.0, 1024)]).expect("window");
        assert_eq!(stats.cpu_avg_percent, Some(15.0));
        nan.cpu_usage_percent = Some(f32::INFINITY);
        let stats = summarize(&[nan, sample(10.0, 1024), sample(20.0, 1024)]).expect("window");
        assert_eq!(stats.cpu_avg_percent, Some(15.0));
    }

    #[test]
    fn confidence_tiers() {
        assert_eq!(confidence_for(4, 10), SampleConfidence::Low);
        assert_eq!(confidence_for(5, 10), SampleConfidence::Medium);
        assert_eq!(confidence_for(12, 24), SampleConfidence::High);
        assert_eq!(confidence_for(2, 10), SampleConfidence::Low); // <50% valid
    }

    #[test]
    fn span_covers_oldest_to_newest_valid_sample() {
        let start = Utc::now() - chrono::Duration::hours(200);
        let samples: Vec<MetricSample> = (0..20)
            .map(|i| sample_at(10.0, 1024, start + chrono::Duration::hours(i * 10)))
            .collect();
        let stats = summarize(&samples).expect("window exists");
        assert_eq!(stats.window_start, Some(start));
        assert_eq!(stats.window_end, Some(start + chrono::Duration::hours(190)));
        let span = stats.span_hours.expect("span exists");
        assert!((span - 190.0).abs() < 0.01, "span was {span}");
    }

    #[test]
    fn right_sizing_needs_high_confidence_and_a_week_of_span() {
        // High confidence but zero span (snapshots seconds apart): not ready.
        let snapshots: Vec<MetricSample> = (0..12).map(|i| sample(i as f32, 1024)).collect();
        let stats = summarize(&snapshots).expect("window exists");
        assert_eq!(stats.confidence, SampleConfidence::High);
        assert!(!stats.right_sizing_ready());

        // High confidence over 168h+: ready.
        let start = Utc::now() - chrono::Duration::hours(200);
        let week: Vec<MetricSample> = (0..24)
            .map(|i| sample_at(10.0, 1024, start + chrono::Duration::hours(i * 8)))
            .collect();
        let stats = summarize(&week).expect("window exists");
        assert!(stats.right_sizing_ready());

        // A week of span but too few valid samples: not ready.
        let sparse: Vec<MetricSample> = (0..3)
            .map(|i| sample_at(10.0, 1024, start + chrono::Duration::hours(i * 84)))
            .collect();
        let stats = summarize(&sparse).expect("window exists");
        assert!(!stats.right_sizing_ready());
    }

    #[test]
    fn swap_is_summarized_with_the_same_percentiles() {
        let at = Utc::now();
        let samples: Vec<MetricSample> = (0..20)
            .map(|i| {
                let mut s = sample_at(10.0, 1024, at + chrono::Duration::hours(i));
                s.swap_used_mb = Some(i as u64 * 100);
                s
            })
            .collect();
        let stats = summarize(&samples).expect("window exists");
        assert_eq!(stats.swap_peak_mb, Some(1900.0));
        assert_eq!(stats.swap_p95_mb, Some(1800.0));
        assert_eq!(stats.swap_avg_mb, Some(950.0));

        // A window without swap samples leaves the swap stats empty rather
        // than reporting zero usage.
        let cpu_ram_only: Vec<MetricSample> = (0..5)
            .map(|i| sample_at(10.0, 1024, at + chrono::Duration::hours(i)))
            .collect();
        let stats = summarize(&cpu_ram_only).expect("window exists");
        assert_eq!(stats.swap_p95_mb, None);
    }

    #[test]
    fn comparison_needs_two_weeks_of_span() {
        let end = Utc::now();
        // 24 samples 8h apart: 184h of span, not enough for two halves.
        let week: Vec<MetricSample> = (0..24)
            .map(|i| sample_at(10.0, 1024, end - chrono::Duration::hours(i * 8)))
            .collect();
        let stats = summarize(&week).expect("window exists");
        assert!(stats.right_sizing_ready());
        assert!(stats.comparison.is_none(), "one week cannot be compared");

        // 48 samples 8h apart: 376h, so both halves carry a week. The split
        // falls 168h before the newest sample, which leaves 26 samples in the
        // prior half and 22 in the recent one.
        let fortnight: Vec<MetricSample> = (0..48)
            .map(|i| {
                let age = i * 8;
                let cpu = if age > 168 { 10.0 } else { 40.0 };
                sample_at(cpu, 1024, end - chrono::Duration::hours(age))
            })
            .collect();
        let stats = summarize(&fortnight).expect("window exists");
        let cmp = stats.comparison.expect("two weeks can be compared");
        assert_eq!(cmp.sub_window_hours, MIN_WINDOW_HOURS_FOR_RIGHT_SIZING);
        assert_eq!(cmp.prior_sample_count, 26);
        assert_eq!(cmp.recent_sample_count, 22);
        assert_eq!(cmp.cpu_p95_prior_percent, Some(10.0));
        assert_eq!(cmp.cpu_p95_recent_percent, Some(40.0));
        assert_eq!(cmp.ram_p95_prior_mb, Some(1024.0));
        assert_eq!(cmp.ram_p95_recent_mb, Some(1024.0));
        assert!(cmp.recent_span_hours.unwrap_or(0.0) >= 160.0);
    }

    #[test]
    fn comparison_needs_enough_samples_in_both_halves() {
        let end = Utc::now();
        // Long span, but the prior half holds only two samples.
        let lopsided: Vec<MetricSample> = (0..20)
            .map(|i| {
                let age = if i < 2 { 400 } else { i * 8 };
                sample_at(10.0, 1024, end - chrono::Duration::hours(age))
            })
            .collect();
        let stats = summarize(&lopsided).expect("window exists");
        assert!(stats.span_hours.unwrap_or(0.0) >= MIN_SPAN_HOURS_FOR_COMPARISON);
        assert!(
            stats.comparison.is_none(),
            "a half-week must not be dressed up as a trend"
        );
    }
}
