//! Capacity and utilization processing.
//!
//! Capacity is a current allocation (CPU model/cores, RAM). Utilization is a
//! time-series of samples. A single sample is always a snapshot and must never
//! be presented as sufficient historical evidence for right-sizing.
//!
//! Windows are summarized into avg/p95/p99/peak statistics and assigned a
//! [`SampleConfidence`] tier from the number of samples and their validity,
//! so consumers (CLI reports, future right-sizing rules) can weigh evidence
//! instead of trusting any single sample.

use crate::domain::MetricSample;

/// Aggregation over a batch of resource samples within an observation window.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct WindowStats {
    pub sample_count: usize,
    pub cpu_avg_percent: Option<f64>,
    pub cpu_p95_percent: Option<f64>,
    pub cpu_p99_percent: Option<f64>,
    pub cpu_peak_percent: Option<f64>,
    pub ram_avg_mb: Option<f64>,
    pub ram_p95_mb: Option<f64>,
    pub ram_p99_mb: Option<f64>,
    pub ram_peak_mb: Option<f64>,
    pub confidence: SampleConfidence,
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

    let (cpu_avg, cpu_p95, cpu_p99, cpu_peak) = percentile_bundle(&cpu);
    let (ram_avg, ram_p95, ram_p99, ram_peak) = percentile_bundle(&ram);

    let validity = cpu
        .len()
        .max(ram.len())
        .min(if valid.is_empty() { 0 } else { valid.len() });

    Some(WindowStats {
        sample_count: samples.len(),
        cpu_avg_percent: cpu_avg,
        cpu_p95_percent: cpu_p95,
        cpu_p99_percent: cpu_p99,
        cpu_peak_percent: cpu_peak,
        ram_avg_mb: ram_avg,
        ram_p95_mb: ram_p95,
        ram_p99_mb: ram_p99,
        ram_peak_mb: ram_peak,
        confidence: confidence_for(valid.len(), validity),
    })
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
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let avg = sorted.iter().sum::<f64>() / sorted.len() as f64;
    let idx_p95 = ((sorted.len() as f64 - 1.0) * 0.95).round() as usize;
    let idx_p99 = ((sorted.len() as f64 - 1.0) * 0.99).round() as usize;
    let peak = sorted[sorted.len() - 1];
    (
        Some(avg),
        Some(sorted[idx_p95]),
        Some(sorted[idx_p99]),
        Some(peak),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample(cpu: f32, ram_mb: u64) -> MetricSample {
        MetricSample {
            asset_id: "a1".into(),
            sampled_at: Utc::now(),
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
    fn confidence_tiers() {
        assert_eq!(confidence_for(4, 10), SampleConfidence::Low);
        assert_eq!(confidence_for(5, 10), SampleConfidence::Medium);
        assert_eq!(confidence_for(12, 24), SampleConfidence::High);
        assert_eq!(confidence_for(2, 10), SampleConfidence::Low); // <50% valid
    }
}
