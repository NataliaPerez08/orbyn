//! Capacity and utilization processing.
//!
//! Capacity is a current allocation (CPU model/cores, RAM). Utilization is a
//! time-series of samples. A single sample is always a snapshot and must never
//! be presented as sufficient historical evidence for right-sizing.

use crate::domain::MetricSample;

/// Aggregation over a batch of resource samples within an observation window.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowStats {
    pub sample_count: usize,
    pub cpu_avg_percent: Option<f64>,
    pub cpu_p95_percent: Option<f64>,
    pub cpu_peak_percent: Option<f64>,
    pub ram_avg_mb: Option<f64>,
    pub ram_p95_mb: Option<f64>,
    pub ram_peak_mb: Option<f64>,
}

/// Guard condition: a window needs a minimum number of samples before it can
/// support any utilization claims.
pub const MIN_SAMPLES_FOR_STATS: usize = 2;

pub fn summarize(samples: &[MetricSample]) -> Option<WindowStats> {
    if samples.len() < MIN_SAMPLES_FOR_STATS {
        return None;
    }

    let mut cpu: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.cpu_usage_percent.map(|v| v as f64))
        .collect();
    let mut ram: Vec<f64> = samples
        .iter()
        .filter_map(|s| s.ram_used_mb.map(|mb| mb as f64))
        .collect();

    let (cpu_avg, cpu_p95, cpu_peak) = percentile_bundle(&mut cpu);
    let (ram_avg, ram_p95, ram_peak) = percentile_bundle(&mut ram);

    Some(WindowStats {
        sample_count: samples.len(),
        cpu_avg_percent: cpu_avg,
        cpu_p95_percent: cpu_p95,
        cpu_peak_percent: cpu_peak,
        ram_avg_mb: ram_avg,
        ram_p95_mb: ram_p95,
        ram_peak_mb: ram_peak,
    })
}

/// Rough p95 for the skeleton; percentile statistics become a proper module in
/// v1.2.
fn percentile_bundle(values: &mut [f64]) -> (Option<f64>, Option<f64>, Option<f64>) {
    if values.is_empty() {
        return (None, None, None);
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let avg = values.iter().sum::<f64>() / values.len() as f64;
    let idx_p95 = ((values.len() as f64 - 1.0) * 0.95).round() as usize;
    let peak = values[values.len() - 1];
    (Some(avg), Some(values[idx_p95]), Some(peak))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::MetricSample;
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
    fn aggregates_a_window() {
        let stats = summarize(&[sample(10.0, 1024), sample(20.0, 2048), sample(40.0, 3072)])
            .expect("window exists");
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.cpu_avg_percent, Some(23.333333333333332));
        assert_eq!(stats.cpu_p95_percent, Some(40.0));
        assert_eq!(stats.cpu_peak_percent, Some(40.0));
        assert_eq!(stats.ram_avg_mb, Some(2048.0));
    }
}
