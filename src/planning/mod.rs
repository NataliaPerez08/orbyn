//! Migration planning models (v1.2).
//!
//! Readiness and strategy are pure functions over a borrowed inventory
//! snapshot — the same discipline as the assessment rules: they never
//! read the store, so results stay deterministic and testable. The
//! orchestration (`orbyn plan`) assembles the snapshot and persists the
//! outcome as a [`crate::domain::MigrationPlan`] artifact.

pub mod readiness;
pub mod strategy;

use crate::assessment::{AssetScore, AssetWindow, Finding};
use crate::domain::{
    Application, ApplicationMember, Asset, Capacity, Connection, Dependency, Service,
};

/// The borrowed snapshot both planning models evaluate. Assembled by the
/// app layer from the store plus the current assessment report.
pub struct PlanInput<'a> {
    pub application: &'a Application,
    /// Active (non-excluded) members.
    pub members: &'a [ApplicationMember],
    pub assets: &'a [Asset],
    pub services: &'a [Service],
    pub dependencies: &'a [Dependency],
    pub connections: &'a [Connection],
    pub capacities: &'a [Capacity],
    pub findings: &'a [Finding],
    pub asset_scores: &'a [AssetScore],
    pub metric_windows: &'a [AssetWindow],
}

impl PlanInput<'_> {
    /// Assemble from an application, its members and the assessment
    /// snapshot — the one construction path every caller shares.
    pub fn from_snapshot<'a>(
        application: &'a Application,
        members: &'a [ApplicationMember],
        input: &'a crate::assessment::AssessmentInput,
        report: &'a crate::assessment::AssessmentReport,
    ) -> PlanInput<'a> {
        PlanInput {
            application,
            members,
            assets: &input.assets,
            services: &input.services,
            dependencies: &input.dependencies,
            connections: &input.connections,
            capacities: &input.capacities,
            findings: &report.findings,
            asset_scores: &report.asset_scores,
            metric_windows: &input.metric_windows,
        }
    }

    /// The assets of the application's active members, in member order.
    pub fn member_assets(&self) -> Vec<&Asset> {
        let by_id = |id: &str| self.assets.iter().find(|a| a.id == id);
        self.members
            .iter()
            .filter_map(|m| by_id(&m.asset_id))
            .collect()
    }

    /// The member's summarized utilization window, when one exists.
    pub fn window(&self, asset_id: &str) -> Option<&AssetWindow> {
        self.metric_windows.iter().find(|w| w.asset_id == asset_id)
    }

    /// The member's capacity row, when one exists.
    pub fn capacity(&self, asset_id: &str) -> Option<&Capacity> {
        self.capacities.iter().find(|c| c.asset_id == asset_id)
    }

    /// Findings on member assets with the given rule id.
    pub fn member_findings(&self, rule_id: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.rule_id == rule_id)
            .filter(|f| {
                f.asset_id
                    .as_deref()
                    .is_some_and(|id| self.members.iter().any(|m| m.asset_id == id))
            })
            .collect()
    }

    /// Member asset ids as a set-like lookup closure helper: membership
    /// test used across factors.
    pub fn is_member(&self, asset_id: &str) -> bool {
        self.members.iter().any(|m| m.asset_id == asset_id)
    }
}

/// Deterministic fixtures for the planning model tests.
#[cfg(test)]
pub(crate) mod testkit {
    use crate::assessment::{AssetScore, AssetWindow, Finding, Severity};
    use crate::domain::{
        AppSource, Application, ApplicationMember, Asset, Capacity, Connection, Criticality,
        Dependency, Service,
    };
    use crate::metrics::{SampleConfidence, WindowStats};

    /// An owned snapshot fixture; [`Fixture::input`] borrows it into the
    /// [`PlanInput`] the models evaluate.
    pub struct Fixture {
        pub application: Application,
        pub members: Vec<ApplicationMember>,
        pub assets: Vec<Asset>,
        pub services: Vec<Service>,
        pub dependencies: Vec<Dependency>,
        pub connections: Vec<Connection>,
        pub capacities: Vec<Capacity>,
        pub findings: Vec<Finding>,
        pub asset_scores: Vec<AssetScore>,
        pub metric_windows: Vec<AssetWindow>,
    }

    impl Fixture {
        pub fn input(&self) -> super::PlanInput<'_> {
            super::PlanInput {
                application: &self.application,
                members: &self.members,
                assets: &self.assets,
                services: &self.services,
                dependencies: &self.dependencies,
                connections: &self.connections,
                capacities: &self.capacities,
                findings: &self.findings,
                asset_scores: &self.asset_scores,
                metric_windows: &self.metric_windows,
            }
        }
    }

    /// `n` members, fully documented: OS, hostname, owner, environment,
    /// capacity, high-confidence samples, one confirmed internal edge —
    /// readiness 100 with no factors.
    pub fn complete_application(n: usize) -> Fixture {
        let now = chrono::Utc::now();
        let assets: Vec<Asset> = (0..n)
            .map(|i| Asset {
                id: format!("a{i}"),
                ip: format!("10.0.0.{}", i + 1).parse().unwrap(),
                hostname: Some(format!("host-{i}")),
                device_class: Some("server".into()),
                os_name: Some("Ubuntu 22.04.4 LTS".into()),
                os_version: Some("5.15.0".into()),
                sys_descr: None,
                environment: Some("prod".into()),
                owner: Some("team-a".into()),
                criticality: Some(Criticality::High),
                tags: Vec::new(),
                first_seen: now,
                last_seen: now,
            })
            .collect();
        let members: Vec<ApplicationMember> = assets
            .iter()
            .map(|a| ApplicationMember {
                application_id: "app-1".into(),
                asset_id: a.id.clone(),
                source: AppSource::Inferred,
                confidence: 1.0,
                evidence: Vec::new(),
                is_excluded: false,
            })
            .collect();
        let services: Vec<Service> = assets
            .iter()
            .map(|a| Service {
                asset_id: a.id.clone(),
                proto: "tcp".into(),
                port: 22,
                name: Some("ssh".into()),
                state: "open".into(),
                banner: None,
            })
            .collect();
        let mut dependencies = Vec::new();
        if n >= 2 {
            dependencies.push(Dependency {
                source_asset_id: "a0".into(),
                target_asset_id: "a1".into(),
                proto: "tcp".into(),
                port: 5432,
                evidence_source: "manual".into(),
                confidence: 1.0,
                confirmed: true,
            });
        }
        Fixture {
            application: Application {
                id: "app-1".into(),
                name: "app".into(),
                source: AppSource::Inferred,
                confidence: 1.0,
                created_at: now,
                updated_at: now,
            },
            members,
            assets,
            services,
            dependencies,
            connections: Vec::new(),
            capacities: (0..n)
                .map(|i| Capacity {
                    asset_id: format!("a{i}"),
                    cpu_model: None,
                    cpu_sockets: Some(1),
                    cpu_cores: Some(4),
                    cpu_threads: Some(4),
                    ram_total_mb: Some(8192),
                    hypervisor: None,
                    collected_at: now,
                })
                .collect(),
            findings: Vec::new(),
            asset_scores: (0..n)
                .map(|i| AssetScore {
                    asset_id: format!("a{i}"),
                    score: 4,
                    findings: 0,
                })
                .collect(),
            metric_windows: (0..n)
                .map(|i| AssetWindow {
                    asset_id: format!("a{i}"),
                    stats: WindowStats {
                        sample_count: 12,
                        window_start: None,
                        window_end: None,
                        span_hours: None,
                        cpu_avg_percent: Some(10.0),
                        cpu_p95_percent: Some(20.0),
                        cpu_p99_percent: Some(25.0),
                        cpu_peak_percent: Some(30.0),
                        ram_avg_mb: Some(1024.0),
                        ram_p95_mb: Some(2048.0),
                        ram_p99_mb: Some(2304.0),
                        ram_peak_mb: Some(2560.0),
                        swap_avg_mb: Some(0.0),
                        swap_p95_mb: Some(0.0),
                        swap_p99_mb: Some(0.0),
                        swap_peak_mb: Some(0.0),
                        confidence: SampleConfidence::High,
                        comparison: None,
                    },
                })
                .collect(),
        }
    }

    /// A finding on an asset.
    pub fn finding(rule_id: &str, asset_id: &str, message: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: Severity::High,
            message: message.into(),
            evidence: Vec::new(),
            asset_id: Some(asset_id.into()),
        }
    }

    /// An observed connection from an asset to a remote endpoint.
    pub fn connection(asset_id: &str, remote_ip: &str, port: u16) -> Connection {
        Connection {
            asset_id: asset_id.into(),
            proto: "tcp".into(),
            local_ip: None,
            local_port: None,
            remote_ip: remote_ip.parse().unwrap(),
            remote_port: port,
            process: None,
        }
    }
}
