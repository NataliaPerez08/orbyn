//! PostgreSQL store integration tests.
//!
//! Skipped unless `ORBYN_PG_TEST_URL` points at a reachable database (for
//! example `postgres://orbyn:orbyn@localhost:5432/orbyn_test`); CI runs them
//! against a service container. Tests share one database: a global lock
//! serializes them and each one truncates every table first, so assertions
//! can be exact and re-runs stay deterministic.

use chrono::Utc;
use orbyn::domain::{
    Asset, AuditEvent, Capacity, Connection, Criticality, Dependency, DiscoveryJob, Filesystem,
    Interface, JobOutcome, JobStatus, MetricSample, Observation, RunningService, Service,
};
use orbyn::store::postgres::PostgresStore;
use orbyn::store::traits::{AnnotationField, AssetAnnotations};
use orbyn::store::Store;

/// Serializes the tests in this binary (they share one database).
static TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

/// Acquire the suite lock, open the test store and truncate every table.
/// Returns `None` to skip the test when `ORBYN_PG_TEST_URL` is unset.
async fn locked_store() -> Option<(tokio::sync::MutexGuard<'static, ()>, PostgresStore)> {
    let guard = TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let url = std::env::var("ORBYN_PG_TEST_URL").ok()?;
    let store = PostgresStore::open(&url)
        .await
        .expect("open postgres test store");
    sqlx::query(
        "TRUNCATE TABLE audit_events, discovery_jobs, metric_samples, asset_connections, \
         asset_running_services, asset_filesystems, asset_capacity, dependencies, \
         asset_interfaces, services, assets CASCADE",
    )
    .execute(store.pool())
    .await
    .expect("truncate tables");
    Some((guard, store))
}

/// Unique asset id for this test invocation.
fn unique_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn asset(id: &str, ip: &str, hostname: Option<&str>) -> Asset {
    Asset {
        id: id.into(),
        ip: ip.parse().unwrap(),
        hostname: hostname.map(Into::into),
        device_class: Some("server".into()),
        os_name: Some("Ubuntu 22.04".into()),
        os_version: Some("5.15".into()),
        sys_descr: Some("Linux host 5.15.0".into()),
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    }
}

#[tokio::test]
async fn round_trips_every_observation_kind() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    assert_eq!(store.database_type(), "postgres");

    let api_id = unique_id("pg-api");
    let db_id = unique_id("pg-db");
    let api = asset(&api_id, "10.211.0.1", Some("pg-api-01"));
    let db = asset(&db_id, "10.211.0.2", Some("pg-db-01"));

    store
        .store_observations(vec![
            Observation::Asset(api.clone()),
            Observation::Asset(db.clone()),
            Observation::Interface(Interface::new(
                &api_id,
                Some("eth0"),
                Some("00:11:22:33:44:55"),
                Some("10.211.0.1".parse().unwrap()),
            )),
            Observation::Service(Service {
                asset_id: api_id.clone(),
                proto: "tcp".into(),
                port: 443,
                name: Some("https".into()),
                state: "open".into(),
                banner: Some("nginx 1.18.0".into()),
            }),
            Observation::Capacity(Capacity {
                asset_id: api_id.clone(),
                cpu_model: Some("Xeon Gold 6138".into()),
                cpu_sockets: Some(1),
                cpu_cores: Some(4),
                cpu_threads: Some(8),
                ram_total_mb: Some(16384),
                hypervisor: Some("kvm".into()),
                collected_at: Utc::now(),
            }),
            Observation::Filesystem(Filesystem {
                asset_id: api_id.clone(),
                device: Some("/dev/sda1".into()),
                mount: "/".into(),
                fs_type: Some("ext4".into()),
                size_kb: 52425716,
                used_kb: Some(12345678),
                available_kb: Some(37380844),
                used_pct: Some(25),
            }),
            Observation::RunningService(RunningService {
                asset_id: api_id.clone(),
                name: "nginx.service".into(),
                state: Some("running".into()),
                description: Some("web server".into()),
            }),
            Observation::Connection(Connection {
                asset_id: api_id.clone(),
                proto: "tcp".into(),
                local_ip: Some("10.211.0.1".parse().unwrap()),
                local_port: Some(54322),
                remote_ip: "10.211.0.2".parse().unwrap(),
                remote_port: 5432,
                process: Some("postgres".into()),
            }),
            Observation::Dependency(Dependency {
                source_asset_id: api_id.clone(),
                target_asset_id: db_id.clone(),
                proto: "tcp".into(),
                port: 5432,
                evidence_source: "active-connections".into(),
                confidence: 0.9,
                confirmed: false,
            }),
        ])
        .await
        .expect("persist observations");

    let fetched = store.get_asset_by_ip("10.211.0.1").await.unwrap().unwrap();
    assert_eq!(fetched.id, api_id);
    assert_eq!(fetched.hostname.as_deref(), Some("pg-api-01"));
    assert_eq!(fetched.os_name.as_deref(), Some("Ubuntu 22.04"));
    assert_eq!(fetched.sys_descr.as_deref(), Some("Linux host 5.15.0"));

    let by_hostname = store
        .get_asset_by_hostname("PG-API-01")
        .await
        .unwrap()
        .expect("case-insensitive hostname lookup");
    assert_eq!(by_hostname.id, api_id);

    let interfaces = store.list_interfaces(&api_id).await.unwrap();
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].mac.as_deref(), Some("00:11:22:33:44:55"));
    assert_eq!(interfaces[0].mtu, None);

    let services = store.list_services(&api_id).await.unwrap();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].port, 443);
    assert_eq!(services[0].banner.as_deref(), Some("nginx 1.18.0"));

    let capacity = store.get_capacity(&api_id).await.unwrap().unwrap();
    assert_eq!(capacity.ram_total_mb, Some(16384));
    assert_eq!(capacity.cpu_cores, Some(4));
    assert_eq!(capacity.hypervisor.as_deref(), Some("kvm"));

    let filesystems = store.list_filesystems(&api_id).await.unwrap();
    assert_eq!(filesystems.len(), 1);
    assert_eq!(filesystems[0].used_pct, Some(25));

    let running = store.list_running_services(&api_id).await.unwrap();
    assert_eq!(running.len(), 1);
    assert_eq!(running[0].name, "nginx.service");

    let connections = store.list_connections(&api_id).await.unwrap();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].remote_port, 5432);

    // The batch reconcile must have created the same edge the explicit
    // dependency observation inserted (ON CONFLICT keeps one row).
    let deps = store.list_dependencies().await.unwrap();
    let edge = deps
        .iter()
        .find(|d| d.source_asset_id == api_id && d.target_asset_id == db_id)
        .expect("dependency edge exists");
    assert_eq!(edge.port, 5432);
    assert!((edge.confidence - 0.9).abs() < f32::EPSILON);
}

#[tokio::test]
async fn bulk_reads_match_per_asset_reads() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    let api_id = unique_id("pg-bulk-api");
    let db_id = unique_id("pg-bulk-db");
    store
        .store_observations(vec![
            Observation::Asset(asset(&api_id, "10.212.0.1", None)),
            Observation::Asset(asset(&db_id, "10.212.0.2", None)),
            Observation::Service(Service {
                asset_id: api_id.clone(),
                proto: "tcp".into(),
                port: 443,
                name: None,
                state: "open".into(),
                banner: None,
            }),
            Observation::Service(Service {
                asset_id: db_id.clone(),
                proto: "tcp".into(),
                port: 5432,
                name: None,
                state: "open".into(),
                banner: None,
            }),
            Observation::Interface(Interface::new(
                &api_id,
                Some("eth0"),
                None,
                Some("10.212.0.1".parse().unwrap()),
            )),
            Observation::Capacity(Capacity {
                asset_id: api_id.clone(),
                cpu_model: None,
                cpu_sockets: None,
                cpu_cores: None,
                cpu_threads: None,
                ram_total_mb: Some(8192),
                hypervisor: None,
                collected_at: Utc::now(),
            }),
            Observation::Filesystem(Filesystem {
                asset_id: db_id.clone(),
                device: None,
                mount: "/data".into(),
                fs_type: None,
                size_kb: 1000,
                used_kb: None,
                available_kb: None,
                used_pct: None,
            }),
            Observation::Connection(Connection {
                asset_id: api_id.clone(),
                proto: "tcp".into(),
                local_ip: None,
                local_port: None,
                remote_ip: "10.212.0.2".parse().unwrap(),
                remote_port: 5432,
                process: None,
            }),
        ])
        .await
        .unwrap();

    let mut per_asset_services = Vec::new();
    let mut per_asset_interfaces = Vec::new();
    let mut per_asset_filesystems = Vec::new();
    let mut per_asset_connections = Vec::new();
    for id in [&api_id, &db_id] {
        per_asset_services.extend(store.list_services(id).await.unwrap());
        per_asset_interfaces.extend(store.list_interfaces(id).await.unwrap());
        per_asset_filesystems.extend(store.list_filesystems(id).await.unwrap());
        per_asset_connections.extend(store.list_connections(id).await.unwrap());
    }

    let all_services = store.list_all_services().await.unwrap();
    for svc in &per_asset_services {
        assert!(all_services.contains(svc), "bulk services cover {svc:?}");
    }
    let all_interfaces = store.list_all_interfaces().await.unwrap();
    for iface in &per_asset_interfaces {
        assert!(
            all_interfaces.contains(iface),
            "bulk interfaces cover {iface:?}"
        );
    }
    let all_filesystems = store.list_all_filesystems().await.unwrap();
    for fs in &per_asset_filesystems {
        assert!(
            all_filesystems.contains(fs),
            "bulk filesystems cover {fs:?}"
        );
    }
    let all_connections = store.list_all_connections().await.unwrap();
    for conn in &per_asset_connections {
        assert!(
            all_connections.contains(conn),
            "bulk connections cover {conn:?}"
        );
    }
    let all_capacities = store.list_all_capacities().await.unwrap();
    assert!(all_capacities
        .iter()
        .any(|c| c.asset_id == api_id && c.ram_total_mb == Some(8192)));
    // #8 overwrite semantics: the re-scan dropped every measured field it no
    // longer detected, including the hypervisor.
    assert!(all_capacities
        .iter()
        .any(|c| c.asset_id == api_id && c.hypervisor.is_none()));
}

#[tokio::test]
async fn confirms_and_removes_dependency_edges() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    let source = unique_id("pg-dep-src");
    let target = unique_id("pg-dep-dst");
    store
        .store_observations(vec![
            Observation::Asset(asset(&source, "10.213.0.1", None)),
            Observation::Asset(asset(&target, "10.213.0.2", None)),
            Observation::Connection(Connection {
                asset_id: source.clone(),
                proto: "tcp".into(),
                local_ip: None,
                local_port: None,
                remote_ip: "10.213.0.2".parse().unwrap(),
                remote_port: 6379,
                process: None,
            }),
        ])
        .await
        .unwrap();

    let confirmed = store
        .confirm_dependency(&source, &target, Some("tcp"), Some(6379))
        .await
        .unwrap();
    assert_eq!(confirmed, 1);
    let edge = store
        .list_dependencies()
        .await
        .unwrap()
        .into_iter()
        .find(|d| d.source_asset_id == source && d.target_asset_id == target)
        .unwrap();
    assert!(edge.confirmed);
    assert_eq!(edge.confidence, 1.0);

    let removed = store
        .remove_dependency(&source, &target, None, None)
        .await
        .unwrap();
    assert_eq!(removed, 1);
    let edges = store.list_dependencies().await.unwrap();
    assert!(!edges
        .iter()
        .any(|d| d.source_asset_id == source && d.target_asset_id == target));
}

#[tokio::test]
async fn annotates_and_unsets_fields() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    let id = unique_id("pg-annot");
    store
        .store_observations(vec![Observation::Asset(asset(&id, "10.214.0.1", None))])
        .await
        .unwrap();

    store
        .annotate_asset(
            &id,
            AssetAnnotations {
                environment: Some("prod".into()),
                owner: Some("platform".into()),
                criticality: Some(Criticality::High),
                add_tags: vec!["core".into(), "api".into()],
                remove_tags: Vec::new(),
                unset: Vec::new(),
            },
        )
        .await
        .unwrap();
    let annotated = store.get_asset(&id).await.unwrap().unwrap();
    assert_eq!(annotated.environment.as_deref(), Some("prod"));
    assert_eq!(annotated.owner.as_deref(), Some("platform"));
    assert_eq!(annotated.criticality, Some(Criticality::High));
    assert_eq!(annotated.tags, vec!["core".to_string(), "api".into()]);

    store
        .annotate_asset(
            &id,
            AssetAnnotations {
                environment: None,
                owner: None,
                criticality: None,
                add_tags: vec!["api".into()],
                remove_tags: vec!["core".into()],
                unset: vec![AnnotationField::Criticality],
            },
        )
        .await
        .unwrap();
    let updated = store.get_asset(&id).await.unwrap().unwrap();
    assert_eq!(updated.environment.as_deref(), Some("prod"));
    assert_eq!(updated.criticality, None);
    assert_eq!(updated.tags, vec!["api".to_string()]);
}

/// The bulk annotation path must behave exactly like the single-asset one:
/// this is what a large import uses, one transaction instead of one per asset.
#[tokio::test]
async fn bulk_annotation_applies_every_edit() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    let db_id = unique_id("pg-bulk-db");
    let web_id = unique_id("pg-bulk-web");
    store
        .store_observations(vec![
            Observation::Asset(asset(&db_id, "10.216.0.1", None)),
            Observation::Asset(asset(&web_id, "10.216.0.2", None)),
        ])
        .await
        .unwrap();

    store
        .annotate_assets(vec![
            (
                db_id.clone(),
                AssetAnnotations {
                    environment: Some("prod".into()),
                    owner: Some("platform".into()),
                    criticality: Some(Criticality::Critical),
                    add_tags: vec!["core".into()],
                    remove_tags: Vec::new(),
                    unset: Vec::new(),
                },
            ),
            (
                web_id.clone(),
                AssetAnnotations {
                    environment: Some("staging".into()),
                    owner: None,
                    criticality: Some(Criticality::Low),
                    add_tags: vec!["edge".into(), "core".into()],
                    remove_tags: Vec::new(),
                    unset: Vec::new(),
                },
            ),
        ])
        .await
        .unwrap();

    let db = store.get_asset(&db_id).await.unwrap().unwrap();
    assert_eq!(db.environment.as_deref(), Some("prod"));
    assert_eq!(db.owner.as_deref(), Some("platform"));
    assert_eq!(db.tags, vec!["core".to_string()]);

    let web = store.get_asset(&web_id).await.unwrap().unwrap();
    assert_eq!(web.environment.as_deref(), Some("staging"));
    assert_eq!(web.criticality, Some(Criticality::Low));
    assert_eq!(web.tags, vec!["edge".to_string(), "core".into()]);

    // A later edit merges over the bulk write, exactly as it would after a
    // single-asset annotation.
    store
        .annotate_assets(vec![(
            web_id.clone(),
            AssetAnnotations {
                environment: None,
                owner: Some("web-team".into()),
                criticality: None,
                add_tags: Vec::new(),
                remove_tags: vec!["core".into()],
                unset: Vec::new(),
            },
        )])
        .await
        .unwrap();
    let web = store.get_asset(&web_id).await.unwrap().unwrap();
    assert_eq!(web.tags, vec!["edge".to_string()]);
    assert_eq!(web.owner.as_deref(), Some("web-team"));
    assert_eq!(web.environment.as_deref(), Some("staging"), "kept");
    assert_eq!(web.criticality, Some(Criticality::Low), "kept");

    // An unknown asset fails the whole batch instead of silently skipping.
    let err = store
        .annotate_assets(vec![(
            unique_id("pg-bulk-missing"),
            AssetAnnotations::default(),
        )])
        .await
        .expect_err("unknown asset");
    assert!(err.to_string().contains("no asset matches"), "{err}");
}

#[tokio::test]
async fn jobs_and_audit_events_round_trip() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    let job_id = unique_id("pg-job");
    store
        .create_job(DiscoveryJob {
            id: job_id.clone(),
            collector: "nmap".into(),
            targets: vec!["10.215.0.0/29".into()],
            status: JobStatus::Running,
            started_at: Utc::now(),
            finished_at: None,
            error: None,
            assets_found: None,
            services_found: None,
            filesystems_found: None,
            running_services_found: None,
            connections_found: None,
        })
        .await
        .unwrap();

    store
        .finish_job(
            &job_id,
            JobStatus::Succeeded,
            None,
            Some(JobOutcome {
                assets_found: 3,
                services_found: 7,
                filesystems_found: 2,
                running_services_found: 5,
                connections_found: 4,
            }),
        )
        .await
        .unwrap();

    let job = store.get_job(&job_id).await.unwrap().unwrap();
    assert_eq!(job.status, JobStatus::Succeeded);
    assert_eq!(job.assets_found, Some(3));
    assert_eq!(job.connections_found, Some(4));
    assert!(job.finished_at.is_some());

    let jobs = store.list_jobs(Some(50)).await.unwrap();
    assert!(jobs.iter().any(|j| j.id == job_id));

    let audit_id = unique_id("pg-audit");
    store
        .create_audit_event(AuditEvent {
            id: audit_id.clone(),
            action: "annotate".into(),
            target: "10.215.0.1".into(),
            status: JobStatus::Running,
            started_at: Utc::now(),
            finished_at: None,
            details: Some("environment=prod".into()),
            error: None,
        })
        .await
        .unwrap();
    store
        .finish_audit_event(&audit_id, JobStatus::Succeeded, None)
        .await
        .unwrap();
    let events = store.list_audit_events(Some(50)).await.unwrap();
    let event = events.iter().find(|e| e.id == audit_id).unwrap();
    assert_eq!(event.status, JobStatus::Succeeded);
    assert!(event.finished_at.is_some());
}

#[tokio::test]
async fn metric_samples_respect_limit_and_order() {
    let Some((_guard, store)) = locked_store().await else {
        eprintln!("skipping: ORBYN_PG_TEST_URL is not set");
        return;
    };
    let id = unique_id("pg-metrics");
    store
        .store_observations(vec![Observation::Asset(asset(&id, "10.216.0.1", None))])
        .await
        .unwrap();

    let base = Utc::now();
    let samples: Vec<Observation> = [10.0f64, 20.0, 40.0, 30.0]
        .iter()
        .enumerate()
        .map(|(i, cpu)| {
            Observation::MetricSample(MetricSample {
                asset_id: id.clone(),
                sampled_at: base + chrono::Duration::seconds(i as i64 + 1),
                cpu_usage_percent: Some(*cpu as f32),
                ram_used_mb: Some(1024 * (i as u64 + 1)),
                ram_available_mb: Some(4096),
                swap_used_mb: None,
                load_1m: Some(0.5),
                load_5m: Some(0.4),
                load_15m: Some(0.3),
            })
        })
        .collect();
    store.store_observations(samples).await.unwrap();

    let stored = store.list_metric_samples(&id, None).await.unwrap();
    assert_eq!(stored.len(), 4);
    assert!(stored
        .windows(2)
        .all(|w| w[0].sampled_at <= w[1].sampled_at));

    let recent = store.list_metric_samples(&id, Some(2)).await.unwrap();
    assert_eq!(recent.len(), 2);
    // The two newest samples (+3 s and +4 s), oldest first.
    assert_eq!(recent[0].cpu_usage_percent, Some(40.0));
    assert_eq!(recent[1].cpu_usage_percent, Some(30.0));
}
