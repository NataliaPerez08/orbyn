//! Integration tests for the persistence path used by the CLI.
//!
//! These populate a real SQLite database with sample observations and verify
//! that the store (and therefore every `orbyn` read command) can retrieve them.

use chrono::Utc;
use orbyn::domain::{
    Asset, Criticality, Dependency, DiscoveryJob, Interface, JobOutcome, JobStatus, Observation,
    Service,
};
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::traits::AssetAnnotations;
use orbyn::store::Store;

fn sample_db_path() -> String {
    std::env::var("ORBYN_TEST_DB").unwrap_or_else(|_| "/tmp/orbyn-test-smoke.db".to_string())
}

fn sample_observations() -> Vec<Observation> {
    let api = Asset {
        id: "asset-api".into(),
        ip: "10.0.0.1".parse().unwrap(),
        hostname: Some("api-01".into()),
        device_class: Some("server".into()),
        os_name: None,
        os_version: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    let db = Asset {
        id: "asset-db".into(),
        ip: "10.0.0.2".parse().unwrap(),
        hostname: Some("postgres-01".into()),
        device_class: Some("server".into()),
        os_name: None,
        os_version: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    vec![
        Observation::Asset(api.clone()),
        Observation::Asset(db.clone()),
        Observation::Interface(Interface::new(
            &api.id,
            Some("eth0"),
            Some("00:11:22:33:44:55"),
            Some("10.0.0.1".parse().unwrap()),
        )),
        Observation::Service(Service {
            asset_id: api.id.clone(),
            proto: "tcp".into(),
            port: 443,
            name: Some("https".into()),
            state: "open".into(),
            banner: None,
        }),
        Observation::Service(Service {
            asset_id: db.id.clone(),
            proto: "tcp".into(),
            port: 5432,
            name: Some("postgresql".into()),
            state: "open".into(),
            banner: None,
        }),
        Observation::Dependency(Dependency {
            source_asset_id: api.id.clone(),
            target_asset_id: db.id.clone(),
            proto: "tcp".into(),
            port: 5432,
            evidence_source: "active-connections".into(),
            confidence: 0.9,
            confirmed: false,
        }),
    ]
}

fn sample_job() -> DiscoveryJob {
    DiscoveryJob {
        id: "job-1".into(),
        collector: "nmap".into(),
        targets: vec!["10.0.0.0/29".into()],
        status: JobStatus::Succeeded,
        started_at: Utc::now(),
        finished_at: Some(Utc::now()),
        error: None,
        assets_found: Some(2),
        services_found: Some(2),
    }
}

#[tokio::test]
async fn store_round_trip() {
    let _ = std::fs::remove_file(sample_db_path());
    let store = SqliteStore::open(std::path::Path::new(&sample_db_path()))
        .await
        .expect("open test db");
    store
        .store_observations(sample_observations())
        .await
        .expect("persist sample observations");

    let assets = store.list_assets().await.expect("list assets");
    assert_eq!(assets.len(), 2);

    let api = store
        .get_asset_by_ip("10.0.0.1")
        .await
        .expect("lookup by ip")
        .expect("asset exists");
    assert_eq!(api.hostname.as_deref(), Some("api-01"));

    let services = store.list_services(&api.id).await.expect("list services");
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].port, 443);

    let interfaces = store
        .list_interfaces(&api.id)
        .await
        .expect("list interfaces");
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].mac.as_deref(), Some("00:11:22:33:44:55"));
    assert_eq!(interfaces[0].ip, Some("10.0.0.1".parse().unwrap()));

    let deps = store.list_dependencies().await.expect("list dependencies");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].confidence, 0.9);
}

#[tokio::test]
async fn re_observation_reconciles_interfaces() {
    let _ = std::fs::remove_file(format!("{}.iface", sample_db_path()));
    let store = SqliteStore::open(std::path::Path::new(&format!("{}.iface", sample_db_path())))
        .await
        .expect("open test db");

    let asset = Observation::Asset(Asset {
        id: "asset-a".into(),
        ip: "10.0.0.10".parse().unwrap(),
        hostname: None,
        device_class: None,
        os_name: None,
        os_version: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    });
    store.store_observation(asset).await.expect("store asset");

    let iface = Interface::new("asset-a", Some("eth0"), Some("00:11:22:33:44:55"), None);
    store
        .store_observation(Observation::Interface(iface))
        .await
        .expect("store interface");

    let interfaces = store
        .list_interfaces("asset-a")
        .await
        .expect("list interfaces");
    assert_eq!(interfaces.len(), 1);

    // Re-observing the same interface must reconcile, not duplicate.
    let iface = Interface::new("asset-a", Some("eth0"), Some("00:11:22:33:44:55"), None);
    store
        .store_observation(Observation::Interface(iface))
        .await
        .expect("re-store interface");
    let interfaces = store
        .list_interfaces("asset-a")
        .await
        .expect("list interfaces");
    assert_eq!(interfaces.len(), 1);
}

#[tokio::test]
async fn annotation_merges_and_preserves() {
    let _ = std::fs::remove_file(format!("{}.ann", sample_db_path()));
    let store = SqliteStore::open(std::path::Path::new(&format!("{}.ann", sample_db_path())))
        .await
        .expect("open test db");

    store
        .store_observations(sample_observations())
        .await
        .expect("persist sample observations");

    store
        .annotate_asset(
            "asset-db",
            AssetAnnotations {
                environment: Some("prod".into()),
                owner: Some("platform".into()),
                criticality: Some(Criticality::Critical),
                add_tags: vec!["core".into(), "postgres".into()],
                remove_tags: vec![],
            },
        )
        .await
        .expect("annotate");

    // A later discovery of the same asset must not wipe annotations.
    let refreshed = Observation::Asset(Asset {
        id: "asset-db".into(),
        ip: "10.0.0.2".parse().unwrap(),
        hostname: Some("postgres-01".into()),
        device_class: Some("server".into()),
        os_name: Some("Linux".into()),
        os_version: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    });
    store
        .store_observation(refreshed)
        .await
        .expect("re-discover");

    let db = store
        .get_asset("asset-db")
        .await
        .expect("fetch")
        .expect("asset exists");
    assert_eq!(db.environment.as_deref(), Some("prod"));
    assert_eq!(db.owner.as_deref(), Some("platform"));
    assert_eq!(db.criticality, Some(Criticality::Critical));
    assert_eq!(db.tags, vec!["core".to_string(), "postgres".to_string()]);
    assert_eq!(db.os_name.as_deref(), Some("Linux"));

    // Remove one tag; the other annotations stay.
    store
        .annotate_asset(
            "asset-db",
            AssetAnnotations {
                environment: None,
                owner: None,
                criticality: None,
                add_tags: vec![],
                remove_tags: vec!["core".into()],
            },
        )
        .await
        .expect("remove tag");
    let db = store.get_asset("asset-db").await.expect("fetch").unwrap();
    assert_eq!(db.tags, vec!["postgres".to_string()]);
    assert_eq!(db.criticality, Some(Criticality::Critical));
}

#[tokio::test]
async fn job_history_round_trip() {
    let _ = std::fs::remove_file(format!("{}.jobs", sample_db_path()));
    let store = SqliteStore::open(std::path::Path::new(&format!("{}.jobs", sample_db_path())))
        .await
        .expect("open test db");

    store.create_job(sample_job()).await.expect("create job");
    store
        .finish_job(
            "job-1",
            JobStatus::Succeeded,
            None,
            Some(JobOutcome {
                assets_found: 2,
                services_found: 2,
            }),
        )
        .await
        .expect("finish job");

    let jobs = store.list_jobs(Some(10)).await.expect("list jobs");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].collector, "nmap");
    assert_eq!(jobs[0].assets_found, Some(2));
    assert_eq!(jobs[0].services_found, Some(2));
    assert_eq!(jobs[0].status, JobStatus::Succeeded);

    let job = store.get_job("job-1").await.expect("get job").unwrap();
    assert_eq!(job.targets, vec!["10.0.0.0/29".to_string()]);
}

#[tokio::test]
async fn annotate_unknown_asset_errors() {
    let _ = std::fs::remove_file(format!("{}.missing", sample_db_path()));
    let store = SqliteStore::open(std::path::Path::new(&format!(
        "{}.missing",
        sample_db_path()
    )))
    .await
    .expect("open test db");
    let result = store
        .annotate_asset("nope", AssetAnnotations::default())
        .await;
    assert!(result.is_err());
}
