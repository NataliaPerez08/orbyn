//! Integration tests for the persistence path used by the CLI.
//!
//! These populate a real SQLite database with sample observations and verify
//! that the store (and therefore every `orbyn` read command) can retrieve them.

use chrono::Utc;
use orbyn::domain::{Asset, Dependency, Observation, Service};
use orbyn::store::sqlite::SqliteStore;
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
        first_seen: Utc::now(),
        last_seen: Utc::now(),
    };
    vec![
        Observation::Asset(api.clone()),
        Observation::Asset(db.clone()),
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

    let deps = store.list_dependencies().await.expect("list dependencies");
    assert_eq!(deps.len(), 1);
    assert_eq!(deps[0].confidence, 0.9);
}
