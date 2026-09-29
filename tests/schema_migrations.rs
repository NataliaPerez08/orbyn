//! Integration tests for the SQLite schema: migrations apply cleanly,
//! idempotently, and produce the tables/indexes each milestone relies on.
//!
//! These use the store's public `open` path (which runs `sqlx::migrate!`) and
//! inspect `sqlite_master` through the exposed pool.

use orbyn::domain::{Asset, Interface, Observation};
use orbyn::store::sqlite::SqliteStore;
use orbyn::store::Store;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

fn db_path(tag: &str) -> String {
    std::env::var("ORBYN_TEST_DB")
        .map(|base| format!("{base}.{tag}"))
        .unwrap_or_else(|_| format!("/tmp/orbyn-test-{tag}.db"))
}

async fn open(tag: &str) -> SqliteStore {
    let path = db_path(tag);
    let _ = std::fs::remove_file(&path);
    SqliteStore::open(std::path::Path::new(&path))
        .await
        .expect("open test db")
}

async fn table_names(store: &SqliteStore) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
    )
    .fetch_all(store.pool())
    .await
    .expect("list tables")
}

async fn index_names(store: &SqliteStore) -> Vec<String> {
    sqlx::query_scalar::<_, String>(
        "SELECT name FROM sqlite_master WHERE type = 'index' \
         AND (name LIKE 'idx_%' OR name LIKE 'uq_%') ORDER BY name",
    )
    .fetch_all(store.pool())
    .await
    .expect("list indexes")
}

#[tokio::test]
async fn migrations_create_all_expected_tables() {
    let store = open("schema-tables").await;
    let tables = table_names(&store).await;

    for expected in [
        "assets",
        "services",
        "discovery_jobs",
        "asset_capacity",
        "metric_samples",
        "dependencies",
        "asset_interfaces",
        "asset_filesystems",
        "asset_running_services",
        "asset_connections",
        "audit_events",
        "_sqlx_migrations",
    ] {
        assert!(
            tables.iter().any(|t| t == expected),
            "missing table {expected}: {tables:?}"
        );
    }
}

#[tokio::test]
async fn migrations_create_expected_indexes() {
    let store = open("schema-indexes").await;
    let indexes = index_names(&store).await;
    for expected in [
        "idx_metric_samples_asset_time",
        "uq_metric_samples_asset_instant",
        "idx_asset_interfaces_asset",
        "idx_asset_filesystems_asset",
        "idx_discovery_jobs_started",
        "idx_asset_connections_asset",
        "idx_dependencies_source",
        "idx_dependencies_target",
        "idx_audit_events_started",
    ] {
        assert!(
            indexes.iter().any(|i| i == expected),
            "missing index {expected}: {indexes:?}"
        );
    }
}

#[tokio::test]
async fn migrations_are_idempotent_on_reopen() {
    let tag = "schema-idempotent";
    let path = db_path(tag);
    let _ = std::fs::remove_file(&path);

    let first = SqliteStore::open(std::path::Path::new(&path))
        .await
        .expect("first open");
    let tables = table_names(&first).await;

    drop(first);
    // Reopen the same file: `migrate!` must be a no-op, not an error.
    let second = SqliteStore::open(std::path::Path::new(&path))
        .await
        .expect("second open must be idempotent");
    assert_eq!(table_names(&second).await, tables);
}

#[tokio::test]
async fn existing_initial_schema_is_upgraded_and_data_is_preserved() {
    let tag = "schema-upgrade";
    let path = db_path(tag);
    let _ = std::fs::remove_file(&path);

    // Simulate a database created by the initial release before later
    // migrations were added. It intentionally has no _sqlx_migrations table.
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("open legacy database");
    sqlx::raw_sql(include_str!("../migrations/0001_initial.sql"))
        .execute(&pool)
        .await
        .expect("create initial schema");
    sqlx::query(
        "INSERT INTO assets (id, ip, hostname, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind("legacy-asset")
    .bind("192.0.2.10")
    .bind("legacy-host")
    .bind("2024-01-01T00:00:00Z")
    .bind("2024-01-01T00:00:00Z")
    .execute(&pool)
    .await
    .expect("insert legacy asset");
    pool.close().await;

    let upgraded = SqliteStore::open(std::path::Path::new(&path))
        .await
        .expect("upgrade legacy database");
    let asset = upgraded
        .get_asset("legacy-asset")
        .await
        .expect("read upgraded asset")
        .expect("legacy asset preserved");
    assert_eq!(asset.ip.to_string(), "192.0.2.10");
    assert_eq!(asset.hostname.as_deref(), Some("legacy-host"));

    let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(upgraded.pool())
        .await
        .expect("count applied migrations");
    assert_eq!(migration_count, 9, "all current migrations must be applied");
    assert!(table_names(&upgraded)
        .await
        .iter()
        .any(|name| name == "asset_connections"));
    // The Phase 2 virtualization column must exist on the upgraded schema.
    let hypervisor: Option<String> =
        sqlx::query_scalar("SELECT hypervisor FROM asset_capacity LIMIT 1")
            .fetch_optional(upgraded.pool())
            .await
            .expect("hypervisor column readable")
            .flatten();
    assert_eq!(hypervisor, None, "empty table, column present");
}

#[tokio::test]
async fn foreign_keys_are_enforced() {
    let store = open("schema-fk").await;
    // An interface referencing a non-existent asset must fail.
    let result = store
        .store_observation(Observation::Interface(Interface::new(
            "missing-asset",
            Some("eth0"),
            Some("00:11:22:33:44:55"),
            None,
        )))
        .await;
    assert!(result.is_err(), "FK violation must be rejected");
}

#[tokio::test]
async fn asset_can_receive_every_observation_family() {
    let store = open("schema-roundtrip").await;
    let now = chrono::Utc::now();
    let asset = Asset {
        id: "asset-all".into(),
        ip: "10.0.0.50".parse().unwrap(),
        hostname: None,
        device_class: None,
        os_name: None,
        os_version: None,
        sys_descr: None,
        environment: None,
        owner: None,
        criticality: None,
        tags: Vec::new(),
        first_seen: now,
        last_seen: now,
    };
    store
        .store_observation(Observation::Asset(asset))
        .await
        .expect("store asset");

    // Each table reserved across milestones is reachable via its observation
    // family; capacity/filesystem/running-service/connection persisted here
    // prove the v0.3/v0.4 columns accept real data.
    use orbyn::domain::{Capacity, Connection, Filesystem, RunningService, Service};
    store
        .store_observation(Observation::Capacity(Capacity {
            asset_id: "asset-all".into(),
            cpu_model: Some("x".into()),
            cpu_sockets: Some(1),
            cpu_cores: Some(4),
            cpu_threads: Some(8),
            ram_total_mb: Some(8192),
            hypervisor: Some("kvm".into()),
            collected_at: now,
        }))
        .await
        .expect("capacity");
    store
        .store_observation(Observation::Filesystem(Filesystem {
            asset_id: "asset-all".into(),
            device: Some("/dev/sda1".into()),
            mount: "/".into(),
            fs_type: Some("ext4".into()),
            size_kb: 100,
            used_kb: Some(50),
            available_kb: Some(50),
            used_pct: Some(50),
        }))
        .await
        .expect("filesystem");
    store
        .store_observation(Observation::RunningService(RunningService {
            asset_id: "asset-all".into(),
            name: "nginx.service".into(),
            state: Some("running".into()),
            description: None,
        }))
        .await
        .expect("running service");
    store
        .store_observation(Observation::Service(Service {
            asset_id: "asset-all".into(),
            proto: "tcp".into(),
            port: 443,
            name: None,
            state: "open".into(),
            banner: None,
        }))
        .await
        .expect("service");
    store
        .store_observation(Observation::Connection(Connection {
            asset_id: "asset-all".into(),
            proto: "tcp".into(),
            local_ip: None,
            local_port: None,
            remote_ip: "203.0.113.9".parse().unwrap(),
            remote_port: 443,
            process: None,
        }))
        .await
        .expect("connection");

    assert_eq!(store.list_assets().await.unwrap().len(), 1);
    assert_eq!(store.list_services("asset-all").await.unwrap().len(), 1);
    assert_eq!(store.list_filesystems("asset-all").await.unwrap().len(), 1);
    assert_eq!(
        store
            .list_running_services("asset-all")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(store.list_connections("asset-all").await.unwrap().len(), 1);
    assert!(store.get_capacity("asset-all").await.unwrap().is_some());
}
