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
        "applications",
        "application_members",
        "migration_plans",
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
        "idx_application_members_asset",
        "idx_migration_plans_application",
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
    assert_eq!(
        migration_count, 11,
        "all current migrations must be applied"
    );
    assert!(table_names(&upgraded)
        .await
        .iter()
        .any(|name| name == "asset_connections"));
    assert!(table_names(&upgraded)
        .await
        .iter()
        .any(|name| name == "applications"));
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
async fn applications_support_manual_precedence_and_tombstones() {
    use orbyn::domain::{AppSource, Application, ApplicationMember, Connection};

    let store = open("schema-applications").await;
    let now = chrono::Utc::now();

    let asset = |id: &str, ip: &str| Asset {
        id: id.into(),
        ip: ip.parse().unwrap(),
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
        .store_observation(Observation::Asset(asset("app-asset-1", "10.0.0.61")))
        .await
        .expect("store asset 1");
    store
        .store_observation(Observation::Asset(asset("app-asset-2", "10.0.0.62")))
        .await
        .expect("store asset 2");

    // Re-observing the same connection increments the observation counter
    // and the aggregate joins against the inventory.
    let conn = Connection {
        asset_id: "app-asset-1".into(),
        proto: "tcp".into(),
        local_ip: None,
        local_port: None,
        remote_ip: "10.0.0.62".parse().unwrap(),
        remote_port: 5432,
        process: None,
    };
    store
        .store_observation(Observation::Connection(conn.clone()))
        .await
        .expect("connection 1");
    store
        .store_observation(Observation::Connection(conn))
        .await
        .expect("connection 2");
    let evidence = store.list_dependency_evidence().await.expect("evidence");
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].source_asset_id, "app-asset-1");
    assert_eq!(evidence[0].target_asset_id, "app-asset-2");
    assert_eq!(evidence[0].observations, 2, "upsert must increment");

    // Manual application: create, add, remove deletes the row outright.
    let app = |id: &str, name: &str, source: AppSource| Application {
        id: id.into(),
        name: name.into(),
        source,
        confidence: 1.0,
        created_at: now,
        updated_at: now,
    };
    store
        .create_application(app("manual-1", "billing", AppSource::Manual))
        .await
        .expect("create manual application");
    store
        .add_application_member(ApplicationMember {
            application_id: "manual-1".into(),
            asset_id: "app-asset-1".into(),
            source: AppSource::Manual,
            confidence: 1.0,
            evidence: Vec::new(),
            is_excluded: false,
        })
        .await
        .expect("add manual member");
    // Lookup is by id or case-insensitive name.
    assert_eq!(
        store.get_application("BILLING").await.unwrap().unwrap().id,
        "manual-1"
    );
    assert!(store
        .remove_application_member("manual-1", "app-asset-1")
        .await
        .unwrap());
    assert!(store
        .list_application_members("manual-1")
        .await
        .unwrap()
        .is_empty());

    // A duplicate name is rejected with a clean error.
    store
        .create_application(app("manual-2", "billing", AppSource::Manual))
        .await
        .expect_err("duplicate name must be rejected");

    // Inferred application: refresh replaces inferred members but keeps
    // manual rows and exclusion tombstones.
    store
        .create_application(app("inf-1", "web-stack", AppSource::Inferred))
        .await
        .expect("create inferred application");
    let inferred_member = |asset_id: &str| ApplicationMember {
        application_id: "inf-1".into(),
        asset_id: asset_id.into(),
        source: AppSource::Inferred,
        confidence: 0.9,
        evidence: Vec::new(),
        is_excluded: false,
    };
    store
        .replace_inferred_members(
            "inf-1",
            vec![
                inferred_member("app-asset-1"),
                inferred_member("app-asset-2"),
            ],
        )
        .await
        .expect("first inferred refresh");
    // A manual add on an inferred member upgrades it to manual.
    store
        .add_application_member(ApplicationMember {
            application_id: "inf-1".into(),
            asset_id: "app-asset-1".into(),
            source: AppSource::Manual,
            confidence: 1.0,
            evidence: Vec::new(),
            is_excluded: false,
        })
        .await
        .expect("manual upgrade");
    // Removing the other inferred member leaves a tombstone.
    assert!(store
        .remove_application_member("inf-1", "app-asset-2")
        .await
        .unwrap());

    // Re-discovery re-infers both assets: the manual row survives, and
    // the tombstone blocks the excluded asset from coming back.
    store
        .replace_inferred_members(
            "inf-1",
            vec![
                inferred_member("app-asset-1"),
                inferred_member("app-asset-2"),
            ],
        )
        .await
        .expect("second inferred refresh");
    let members = store
        .list_application_members("inf-1")
        .await
        .expect("list members");
    assert_eq!(members.len(), 2);
    let upgraded = members
        .iter()
        .find(|m| m.asset_id == "app-asset-1")
        .expect("upgraded member");
    assert_eq!(upgraded.source, AppSource::Manual, "manual must survive");
    let tombstone = members
        .iter()
        .find(|m| m.asset_id == "app-asset-2")
        .expect("tombstone member");
    assert!(tombstone.is_excluded, "exclusion must survive");

    // Confidence refreshes only touch inferred applications.
    store
        .update_application_confidence("inf-1", 0.5)
        .await
        .expect("update confidence");
    let refreshed = store
        .get_application("web-stack")
        .await
        .unwrap()
        .expect("inferred app");
    assert!((refreshed.confidence - 0.5).abs() < f32::EPSILON);

    // Deleting removes the application and its members.
    store.delete_application("inf-1").await.expect("delete");
    assert!(store
        .list_application_members("inf-1")
        .await
        .unwrap()
        .is_empty());
    assert!(store.get_application("inf-1").await.unwrap().is_none());
}

#[tokio::test]
async fn plans_round_trip_through_json_columns() {
    use orbyn::domain::{
        BlockerSeverity, MigrationAssumption, MigrationBlocker, MigrationPlan,
        MigrationRecommendation, MigrationStrategy, MigrationTarget, PlanProvenance,
        ReadinessFactor,
    };

    let store = open("schema-plans").await;
    let now = chrono::Utc::now();

    let asset = Asset {
        id: "plan-asset-1".into(),
        ip: "10.0.0.71".parse().unwrap(),
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
    store
        .create_application(orbyn::domain::Application {
            id: "plan-app-1".into(),
            name: "billing".into(),
            source: orbyn::domain::AppSource::Manual,
            confidence: 1.0,
            created_at: now,
            updated_at: now,
        })
        .await
        .expect("create application");

    let plan = MigrationPlan {
        id: "plan-1".into(),
        application_id: "plan-app-1".into(),
        created_at: now,
        provenance: PlanProvenance {
            assets: 1,
            last_seen: now,
            rules_version: "0.8.0".into(),
            inference_version: "application-inference/v1".into(),
            readiness_version: "readiness/v1".into(),
            strategy_version: "strategy/v1".into(),
            sku_catalog_version: "sku-catalog/v1".into(),
        },
        readiness: 72,
        readiness_factors: vec![ReadinessFactor {
            factor: "inventory-completeness".into(),
            delta: -12,
            evidence: vec!["2 of 3 assets miss OS metadata".into()],
        }],
        recommendation: MigrationRecommendation {
            strategy: MigrationStrategy::Rehost,
            confidence: 0.8,
            rationale: "standard x86 servers, no blockers".into(),
            evidence: vec!["no exotic hardware".into()],
            alternatives: vec![MigrationStrategy::Replatform],
        },
        wave: Some(2),
        targets: vec![MigrationTarget {
            asset_id: "plan-asset-1".into(),
            cores: Some(4),
            ram_mb: Some(8192),
            provider: Some("aws".into()),
            instance_type: Some("m5.xlarge".into()),
        }],
        blockers: vec![MigrationBlocker {
            severity: BlockerSeverity::Warning,
            factor: "unconfirmed-dependencies".into(),
            message: "2 unconfirmed edges".into(),
            evidence: vec!["plan-asset-1 -> 10.0.0.99:5432".into()],
        }],
        assumptions: vec![MigrationAssumption {
            assumption: "metrics window".into(),
            detail: "no samples; sizing from capacity allocation".into(),
        }],
    };
    store.save_plan(plan.clone()).await.expect("save plan");

    let fetched = store.get_plan("plan-1").await.unwrap().expect("plan");
    assert_eq!(fetched, plan, "plan must round-trip exactly");

    // A second plan for another application: list filters and orders
    // newest first.
    let mut other = plan;
    other.id = "plan-2".into();
    other.application_id = "plan-app-1".into();
    other.readiness = 10;
    other.wave = None;
    std::thread::sleep(std::time::Duration::from_millis(10));
    other.created_at = chrono::Utc::now();
    store.save_plan(other).await.expect("save second plan");

    let all = store.list_plans(None).await.unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].id, "plan-2", "newest first");
    let for_app = store.list_plans(Some("plan-app-1")).await.unwrap();
    assert_eq!(for_app.len(), 2);
    assert!(store.list_plans(Some("nope")).await.unwrap().is_empty());
    assert!(store.get_plan("missing").await.unwrap().is_none());
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
