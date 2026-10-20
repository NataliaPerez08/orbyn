//! Provider-neutral target catalog (v1.3, runtime overlay in v1.4 track C).
//!
//! Capability data ([`TargetSku`]) and pricing data ([`TargetPrice`]) are
//! kept strictly separate — the roadmap requires the two never blur — and
//! join on (provider, region, sku). Catalogs ship embedded at build time
//! so the binary stays single-file and test runs stay deterministic; a
//! runtime directory (`ORBYN_CATALOG_DIR`, default `./data/catalogs/`)
//! overrides per provider, so freshness arrives as versioned data
//! packages without a rebuild (ADR-0002 D4: no live API calls at report
//! time). A new provider arrives as catalog data, never as engine code.
//!
//! Managed-database tiers ([`ManagedDbTier`]) are the one exception to
//! the capability/price split: a managed tier is a single priced service
//! size, so it is one row.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub mod cost;
pub mod matching;

/// Environment variable overriding the runtime catalog directory.
pub const CATALOG_DIR_ENV: &str = "ORBYN_CATALOG_DIR";

/// Default runtime catalog directory (cwd-anchored, like the default
/// database `./data/orbyn.db`).
const DEFAULT_CATALOG_DIR: &str = "./data/catalogs";

/// One instance type: capability data only, never a price.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetSku {
    pub provider: String,
    pub region: String,
    pub sku: String,
    pub cpu: u32,
    /// RAM in MiB.
    pub memory_mib: u64,
    pub architecture: String,
    pub storage: Option<String>,
    pub capabilities: Vec<String>,
}

/// Block-storage list pricing for a provider's region: one curated
/// general-purpose SSD tier, priced per GiB-month.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct StoragePricing {
    pub sku: String,
    /// List price per GiB-month.
    pub gb_monthly_price: f64,
}

/// One price observation: pricing data only, never a capability.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TargetPrice {
    pub provider: String,
    pub region: String,
    pub sku: String,
    pub currency: String,
    pub hourly_price: f64,
    pub pricing_model: String,
    pub observed_at: String,
    pub source: String,
}

/// One managed-database service tier (engine + size + price in one row).
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ManagedDbTier {
    pub engine: String,
    pub sku: String,
    pub cpu: u32,
    /// RAM in MiB.
    pub memory_mib: u64,
    pub hourly_price: f64,
}

/// A price row as it lives in the catalog file (metadata is catalog-level).
#[derive(Debug, serde::Deserialize)]
struct PriceRow {
    sku: String,
    hourly_price: f64,
    pricing_model: String,
}

/// A capability row as it lives in the catalog file.
#[derive(Debug, serde::Deserialize)]
struct SkuRow {
    sku: String,
    cpu: u32,
    memory_mib: u64,
    architecture: String,
    storage: Option<String>,
    capabilities: Vec<String>,
}

/// A managed-database tier as it lives in the catalog file.
#[derive(Debug, serde::Deserialize)]
struct ManagedDbRow {
    engine: String,
    sku: String,
    cpu: u32,
    memory_mib: u64,
    hourly_price: f64,
}

/// A catalog file: metadata plus its capability and price rows.
#[derive(Debug, serde::Deserialize)]
struct CatalogFile {
    provider: String,
    region: String,
    catalog_version: String,
    retrieved_at: String,
    source: String,
    currency: String,
    storage: Option<StoragePricing>,
    skus: Vec<SkuRow>,
    prices: Vec<PriceRow>,
    #[serde(default)]
    managed_databases: Vec<ManagedDbRow>,
}

/// One provider's parsed catalog.
#[derive(Debug)]
pub struct TargetCatalog {
    pub provider: String,
    pub region: String,
    pub catalog_version: String,
    pub retrieved_at: String,
    pub source: String,
    pub currency: String,
    pub storage: Option<StoragePricing>,
    pub skus: Vec<TargetSku>,
    pub prices: Vec<TargetPrice>,
    pub managed_databases: Vec<ManagedDbTier>,
    /// True when this catalog was loaded from the runtime directory
    /// instead of the embedded default.
    pub runtime: bool,
}

impl TargetCatalog {
    /// The price of one sku, if the catalog has it.
    pub fn price(&self, sku: &str) -> Option<&TargetPrice> {
        self.prices.iter().find(|p| p.sku == sku)
    }

    /// The managed-database tiers for one engine, if the catalog has any.
    pub fn managed_db_tiers(&self, engine: &str) -> Vec<&ManagedDbTier> {
        self.managed_databases
            .iter()
            .filter(|t| t.engine == engine)
            .collect()
    }
}

const AWS: &str = include_str!("../../data/catalogs/aws.json");
const AZURE: &str = include_str!("../../data/catalogs/azure.json");
const GCP: &str = include_str!("../../data/catalogs/gcp.json");
const HUAWEI: &str = include_str!("../../data/catalogs/huawei.json");
const OPENSTACK: &str = include_str!("../../data/catalogs/openstack.json");

/// Parse and validate one catalog file. Used for embedded catalogs
/// (where failure is a build bug) and runtime packages (where failure
/// means the file is skipped with a warning, never a silent load).
// `!(x > 0.0)` over `x <= 0.0` is deliberate: a NaN price must fail
// validation, and NaN compares false against everything.
#[allow(clippy::neg_cmp_op_on_partial_ord)]
pub fn parse_catalog(raw: &str) -> Result<TargetCatalog, String> {
    let f: CatalogFile =
        serde_json::from_str(raw).map_err(|e| format!("invalid catalog JSON: {e}"))?;
    for (name, value) in [
        ("provider", &f.provider),
        ("region", &f.region),
        ("catalog_version", &f.catalog_version),
        ("retrieved_at", &f.retrieved_at),
        ("source", &f.source),
        ("currency", &f.currency),
    ] {
        if value.trim().is_empty() {
            return Err(format!("empty {name}"));
        }
    }
    if f.skus.is_empty() {
        return Err("catalog has no SKUs".into());
    }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for s in &f.skus {
        if !seen.insert(&s.sku) {
            return Err(format!("duplicate SKU '{}'", s.sku));
        }
        if s.cpu == 0 || s.memory_mib == 0 {
            return Err(format!("SKU '{}' has no cpu or memory", s.sku));
        }
    }
    let mut priced: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for p in &f.prices {
        if !seen.contains(&p.sku.as_str()) {
            return Err(format!("price for unknown SKU '{}'", p.sku));
        }
        if !priced.insert(&p.sku) {
            return Err(format!("duplicate price for '{}'", p.sku));
        }
        if !(p.hourly_price > 0.0) {
            return Err(format!("price for '{}' is not positive", p.sku));
        }
    }
    if let Some(storage) = &f.storage {
        if !(storage.gb_monthly_price > 0.0) {
            return Err("storage price is not positive".into());
        }
        if storage.sku.trim().is_empty() {
            return Err("storage sku is empty".into());
        }
    }
    let mut tiers: std::collections::HashSet<(&str, &str)> = std::collections::HashSet::new();
    for t in &f.managed_databases {
        if !tiers.insert((&t.engine, &t.sku)) {
            return Err(format!("duplicate managed-database tier '{}'", t.sku));
        }
        if t.engine.trim().is_empty() || t.sku.trim().is_empty() {
            return Err("managed-database tier with empty engine or sku".into());
        }
        if t.cpu == 0 || t.memory_mib == 0 || !(t.hourly_price > 0.0) {
            return Err(format!(
                "managed-database tier '{}' has no size or price",
                t.sku
            ));
        }
    }

    let skus = f
        .skus
        .into_iter()
        .map(|s| TargetSku {
            provider: f.provider.clone(),
            region: f.region.clone(),
            sku: s.sku,
            cpu: s.cpu,
            memory_mib: s.memory_mib,
            architecture: s.architecture,
            storage: s.storage,
            capabilities: s.capabilities,
        })
        .collect();
    let prices = f
        .prices
        .into_iter()
        .map(|p| TargetPrice {
            provider: f.provider.clone(),
            region: f.region.clone(),
            currency: f.currency.clone(),
            observed_at: f.retrieved_at.clone(),
            source: f.source.clone(),
            sku: p.sku,
            hourly_price: p.hourly_price,
            pricing_model: p.pricing_model,
        })
        .collect();
    let managed_databases = f
        .managed_databases
        .into_iter()
        .map(|t| ManagedDbTier {
            engine: t.engine,
            sku: t.sku,
            cpu: t.cpu,
            memory_mib: t.memory_mib,
            hourly_price: t.hourly_price,
        })
        .collect();
    Ok(TargetCatalog {
        provider: f.provider,
        region: f.region,
        catalog_version: f.catalog_version,
        retrieved_at: f.retrieved_at,
        source: f.source,
        currency: f.currency,
        storage: f.storage,
        skus,
        prices,
        managed_databases,
        runtime: false,
    })
}

/// The runtime catalog directory: `ORBYN_CATALOG_DIR`, or
/// `./data/catalogs/` by default.
pub fn catalog_dir() -> PathBuf {
    std::env::var_os(CATALOG_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CATALOG_DIR))
}

/// Load the embedded catalogs, then overlay every valid `*.json` in
/// `dir` (sorted for determinism; a later file replaces an earlier one
/// for the same provider). Invalid files are skipped with a warning —
/// a bad package must never break a report.
pub fn load_from(dir: Option<&Path>) -> Vec<TargetCatalog> {
    let mut out: Vec<TargetCatalog> = [AWS, AZURE, GCP, HUAWEI, OPENSTACK]
        .iter()
        .map(|raw| parse_catalog(raw).expect("embedded catalog must be valid"))
        .collect();
    let Some(dir) = dir else {
        return out;
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return out, // absent/unreadable dir: embedded defaults only
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    for path in paths {
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("WARNING: ignoring catalog override {}: {e}", path.display());
                continue;
            }
        };
        match parse_catalog(&raw) {
            Ok(mut catalog) => {
                catalog.runtime = true;
                let provider = catalog.provider.clone();
                match out.iter_mut().find(|c| c.provider == provider) {
                    Some(existing) => *existing = catalog,
                    None => out.push(catalog),
                }
            }
            Err(e) => eprintln!("WARNING: ignoring catalog override {}: {e}", path.display()),
        }
    }
    out
}

/// All loaded catalogs: embedded defaults plus runtime overrides.
pub fn catalogs() -> &'static [TargetCatalog] {
    static CATALOGS: OnceLock<Vec<TargetCatalog>> = OnceLock::new();
    CATALOGS.get_or_init(|| load_from(Some(&catalog_dir())))
}

/// One provider's catalog by label ("aws", "azure", "gcp", ...).
pub fn catalog(provider: &str) -> Option<&'static TargetCatalog> {
    catalogs().iter().find(|c| c.provider == provider)
}

/// Validate a catalog package and install it into `dir` as
/// `<provider>.json`. Returns the parsed catalog for reporting.
pub fn install_catalog(raw: &str, dir: &Path) -> Result<TargetCatalog, String> {
    let catalog = parse_catalog(raw)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", catalog.provider));
    std::fs::write(&path, raw).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(catalog)
}

/// One entry of a catalog update manifest: a versioned package offered
/// at `<base>/<file>`.
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
pub struct CatalogManifestEntry {
    pub provider: String,
    pub file: String,
    /// ISO date (YYYY-MM-DD); compared lexically against the loaded
    /// catalog's `retrieved_at`.
    pub retrieved_at: String,
}

/// A catalog update manifest served at `<base>/manifest.json`.
#[derive(Debug, serde::Deserialize)]
pub struct CatalogManifest {
    pub catalogs: Vec<CatalogManifestEntry>,
}

/// What `orbyn catalog update` should do with one manifest entry.
#[derive(Debug, Clone, PartialEq)]
pub enum CatalogUpdate {
    /// Fetch and install the package.
    Install(CatalogManifestEntry),
    /// The loaded catalog is at least as fresh (`have >= offered`).
    UpToDate {
        provider: String,
        have: String,
        offered: String,
    },
}

/// Decide, per manifest entry, whether to install. Lexical ISO-date
/// comparison: `retrieved_at` is pinned to YYYY-MM-DD by validation
/// convention, and an equal date means no churn.
pub fn update_decisions(
    manifest: &CatalogManifest,
    current: &[TargetCatalog],
) -> Vec<CatalogUpdate> {
    manifest
        .catalogs
        .iter()
        .map(
            |entry| match current.iter().find(|c| c.provider == entry.provider) {
                Some(c) if c.retrieved_at >= entry.retrieved_at => CatalogUpdate::UpToDate {
                    provider: entry.provider.clone(),
                    have: c.retrieved_at.clone(),
                    offered: entry.retrieved_at.clone(),
                },
                _ => CatalogUpdate::Install(entry.clone()),
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_parse_with_metadata() {
        let all = catalogs();
        assert_eq!(all.len(), 5);
        let aws = catalog("aws").expect("aws catalog");
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.catalog_version, "aws-catalog/2026-10");
        assert_eq!(aws.currency, "USD");
        assert!(!aws.skus.is_empty());
        assert!(!aws.prices.is_empty());
        assert!(catalog("huawei").is_some());
        for c in catalogs() {
            if c.provider == "openstack" {
                // Reference flavors only: sizing works, pricing stays
                // honestly not calculated (private-cloud pricing is
                // site-specific).
                assert!(c.prices.is_empty());
                assert!(c.storage.is_none());
                continue;
            }
            let storage = c.storage.as_ref().expect("storage pricing");
            assert!(storage.gb_monthly_price > 0.0, "{}", c.provider);
            assert!(!storage.sku.is_empty());
            assert!(!c.prices.is_empty(), "{}", c.provider);
        }
    }

    #[test]
    fn capability_and_price_rows_stay_consistent() {
        for c in catalogs() {
            let names: Vec<&str> = c.skus.iter().map(|s| s.sku.as_str()).collect();
            let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
            assert_eq!(names.len(), unique.len(), "duplicate sku in {}", c.provider);
            for p in &c.prices {
                assert!(
                    names.contains(&p.sku.as_str()),
                    "price for unknown sku {} in {}",
                    p.sku,
                    c.provider
                );
                assert!(p.hourly_price > 0.0, "{} price not positive", p.sku);
            }
            let price_skus: std::collections::HashSet<&str> =
                c.prices.iter().map(|p| p.sku.as_str()).collect();
            assert_eq!(
                price_skus.len(),
                c.prices.len(),
                "duplicate price in {}",
                c.provider
            );
        }
    }

    #[test]
    fn rows_carry_their_catalog_metadata() {
        let aws = catalog("aws").expect("aws catalog");
        let sku = &aws.skus[0];
        assert_eq!(sku.provider, "aws");
        assert_eq!(sku.region, "us-east-1");
        let price = aws.price(&sku.sku).expect("price for first sku");
        assert_eq!(price.provider, "aws");
        assert_eq!(price.observed_at, aws.retrieved_at);
        assert_eq!(price.source, aws.source);
    }

    #[test]
    fn managed_db_tiers_load_per_engine() {
        for (provider, engine) in [("aws", "postgres"), ("azure", "mysql"), ("gcp", "postgres")] {
            let tiers = catalog(provider)
                .unwrap_or_else(|| panic!("{provider} catalog"))
                .managed_db_tiers(engine);
            assert!(!tiers.is_empty(), "{provider}/{engine}");
            assert!(tiers.iter().all(|t| t.hourly_price > 0.0));
        }
        // First cut: only postgres and mysql are priced.
        assert!(catalog("aws")
            .unwrap()
            .managed_db_tiers("oracle")
            .is_empty());
        assert!(catalog("huawei").unwrap().managed_databases.is_empty());
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("orbyn-catalog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn package(provider: &str, retrieved_at: &str) -> String {
        format!(
            r#"{{
              "provider": "{provider}",
              "region": "us-east-1",
              "catalog_version": "{provider}-catalog/{retrieved_at}",
              "retrieved_at": "{retrieved_at}",
              "source": "test package",
              "currency": "USD",
              "storage": {{"sku": "gp3", "gb_monthly_price": 0.08}},
              "skus": [
                {{"sku": "t3.small", "cpu": 2, "memory_mib": 2048, "architecture": "x86_64", "storage": null, "capabilities": []}}
              ],
              "prices": [
                {{"sku": "t3.small", "hourly_price": 0.0208, "pricing_model": "on-demand"}}
              ]
            }}"#
        )
    }

    #[test]
    fn runtime_override_replaces_embedded_and_new_providers_append() {
        let dir = temp_dir("overlay");
        std::fs::write(dir.join("aws.json"), package("aws", "2026-11-01")).unwrap();
        std::fs::write(
            dir.join("digitalocean.json"),
            package("digitalocean", "2026-10-15"),
        )
        .unwrap();
        std::fs::write(dir.join("broken.json"), "{ not json").unwrap();

        let loaded = load_from(Some(&dir));
        let aws = loaded.iter().find(|c| c.provider == "aws").unwrap();
        assert_eq!(aws.retrieved_at, "2026-11-01");
        assert_eq!(aws.catalog_version, "aws-catalog/2026-11-01");
        assert!(aws.runtime);
        let docean = loaded
            .iter()
            .find(|c| c.provider == "digitalocean")
            .unwrap();
        assert!(docean.runtime);
        assert!(loaded.iter().any(|c| c.provider == "digitalocean"));
        // The broken package is skipped, not loaded.
        assert!(!loaded.iter().any(|c| c.provider == "broken"));
        assert_eq!(loaded.len(), 6);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn absent_dir_means_embedded_only() {
        let loaded = load_from(Some(Path::new("/nonexistent-orbyn-catalog-dir")));
        assert_eq!(loaded.len(), 5);
        assert!(loaded.iter().all(|c| !c.runtime));
    }

    #[test]
    fn validation_rejects_broken_packages() {
        assert!(parse_catalog("").is_err());
        assert!(parse_catalog("[]").is_err());
        let base = package("aws", "2026-11-01");
        // Price for an unknown SKU.
        let bad = base.replace("t3.small\", \"hourly_price", "t3.nope\", \"hourly_price");
        assert!(parse_catalog(&bad).is_err());
        // Empty provider.
        let bad = base.replace("\"provider\": \"aws\"", "\"provider\": \"\"");
        assert!(parse_catalog(&bad).is_err());
        // Non-positive price.
        let bad = base.replace("0.0208", "0");
        assert!(parse_catalog(&bad).is_err());
    }

    #[test]
    fn install_catalog_writes_and_validates() {
        let dir = temp_dir("install");
        let installed = install_catalog(&package("aws", "2026-12-01"), &dir).unwrap();
        assert_eq!(installed.provider, "aws");
        assert!(dir.join("aws.json").exists());
        assert!(install_catalog("{ bad", &dir).is_err());
        let loaded = load_from(Some(&dir));
        assert_eq!(
            loaded
                .iter()
                .find(|c| c.provider == "aws")
                .unwrap()
                .retrieved_at,
            "2026-12-01"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_decisions_respect_freshness() {
        let manifest = CatalogManifest {
            catalogs: vec![
                CatalogManifestEntry {
                    provider: "aws".into(),
                    file: "aws-2026-11.json".into(),
                    retrieved_at: "2026-11-01".into(),
                },
                CatalogManifestEntry {
                    provider: "azure".into(),
                    file: "azure-2026-09.json".into(),
                    retrieved_at: "2026-09-01".into(),
                },
                CatalogManifestEntry {
                    provider: "digitalocean".into(),
                    file: "do-2026-10.json".into(),
                    retrieved_at: "2026-10-15".into(),
                },
            ],
        };
        let current = load_from(None);
        let decisions = update_decisions(&manifest, &current);
        assert_eq!(
            decisions[0],
            CatalogUpdate::Install(manifest.catalogs[0].clone())
        );
        assert_eq!(
            decisions[1],
            CatalogUpdate::UpToDate {
                provider: "azure".into(),
                have: "2026-10-01".into(),
                offered: "2026-09-01".into(),
            }
        );
        // A provider with no current catalog is always installed.
        assert!(matches!(decisions[2], CatalogUpdate::Install(_)));
    }
}
