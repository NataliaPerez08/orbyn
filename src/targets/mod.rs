//! Provider-neutral target catalog (v1.3).
//!
//! Capability data ([`TargetSku`]) and pricing data ([`TargetPrice`]) are
//! kept strictly separate — the roadmap requires the two never blur — and
//! join on (provider, region, sku). Catalogs are versioned local files
//! under `data/catalogs/`, embedded at build time so the binary stays
//! single-file and test runs stay deterministic. A new provider arrives
//! as catalog data, never as engine code.
//!
//! ponytail: catalogs are embedded, not read from a runtime directory —
//! `orbyn catalog update` (online refresh behind a source adapter) needs a
//! runtime catalog dir; add it when a live pricing source exists.

use std::sync::OnceLock;

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

/// A catalog file: metadata plus its capability and price rows.
#[derive(Debug, serde::Deserialize)]
struct CatalogFile {
    provider: String,
    region: String,
    catalog_version: String,
    retrieved_at: String,
    source: String,
    currency: String,
    skus: Vec<SkuRow>,
    prices: Vec<PriceRow>,
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
    pub skus: Vec<TargetSku>,
    pub prices: Vec<TargetPrice>,
}

impl TargetCatalog {
    /// The price of one sku, if the catalog has it.
    pub fn price(&self, sku: &str) -> Option<&TargetPrice> {
        self.prices.iter().find(|p| p.sku == sku)
    }
}

const AWS: &str = include_str!("../../data/catalogs/aws.json");
const AZURE: &str = include_str!("../../data/catalogs/azure.json");
const GCP: &str = include_str!("../../data/catalogs/gcp.json");

/// Parse one embedded catalog file, denormalizing the catalog metadata
/// into each row. A corrupt embedded file is a build bug, like the EOL
/// table: it must panic, not silently degrade.
fn parse(raw: &str) -> TargetCatalog {
    let f: CatalogFile = serde_json::from_str(raw).expect("embedded catalog must be valid");
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
    TargetCatalog {
        provider: f.provider,
        region: f.region,
        catalog_version: f.catalog_version,
        retrieved_at: f.retrieved_at,
        source: f.source,
        currency: f.currency,
        skus,
        prices,
    }
}

/// All embedded catalogs.
pub fn catalogs() -> &'static [TargetCatalog] {
    static CATALOGS: OnceLock<Vec<TargetCatalog>> = OnceLock::new();
    CATALOGS.get_or_init(|| [AWS, AZURE, GCP].iter().map(|raw| parse(raw)).collect())
}

/// One provider's catalog by label ("aws", "azure", "gcp").
pub fn catalog(provider: &str) -> Option<&'static TargetCatalog> {
    catalogs().iter().find(|c| c.provider == provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogs_parse_with_metadata() {
        let all = catalogs();
        assert_eq!(all.len(), 3);
        let aws = catalog("aws").expect("aws catalog");
        assert_eq!(aws.region, "us-east-1");
        assert_eq!(aws.catalog_version, "aws-catalog/2026-10");
        assert_eq!(aws.currency, "USD");
        assert!(!aws.skus.is_empty());
        assert!(!aws.prices.is_empty());
        assert!(catalog("huawei").is_none());
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
}
