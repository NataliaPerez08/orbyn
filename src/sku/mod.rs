//! Cloud SKU matching (Phase 9 of `docs/ORBYN_AGENT_PLAN.md`).
//!
//! Converts a vendor-neutral right-sizing baseline (vCPU + RAM) into candidate
//! instance types per provider. Kept fully separate from the core right-sizing
//! rules so provider catalogs never leak into the assessment; the CLI takes an
//! explicit baseline (`orbyn sku-match --provider <p> --cores <n> --ram-mb <m>`).
//!
//! Since v1.3 the capability data lives in the provider-neutral catalog
//! (`crate::targets`, `data/catalogs/`); this module is the thin
//! match-and-render wrapper the `sku-match` command and the planner use.

use std::fmt;

use crate::output::Format;
use crate::targets;

/// Version of the match model; bumped when matching changes so plan
/// provenance stays meaningful. The catalog data carries its own
/// per-provider `catalog_version`.
pub const CATALOG_VERSION: &str = "sku-catalog/v1";

/// A matching instance type (the `sku-match` result view).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Sku {
    pub name: String,
    pub vcpu: u32,
    /// RAM in MiB.
    pub ram_mib: u64,
}

impl fmt::Display for Sku {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} vCPU, {} MiB RAM)",
            self.name, self.vcpu, self.ram_mib
        )
    }
}

/// Providers with a catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Provider {
    Aws,
    Azure,
    Gcp,
}

impl Provider {
    /// Canonical provider label used in CSV output.
    pub fn label(self) -> &'static str {
        match self {
            Provider::Aws => "aws",
            Provider::Azure => "azure",
            Provider::Gcp => "gcp",
        }
    }
}

/// Candidate SKUs meeting both the vCPU and RAM requirement, smallest fit
/// first (by vCPU, then RAM).
pub fn match_skus(provider: Provider, cores: u32, ram_mib: u64) -> Vec<Sku> {
    let catalog = targets::catalog(provider.label()).expect("provider catalog");
    let mut fits: Vec<Sku> = catalog
        .skus
        .iter()
        .filter(|s| s.cpu >= cores && s.memory_mib >= ram_mib)
        .map(|s| Sku {
            name: s.sku.clone(),
            vcpu: s.cpu,
            ram_mib: s.memory_mib,
        })
        .collect();
    fits.sort_by_key(|s| (s.vcpu, s.ram_mib));
    fits
}

/// Render the candidates for `orbyn sku-match`.
pub fn render(provider: Provider, cores: u32, ram_mb: u64, format: Format) -> String {
    let candidates = match_skus(provider, cores, ram_mb);
    match format {
        Format::Json => serde_json::to_string_pretty(&candidates).unwrap_or_else(|_| "[]".into()),
        Format::Csv => {
            let mut out = String::from("provider,name,vcpu,ram_mib\n");
            for s in &candidates {
                out.push_str(&format!(
                    "{},{},{},{}\n",
                    provider.label(),
                    s.name,
                    s.vcpu,
                    s.ram_mib
                ));
            }
            out
        }
        Format::Table => {
            if candidates.is_empty() {
                return format!(
                    "no {} instance type in the curated catalog meets {cores} vCPU \
                     and {ram_mb} MiB RAM\n",
                    provider.label()
                );
            }
            let mut t = crate::output::table(&["Name", "vCPU", "RAM (MiB)"]);
            for s in &candidates {
                t.add_row(vec![
                    comfy_table::Cell::new(&s.name),
                    comfy_table::Cell::new(s.vcpu),
                    comfy_table::Cell::new(s.ram_mib),
                ]);
            }
            format!(
                "{} instance types meeting {cores} vCPU and {ram_mb} MiB RAM \
                 (smallest fit first):\n{}",
                provider.label(),
                crate::output::render_table(t)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smallest_fit_is_first() {
        assert_eq!(match_skus(Provider::Aws, 4, 16384)[0].name, "t3.xlarge");
        assert_eq!(
            match_skus(Provider::Azure, 4, 16384)[0].name,
            "Standard_B4ms"
        );
        assert_eq!(match_skus(Provider::Gcp, 4, 16384)[0].name, "e2-standard-4");
    }

    #[test]
    fn every_candidate_meets_the_requirement() {
        for provider in [Provider::Aws, Provider::Azure, Provider::Gcp] {
            for cores in [1u32, 2, 4, 8, 16] {
                for ram in [2048u64, 8192, 16384, 32768, 65536] {
                    for sku in match_skus(provider, cores, ram) {
                        assert!(sku.vcpu >= cores, "{sku} below {cores} vCPU");
                        assert!(sku.ram_mib >= ram, "{sku} below {ram} MiB");
                    }
                }
            }
        }
    }

    #[test]
    fn no_fit_returns_empty() {
        // Nothing in the curated catalogs reaches 64 vCPU.
        for provider in [Provider::Aws, Provider::Azure, Provider::Gcp] {
            assert!(match_skus(provider, 64, 262_144).is_empty());
        }
    }

    #[test]
    fn catalogs_are_unique_and_non_empty() {
        for provider in [Provider::Aws, Provider::Azure, Provider::Gcp] {
            let catalog = targets::catalog(provider.label()).expect("catalog");
            assert!(!catalog.skus.is_empty(), "{provider:?} catalog is empty");
            let names: Vec<&str> = catalog.skus.iter().map(|s| s.sku.as_str()).collect();
            let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
            assert_eq!(names.len(), unique.len(), "duplicate SKU in {provider:?}");
        }
    }
}
