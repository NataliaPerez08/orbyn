//! Cloud SKU matching (Phase 9 of `docs/ORBYN_AGENT_PLAN.md`).
//!
//! Converts a vendor-neutral right-sizing baseline (vCPU + RAM) into candidate
//! instance types per provider. Kept fully separate from the core right-sizing
//! rules so provider catalogs never leak into the assessment; the CLI takes an
//! explicit baseline (`orbyn sku-match --provider <p> --cores <n> --ram-mb <m>`).
//!
//! Matching is a pure function over curated, static catalogs.
//! `ponytail: on-demand pricing is not embedded — list prices change by region
//! and time and would rot inside the binary; add a live pricing source behind
//! the same `match_skus` shape when a cost comparison is needed.`

use std::fmt;

use crate::output::Format;

/// Version of the curated catalogs; bumped when the catalogs change so
/// plan provenance stays meaningful.
pub const CATALOG_VERSION: &str = "sku-catalog/v1";

/// An instance type in a curated catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Sku {
    pub name: &'static str,
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

/// Providers with a curated instance-type catalog.
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

    /// The curated catalog of instance types.
    pub fn catalog(self) -> &'static [Sku] {
        match self {
            Provider::Aws => AWS,
            Provider::Azure => AZURE,
            Provider::Gcp => GCP,
        }
    }
}

/// Candidate SKUs meeting both the vCPU and RAM requirement, smallest fit
/// first (by vCPU, then RAM).
pub fn match_skus(provider: Provider, cores: u32, ram_mib: u64) -> Vec<&'static Sku> {
    let mut fits: Vec<&'static Sku> = provider
        .catalog()
        .iter()
        .filter(|s| s.vcpu >= cores && s.ram_mib >= ram_mib)
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
            for s in candidates {
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
            for s in candidates {
                t.add_row(vec![
                    comfy_table::Cell::new(s.name),
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

/// AWS EC2 instance types (general purpose t3/m5/m6i, compute c5, memory r5).
const AWS: &[Sku] = &[
    Sku {
        name: "t3.nano",
        vcpu: 2,
        ram_mib: 512,
    },
    Sku {
        name: "t3.micro",
        vcpu: 2,
        ram_mib: 1024,
    },
    Sku {
        name: "t3.small",
        vcpu: 2,
        ram_mib: 2048,
    },
    Sku {
        name: "t3.medium",
        vcpu: 2,
        ram_mib: 4096,
    },
    Sku {
        name: "t3.large",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "t3.xlarge",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "t3.2xlarge",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "m5.large",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "m5.xlarge",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "m5.2xlarge",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "m5.4xlarge",
        vcpu: 16,
        ram_mib: 65536,
    },
    Sku {
        name: "m5.8xlarge",
        vcpu: 32,
        ram_mib: 131072,
    },
    Sku {
        name: "m6i.large",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "m6i.xlarge",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "m6i.2xlarge",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "c5.large",
        vcpu: 2,
        ram_mib: 4096,
    },
    Sku {
        name: "c5.xlarge",
        vcpu: 4,
        ram_mib: 8192,
    },
    Sku {
        name: "c5.2xlarge",
        vcpu: 8,
        ram_mib: 16384,
    },
    Sku {
        name: "c5.4xlarge",
        vcpu: 16,
        ram_mib: 32768,
    },
    Sku {
        name: "r5.large",
        vcpu: 2,
        ram_mib: 16384,
    },
    Sku {
        name: "r5.xlarge",
        vcpu: 4,
        ram_mib: 32768,
    },
    Sku {
        name: "r5.2xlarge",
        vcpu: 8,
        ram_mib: 65536,
    },
    Sku {
        name: "r5.4xlarge",
        vcpu: 16,
        ram_mib: 131072,
    },
];

/// Azure VM sizes (general purpose B/D, memory E, compute F).
const AZURE: &[Sku] = &[
    Sku {
        name: "Standard_B2s",
        vcpu: 2,
        ram_mib: 4096,
    },
    Sku {
        name: "Standard_B2ms",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "Standard_B4ms",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "Standard_B8ms",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "Standard_D2s_v3",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "Standard_D4s_v3",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "Standard_D8s_v3",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "Standard_D16s_v3",
        vcpu: 16,
        ram_mib: 65536,
    },
    Sku {
        name: "Standard_D2ds_v5",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "Standard_D4ds_v5",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "Standard_D8ds_v5",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "Standard_E2s_v3",
        vcpu: 2,
        ram_mib: 16384,
    },
    Sku {
        name: "Standard_E4s_v3",
        vcpu: 4,
        ram_mib: 32768,
    },
    Sku {
        name: "Standard_E8s_v3",
        vcpu: 8,
        ram_mib: 65536,
    },
    Sku {
        name: "Standard_E16s_v3",
        vcpu: 16,
        ram_mib: 131072,
    },
    Sku {
        name: "Standard_F2s_v2",
        vcpu: 2,
        ram_mib: 4096,
    },
    Sku {
        name: "Standard_F4s_v2",
        vcpu: 4,
        ram_mib: 8192,
    },
    Sku {
        name: "Standard_F8s_v2",
        vcpu: 8,
        ram_mib: 16384,
    },
    Sku {
        name: "Standard_F16s_v2",
        vcpu: 16,
        ram_mib: 32768,
    },
];

/// GCP machine types (general purpose n1/e2/n2, compute c2, memory n2-highmem).
const GCP: &[Sku] = &[
    Sku {
        name: "n1-standard-1",
        vcpu: 1,
        ram_mib: 3840,
    },
    Sku {
        name: "n1-standard-2",
        vcpu: 2,
        ram_mib: 7680,
    },
    Sku {
        name: "n1-standard-4",
        vcpu: 4,
        ram_mib: 15360,
    },
    Sku {
        name: "n1-standard-8",
        vcpu: 8,
        ram_mib: 30720,
    },
    Sku {
        name: "n1-standard-16",
        vcpu: 16,
        ram_mib: 61440,
    },
    Sku {
        name: "e2-standard-2",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "e2-standard-4",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "e2-standard-8",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "e2-standard-16",
        vcpu: 16,
        ram_mib: 65536,
    },
    Sku {
        name: "n2-standard-2",
        vcpu: 2,
        ram_mib: 8192,
    },
    Sku {
        name: "n2-standard-4",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "n2-standard-8",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "n2-standard-16",
        vcpu: 16,
        ram_mib: 65536,
    },
    Sku {
        name: "c2-standard-4",
        vcpu: 4,
        ram_mib: 16384,
    },
    Sku {
        name: "c2-standard-8",
        vcpu: 8,
        ram_mib: 32768,
    },
    Sku {
        name: "n2-highmem-2",
        vcpu: 2,
        ram_mib: 16384,
    },
    Sku {
        name: "n2-highmem-4",
        vcpu: 4,
        ram_mib: 32768,
    },
    Sku {
        name: "n2-highmem-8",
        vcpu: 8,
        ram_mib: 65536,
    },
];

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
            let catalog = provider.catalog();
            assert!(!catalog.is_empty(), "{provider:?} catalog is empty");
            let names: Vec<&str> = catalog.iter().map(|s| s.name).collect();
            let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
            assert_eq!(names.len(), unique.len(), "duplicate SKU in {provider:?}");
        }
    }
}
