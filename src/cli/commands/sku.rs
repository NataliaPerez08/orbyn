//! Handler for right-sizing SKU matching.

use anyhow::{anyhow, Result};

use orbyn::output::Format;

pub(crate) fn sku_match(provider: String, cores: u32, ram_mb: u64, format: Format) -> Result<()> {
    if orbyn::targets::catalog(&provider).is_none() {
        let loaded: Vec<&str> = orbyn::targets::catalogs()
            .iter()
            .map(|c| c.provider.as_str())
            .collect();
        return Err(anyhow!(
            "no catalog for provider '{provider}' (loaded: {})",
            loaded.join(", ")
        ));
    }
    print!("{}", orbyn::sku::render(&provider, cores, ram_mb, format));
    Ok(())
}
