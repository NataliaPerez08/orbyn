//! Handler for right-sizing SKU matching.

use orbyn::output::Format;
use orbyn::sku::Provider;

pub(crate) fn sku_match(provider: Provider, cores: u32, ram_mb: u64, format: Format) {
    print!("{}", orbyn::sku::render(provider, cores, ram_mb, format));
}
