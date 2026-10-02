#![no_main]

use libfuzzer_sys::fuzz_target;
use orbyn::import::{parse_import_csv, ImportedAsset, ImportedInventory};

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = parse_import_csv(&input);
    let _ = serde_json::from_str::<ImportedInventory>(&input);
    let _ = serde_json::from_str::<Vec<ImportedAsset>>(&input);
});
