#![no_main]

use libfuzzer_sys::fuzz_target;
use orbyn::collectors::validate_target;
use orbyn::parsing::{normalize_ip, parse_addr_port, split_csv_line, split_sections};

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = split_csv_line(&input);
    let _ = split_sections(&input);
    let _ = normalize_ip(&input);
    let _ = parse_addr_port(&input);
    let _ = validate_target(&input);
});
