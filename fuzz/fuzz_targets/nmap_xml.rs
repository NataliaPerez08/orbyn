#![no_main]

use libfuzzer_sys::fuzz_target;
use orbyn::collectors::nmap::NmapCollector;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = NmapCollector::new().parse_xml(&input);
});
