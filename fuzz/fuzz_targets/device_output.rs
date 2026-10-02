#![no_main]

use libfuzzer_sys::fuzz_target;
use orbyn::collectors::snmp::{SnmpCollector, SnmpVersion};
use orbyn::collectors::ssh::parse_linux_probe;
use orbyn::collectors::winrm::{
    parse_command_id, parse_receive_response, parse_shell_id, parse_soap_fault,
};

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let _ = parse_linux_probe(&input);
    let _ = SnmpCollector::new("public", SnmpVersion::V2c, 161).parse_walk(&input);
    let _ = parse_shell_id(&input);
    let _ = parse_command_id(&input);
    let _ = parse_receive_response(&input);
    let _ = parse_soap_fault(&input);
});
