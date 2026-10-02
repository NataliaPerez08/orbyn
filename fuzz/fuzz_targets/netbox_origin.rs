#![no_main]

use libfuzzer_sys::fuzz_target;
use orbyn::integrations::netbox::url_origin;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    if let Some(origin) = url_origin(&input) {
        assert!(!origin.scheme.is_empty());
        assert!(!origin.host.is_empty());
        // The SSRF guard on pagination `next` URLs: userinfo must never be
        // accepted, or `https://netbox.example.com@evil/` would send the
        // token to `evil`.
        let authority = input
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?', '#']).next());
        if let Some(auth) = authority {
            assert!(!auth.contains('@'), "userinfo accepted: {input:?}");
        }
    }
});
