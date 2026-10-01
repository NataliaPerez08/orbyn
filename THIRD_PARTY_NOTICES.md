# Third-Party Notices

Orbyn is released under the Apache License 2.0. This license applies to Orbyn
source code and does not change the license of software that Orbyn invokes or
of dependencies distributed with the binary.

## Incorporated Rust Dependencies

Orbyn is built using third-party Rust crates. Their licenses are declared in
their package metadata and are checked against the repository policy in
`deny.toml` with `cargo deny`. The accepted SPDX identifiers are listed there;
the crates retain their respective copyright and license notices.

## External Software

The following tools are used only when independently installed by the
operator. They are not bundled in Orbyn release artifacts.

### Nmap

Project: <https://nmap.org/>

Orbyn can invoke the independently installed `nmap` executable for network
discovery. Users must obtain Nmap separately and comply with its applicable
license terms.

### Net-SNMP

Orbyn can invoke `snmpwalk` from an independently installed Net-SNMP package.
Net-SNMP is not included with Orbyn.

### OpenSSH

Orbyn can invoke an independently installed OpenSSH client for host discovery.
OpenSSH is not included with Orbyn.

### curl and dig

Orbyn can invoke independently installed `curl` and, optionally, `dig` for
HTTP integrations and DNS evidence. Neither tool is included with Orbyn.

## Reporting

License or attribution questions should be reported through the security and
maintenance channels documented in [`docs/SECURITY.md`](docs/SECURITY.md).
