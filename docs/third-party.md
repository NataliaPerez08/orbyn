# Third-party notices

!!! disclaimer "Not affiliated"
    Orbyn is an independent open-source project. References to third-party
    products, services, projects, logos and trademarks are made for
    identification purposes only and imply no affiliation, endorsement or
    sponsorship by, or with, their respective owners.

## Orbyn's own license

Orbyn is released under the **Apache License 2.0**. That license applies to
Orbyn's source code and binary — it does **not** change the license of
software Orbyn invokes, nor the license of dependencies distributed with the
binary.

Copyright © 2026 Orbyn contributors.

## External tools Orbyn can invoke

These tools are used only when **independently installed by the operator**.
They are **not bundled** in Orbyn release artifacts and are not redistributed
by this project. Users must obtain them separately and comply with their
applicable license terms.

| Tool | Project | Used by |
| --- | --- | --- |
| [Nmap](https://nmap.org/) | Nmap Project | [Nmap collector](collectors/nmap.md) (`-oX - -sV`) |
| [Net-SNMP](https://net-snmp.org/) — `snmpwalk` | Net-SNMP project | [SNMP collector](collectors/snmp.md) |
| [OpenSSH](https://www.openssh.com/) — `ssh` | OpenBSD project | [SSH](collectors/ssh.md) and [Windows](collectors/windows.md) collectors |
| [curl](https://curl.se/) | curl project | [WinRM collector](collectors/winrm.md) and all [API importers](importers/index.md) |
| [BIND](https://www.isc.org/bind/) — `dig` *(optional)* | ISC | [DNS evidence](collectors/dns.md) |

Missing an optional tool degrades functionality instead of failing the run —
without `dig`, for example, only forward IP matching via the system resolver
remains available.

## External services and platforms Orbyn can query

Orbyn is **read-only** against every service below: it never creates,
modifies or deletes objects, never writes metrics or triggers, and never
stores the credentials you supply. Your use of each service is governed by
**its own terms of service, acceptable-use policy and pricing** — Orbyn does
not provide them and does not modify them.

| Service | How Orbyn connects | Credentials you supply |
| --- | --- | --- |
| [NetBox](https://netbox.dev/) | REST API over HTTPS | API token |
| [Prometheus](https://prometheus.io/) | HTTP API (`/api/v1/query_range`) | Bearer token |
| [Zabbix](https://www.zabbix.com/) | JSON-RPC API | API token |
| [Proxmox VE](https://www.proxmox.com/) | REST API over HTTPS | API token |
| [Amazon Web Services](https://aws.amazon.com/) | EC2 query API, SigV4 (no SDK) | Access key, secret key, session token |
| [Microsoft Azure](https://azure.microsoft.com/) | Azure Resource Manager | Azure AD bearer token, subscription id |
| [Google Cloud](https://cloud.google.com/) | Compute Engine API | OAuth bearer token, project id |
| [OpenStack](https://www.openstack.org/) | Nova / Keystone | Scoped Keystone token |
| [Huawei Cloud](https://huaweicloud.com/) | ECS/EVS/VPC APIs, `SDK-HMAC-SHA256` (no SDK) | Access key (AK), secret key (SK) |

Each platform, logo and product name is the property of its respective
owner. See [Importers](importers/index.md) for flags and limits, and
[Configuration](configuration.md) for the environment variables each one
reads.

## Incorporated Rust dependencies

Orbyn is built with third-party Rust crates. Their licenses are declared in
their package metadata and checked against the repository policy in
`deny.toml` with [`cargo deny`](https://embarkstudios.github.io/cargo-deny/).
Accepted SPDX identifiers:

```text
Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause,
BSL-1.0, CDLA-Permissive-2.0, ISC, LGPL-2.1-or-later, MIT, Unicode-3.0,
Unlicense, Zlib
```

Unknown licenses and unknown registry or git sources fail CI. The crates
retain their respective copyright and license notices; run `cargo deny
licenses` to list them for your build.

## Fonts and site theme

This documentation site is built with [MkDocs](https://www.mkdocs.org/) and
the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)
theme, used under their respective licenses. Typefaces referenced by the
theme are loaded from the theme's own assets and are subject to their own
licenses.

## Reporting

License or attribution questions should be reported through the security and
maintenance channels documented in [SECURITY.md](SECURITY.md#reporting-a-vulnerability).
