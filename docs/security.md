# Security

Infrastructure discovery is security-sensitive. This page summarizes the
guarantees Orbyn makes; the full design rules live in
[SECURITY.md](SECURITY.md) and the threat model in the repository.

!!! danger "Authorized use only"
    You are responsible for ensuring you have authorization to scan and
    inspect target infrastructure. Orbyn rejects accidental unrestricted
    scans by default — that is a guard rail, not permission.

## What Orbyn does

* Requires explicit discovery targets.
* Rejects accidental unrestricted scans by default (IPv4 `/16`, IPv6 `/48`
  floors; `/0` always rejected) — see
  [target validation](collectors/framework.md#target-validation).
* Uses read-only operations whenever possible.
* Never exposes credentials in logs; secrets are redacted before any error is
  persisted or printed.
* Avoids storing credentials unless absolutely necessary — today it stores
  none.
* Runs collectors with minimum privileges and least access.
* Maintains an audit trail for discovery operations (`orbyn jobs`,
  `orbyn audit`).
* Clearly identifies which collector produced each observation.

## Read-only by default

Collectors must not modify the systems they inspect. Targets are passed as
process **argument vectors, never shell strings**, and the SSH probe is a
fixed constant — only the host address comes from input. The WinRM shell is
deleted best-effort even when a command fails.

Nmap is invoked as `-oX - -sV --no-stylesheet`: no OS detection, no NSE
scripts, no destructive scan types. SNMP walks metadata-only subtrees. The
Linux and Windows probes issue only read commands (`df`, `ss`, `systemctl`,
`Get-CimInstance`, `Get-Service`).

## Credentials

* **Orbyn does not store credentials.** A credential profile carries a
  username, a port and an *identity file path* — never secret material. The
  key itself is never read, copied or logged.
* **SSH password authentication is intentionally unsupported.** Use an
  ssh-agent or a key file. Passing passwords through subprocess arguments or
  storing them would violate these rules.
* **The one exception is WinRM** (Basic auth over HTTPS): the password comes
  from `ORBYN_WINRM_PASSWORD` or `--winrm-password -` (stdin), is held in
  process memory for the run only, and is streamed to `curl` as a config line
  on stdin (`-K -`) — never in argv, in a file, or in curl's environment.
* **All other secrets** (community strings, API tokens, cloud keys) accept a
  `-` flag value that reads one line from stdin.

### Environment scrubbing

Before spawning `nmap`, `snmpwalk`, `ssh` or `curl`, Orbyn removes
`ORBYN_SNMP_COMMUNITY`, `ORBYN_NETBOX_TOKEN`, `ORBYN_WINRM_PASSWORD`,
`ORBYN_PROMETHEUS_TOKEN` and `ORBYN_DB` from the child's environment — a
hijacked binary must not be able to read the community string, an API token,
the WinRM password or the database URL password.

The SNMP community is written to a temporary `snmp.conf` with mode `0600`
inside a `0700` directory, referenced through `SNMPCONFPATH`, and deleted
after the walk. Stale directories are cleaned on each run.

## Boundaries

| Boundary | Enforcement |
| --- | --- |
| Scan scope | `validate_target` floors, `--allow-large-cidr` opt-in, `/0` always rejected |
| Shell injection | argument vectors only; no `sh -c`, no string interpolation |
| Output size | 16 MiB stdout / 1 MiB stderr per subprocess; 64 MiB per inventory import |
| Network calls | 60 s timeouts, 3 retries on transient failures only |
| Secrets | stdin or env, redacted in errors, scrubbed from children, never persisted |
| Audit | discovery jobs and mutating commands recorded (`orbyn jobs`, `orbyn audit`) |

## TLS verification

`--no-verify` (importers) and `--winrm-insecure` (WinRM collector) disable
certificate verification and print a `WARNING:`. Use them only for lab
certificates you control.

## Reporting a vulnerability

Report security issues through the channels documented in
[SECURITY.md](SECURITY.md#reporting-a-vulnerability). Please do not open a
public issue for exploitable vulnerabilities.
