# Orbyn Installation

This guide installs a released Orbyn binary without Rust or Cargo. Orbyn uses a
local SQLite database and does not require a server.

## Requirements

The binary itself does not require external services. Install the tools needed
by the collectors you plan to use:

| Capability | Required tool |
| --- | --- |
| Nmap discovery | `nmap` |
| SNMP discovery | `snmpwalk` from net-snmp |
| Linux or Windows host discovery (SSH) | OpenSSH client (`ssh`) |
| Windows host discovery (native WinRM) | `curl` |
| NetBox import | `curl` |
| Prometheus utilization import | `curl` |
| Zabbix utilization import | `curl` |
| Proxmox VE import | `curl` |
| AWS import | `curl` |
| Huawei Cloud import | `curl` |
| DNS relationship evidence (CNAME chains, PTR) | `dig` (optional; without it only forward IP matching via the system resolver) |

SSH host discovery uses key-based authentication through `ssh-agent` or an
identity file. Native WinRM discovery uses Basic authentication over HTTPS
(password from `ORBYN_WINRM_PASSWORD` or stdin, held in memory only). Orbyn
does not store passwords or private key contents.

## Linux

1. Download the `x86_64-unknown-linux-gnu` archive from the [GitHub releases]
   page.
2. Verify its checksum:

   ```bash
   sha256sum -c orbyn-<version>-x86_64-unknown-linux-gnu.tar.gz.sha256
   ```

3. Install the binary:

   ```bash
   tar -xzf orbyn-<version>-x86_64-unknown-linux-gnu.tar.gz
   sudo install -m 0755 orbyn-<version>-x86_64-unknown-linux-gnu /usr/local/bin/orbyn
   ```

4. Verify the installation:

   ```bash
   orbyn --version
   orbyn --help
   ```

Install `nmap`, `snmpwalk`, OpenSSH and `curl` with the package manager for
your distribution when needed.

## Windows

1. Download `orbyn-<version>-x86_64-pc-windows-msvc.exe.zip` and its checksum
   from the releases page.
2. Verify the checksum in PowerShell:

   ```powershell
   (Get-FileHash .\orbyn-<version>-x86_64-pc-windows-msvc.exe.zip -Algorithm SHA256).Hash
   ```

   Compare the printed value with the `.sha256` file.

3. Extract `orbyn.exe` into a directory on `PATH`, for example
   `C:\Program Files\Orbyn\`.
4. Open a new PowerShell session and verify:

   ```powershell
   orbyn.exe --version
   orbyn.exe --help
   ```

Windows host discovery requires either the OpenSSH Server feature on the
target host (PowerShell 3 or newer) or a WinRM HTTPS listener with Basic
authentication enabled (the native WinRM transport, port 5986 by default).

## Database and configuration

By default Orbyn creates and migrates its database at:

```text
./data/orbyn.db
```

The file is created with owner-only permissions (`0600`; the parent directory
is `0700` when Orbyn creates it). Use `--db <path>` or `ORBYN_DB` to select
another database. Configuration variables are documented in the
[README configuration section].

### PostgreSQL

Any `--db`/`ORBYN_DB` value starting with `postgres://` or `postgresql://`
selects the PostgreSQL backend; the schema is applied automatically on open:

```bash
orbyn --db "postgres://orbyn@db.example.com:5432/orbyn?sslmode=require" assets
```

Keep the password out of the process arguments: omit it from the URL and set
`ORBYN_PG_PASSWORD` (or the standard `PGPASSWORD`) instead. A URL that embeds
a password prints a warning, since argv is readable by any local user. TLS is
negotiated when the server offers it; use `?sslmode=require` for remote
databases.

Keep the database and exported inventory files private. They can contain
sensitive infrastructure information.

## Shell completions

Generate completions after installation:

```bash
orbyn completions bash > ~/.local/share/bash-completion/completions/orbyn
orbyn completions fish > ~/.config/fish/completions/orbyn.fish
```

For zsh, create the completion directory first:

```bash
mkdir -p "$HOME/.zsh/completions"
orbyn completions zsh > "$HOME/.zsh/completions/_orbyn"
```

For a one-off session, source a generated script according to your shell's
completion configuration.

## Upgrade

1. Back up the database before replacing the binary:

   ```bash
   cp ./data/orbyn.db ./data/orbyn.db.backup-$(date +%Y%m%d%H%M%S)
   ```

2. Replace the binary with the new release.
3. Run a harmless command pointing at the existing database:

   ```bash
   orbyn --db ./data/orbyn.db assets
   ```

Opening the database runs all pending embedded SQLite migrations automatically.
No separate migration executable or manual SQL step is required. If startup
fails during migration, keep the backup, restore the previous binary, and
report the error with the database schema version and Orbyn version. Never edit
the migration tracking table manually.

## Uninstall

Remove the binary from the installation directory. The database is separate;
remove `./data/orbyn.db` only when the inventory is no longer needed.

## Build from source

For development or platforms without a release artifact:

```bash
git clone https://github.com/NataliaPerez08/orbyn.git
cd orbyn
cargo build --release --locked
install -m 0755 target/release/orbyn ~/.local/bin/orbyn
```

Run the verification suite before installing a locally built binary:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

[GitHub releases]: https://github.com/NataliaPerez08/orbyn/releases
[README configuration section]: configuration.md
