# Orbyn — Release Verification Plan

> **Historical document — completed.** The target `v1.0.3` patch release
> shipped, and the follow-up work shipped as `v1.0.4`. It is kept as a record
> and does not describe current project state. Current direction:
> [ROADMAP.md](ROADMAP.md). Release history: `RELEASE_NOTES_v1.0.*.md`.
> Known issues: [KnowIssues.md](KnowIssues.md).

> **Target:** `v1.0.3` patch release
> **License:** Apache-2.0  
> **Status:** completed — shipped as v1.0.3, follow-up as v1.0.4
> **Primary goal:** Ship the minimum compliance and packaging fixes for the next patch release without expanding product scope.

---

## 1. Mission

The existing public release is `v1.0.2`. This plan tracks the `v1.0.3`
patch release and does not rewrite or move the existing tag.

This is primarily a **stabilization, compliance, documentation, testing, and packaging task**.

Do **not** introduce major new functionality unless it is required to make an existing documented feature work correctly.

The release should demonstrate the following complete workflow:

```text
Target
  ↓
Collector
  ↓
Discovery
  ↓
Normalization
  ↓
Persistence
  ↓
Query / Export
```

A successful release allows a new user to clone or download Orbyn, install its documented external prerequisites, run discovery against an authorized test network, persist the results, and inspect them without modifying the source code.

---

# 2. Agent Operating Rules

Before modifying code:

1. Read:
   - `README.md`
   - `ARCHITECTURE.md`
   - `INSTALL.md`
   - `CONTRIBUTING.md`
   - `SECURITY.md`
   - `THREAT_MODEL.md`
   - `Cargo.toml`
   - `Cargo.lock`
   - existing GitHub Actions workflows

2. Inspect:
   - `src/collectors/`
   - CLI entry points
   - persistence/database layer
   - export functionality
   - migrations
   - tests and fixtures

3. Run the existing test/build pipeline before making changes.

4. Record existing failures separately from failures introduced by the work.

5. Prefer small, reviewable changes.

6. Do not redesign working subsystems merely for style.

7. Do not silently change public CLI behavior.

8. Do not add network scanning techniques beyond the project's existing documented behavior.

9. Do not bundle external discovery tools into Orbyn.

10. Do not remove existing security controls to make tests pass.

---

# 3. Scope Freeze

The following are **in scope** for this release:

- existing collectors
- Nmap integration
- normalization
- SQLite persistence
- CLI usability
- export functionality already present
- error handling
- logging
- configuration
- tests
- documentation
- dependency/license compliance
- CI
- release packaging

The following are **out of scope** unless already implemented and merely broken:

- web UI
- MongoDB migration
- GraphQL
- cloud collectors
- agent-based telemetry
- CPU/RAM utilization discovery
- new SNMP functionality
- new SSH discovery functionality
- advanced migration recommendations
- replacement of Nmap with a native scanner
- major database redesign
- distributed scanning
- authentication systems
- SaaS functionality

If an out-of-scope issue is discovered, document it in the backlog rather than implementing it.

---

# 4. Phase 0 — Establish Baseline

## Tasks

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

Record:

- compiler version
- Cargo version
- OS
- architecture
- failing tests
- compiler warnings
- Clippy warnings

Inspect repository state for:

- generated files
- accidentally committed build artifacts
- credentials
- API keys
- passwords
- private keys
- `.env` files
- database files
- packet captures
- test credentials that could be mistaken for real credentials
- local paths containing developer information

### Acceptance criteria

- [ ] Baseline build status recorded.
- [ ] Baseline test status recorded.
- [ ] No real credentials or secrets are committed.
- [ ] `.gitignore` covers local/runtime artifacts.
- [ ] Existing failures are documented before modifications begin.

---

# 5. Phase 1 — Versioning

Inspect `Cargo.toml`.

The next release candidate's canonical version is `1.0.3`; `v1.0.2` remains
the existing published tag.

The release candidate uses:

```toml
version = "1.0.3"
```

Update references throughout the repository so documentation, CLI version output, Cargo metadata, release workflow, and release notes agree.

Do not rewrite or move the existing `v1.0.2` tag. Future fixes should use a
new patch version and tag.

### Acceptance criteria

- [ ] One canonical release version exists.
- [ ] `Cargo.toml` matches it.
- [ ] CLI version output matches it.
- [ ] Documentation does not contradict it.
- [ ] Release workflow uses the same versioning scheme.

---

# 6. Phase 2 — Dependency and License Compliance

Orbyn source code is intended to remain:

```text
Apache-2.0
```

Do not change the project license without explicit maintainer approval.

## Rust dependencies

Install/configure `cargo-deny`.

Create:

```text
deny.toml
```

Configure license policy using SPDX identifiers.

At minimum, explicitly review dependencies using:

```bash
cargo deny check licenses
cargo deny check sources
```

Do not blindly allow an unknown license merely to make CI green.

For every exception:

- identify the dependency
- identify why it exists
- identify its license
- document why it is acceptable

Also run:

```bash
cargo audit
```

Keep vulnerability auditing separate from license auditing.

### Acceptance criteria

- [x] `cargo deny check licenses` passes.
- [x] `cargo deny check sources` passes.
- [x] Dependency license policy is committed.
- [x] Any license exception is documented.
- [x] No dependency with an unidentified license is silently accepted.

---

# 7. Phase 3 — Third-Party Software Boundary

Orbyn invokes external software.

The release must clearly distinguish between:

```text
software incorporated into Orbyn
```

and:

```text
software invoked externally by Orbyn
```

Pay particular attention to:

- Nmap
- Net-SNMP / `snmpwalk`
- OpenSSH / `ssh`

## Nmap

Nmap must remain an **external dependency**.

Orbyn may execute the independently installed `nmap` binary.

Do NOT add to release artifacts:

- Nmap binaries
- `nmap.exe`
- Npcap
- Nmap source
- Nmap NSE scripts
- `nmap-service-probes`
- `nmap-os-db`
- other Nmap data files copied from an Nmap installation

Do not download Nmap automatically as part of the Orbyn build.

Document the external dependency and direct users to install Nmap separately.

## Net-SNMP and OpenSSH

Apply the same architectural principle.

Do not bundle these programs unless a future release explicitly performs a separate redistribution/license review.

### Acceptance criteria

- [ ] No Nmap binaries/data are distributed with Orbyn.
- [ ] No Npcap binaries are distributed.
- [ ] No OpenSSH binaries are distributed.
- [ ] No Net-SNMP binaries are distributed.
- [x] Documentation clearly calls them external dependencies.
- [x] Missing external binaries produce understandable errors.

---

# 8. Phase 4 — Third-Party Notices

Create:

```text
THIRD_PARTY_NOTICES.md
```

Separate two concepts.

## Incorporated dependencies

Document that Orbyn uses third-party Rust crates under their respective licenses.

Prefer generating dependency/license information from Cargo metadata instead of maintaining a fragile manual list.

## External tools

Document optional/required external integrations separately.

Example structure:

```markdown
## External Software

Orbyn can invoke independently installed third-party software.

### Nmap

Project: https://nmap.org/

Nmap is not included with Orbyn.

Users must obtain and install Nmap separately and comply with
Nmap's applicable license terms.

### Net-SNMP

Net-SNMP is not included with Orbyn.

### OpenSSH

OpenSSH is not included with Orbyn.
```

Do not imply that Apache-2.0 applies to these external programs.

### Acceptance criteria

- [x] `THIRD_PARTY_NOTICES.md` exists.
- [x] Incorporated dependencies and external tools are distinguished.
- [x] Nmap is explicitly identified as external.
- [x] Project license claims only cover Orbyn code where applicable.

---

# 9. Phase 5 — Collector Boundary Review

Review:

```text
src/collectors/
```

The collector abstraction should prevent the rest of Orbyn from depending directly on a specific discovery implementation.

Verify that:

```text
Application
    ↓
Collector interface
    ↓
NmapCollector / SSH / SNMP / ...
```

remains the architecture.

Do not move Nmap-specific behavior into domain or persistence layers.

## Nmap

Verify that the Nmap collector:

- constructs commands safely
- does not invoke through an unnecessary shell
- validates targets
- captures stdout
- captures stderr
- checks process exit status
- handles missing executable
- handles timeout/failure
- handles malformed XML
- handles empty results
- produces normalized Orbyn data
- does not panic on unexpected Nmap output

Document the exact command/arguments currently used.

Do not add aggressive scanning flags as part of this release preparation.

### Acceptance criteria

- [ ] Nmap remains isolated behind the collector layer.
- [ ] No shell interpolation vulnerability exists.
- [ ] Invalid XML returns an error rather than a panic.
- [ ] Missing Nmap produces actionable output.
- [ ] Failed Nmap process produces actionable output.
- [ ] Tests exist for representative XML fixtures.

---

# 10. Phase 6 — Persistence Integrity

Review SQLite persistence and migrations.

Verify:

- database creation
- schema initialization
- migrations
- duplicate discovery behavior
- updates to existing hosts
- foreign-key behavior
- transaction boundaries
- timestamps
- malformed/partial discovery data
- database error propagation

Run discovery repeatedly against the same fixtures and verify the database remains internally consistent.

### Acceptance criteria

- [ ] Fresh database initializes correctly.
- [ ] Existing database opens correctly.
- [ ] Discovery can be persisted.
- [ ] Repeated discovery does not corrupt state.
- [ ] Foreign-key constraints remain valid.
- [ ] Persistence errors are surfaced to the CLI.

---

# 11. Phase 7 — End-to-End Release Path

Create or verify an integration test representing:

```text
Nmap XML fixture
      ↓
Nmap parser
      ↓
normalized model
      ↓
SQLite
      ↓
query
      ↓
expected inventory
```

The integration test must not require scanning the public internet.

Prefer deterministic fixtures.

Network-dependent tests should be clearly separated and should not run by default in CI.

### Acceptance criteria

- [ ] Deterministic end-to-end test exists.
- [ ] CI does not depend on an accessible network target.
- [ ] Test proves discovered hosts reach persistence.
- [ ] Stored results can be retrieved correctly.

---

# 12. Phase 8 — CLI UX

Test the CLI as a new user.

For every public command verify:

```bash
orbyn --help
orbyn <command> --help
```

Review:

- command names
- descriptions
- required arguments
- invalid arguments
- exit codes
- human-readable errors
- machine-readable output if supported
- version output

Avoid exposing Rust implementation details in normal error messages.

Bad:

```text
thread 'main' panicked at src/foo.rs:183
```

Good:

```text
Nmap was not found.

Install Nmap and ensure `nmap` is available in PATH.
```

### Acceptance criteria

- [ ] `--help` works.
- [ ] `--version` works.
- [ ] Invalid target returns non-zero.
- [ ] Missing dependency returns non-zero.
- [ ] Errors identify corrective action where possible.
- [ ] Normal user errors do not generate Rust panics.

---

# 13. Phase 9 — Security Review

Re-read:

```text
SECURITY.md
THREAT_MODEL.md
```

and verify that implementation still matches documentation.

Inspect especially:

- command execution
- target validation
- credential handling
- environment variables
- SSH execution
- SNMP credentials
- database paths
- filesystem writes
- logging

Credentials must never appear in normal logs.

Ensure test fixtures use obviously fake credentials.

### Acceptance criteria

- [ ] No shell command injection identified.
- [ ] Secrets are not logged.
- [ ] No hardcoded real credentials exist.
- [ ] Security documentation reflects implementation.
- [ ] Supported security-reporting mechanism is documented.

---

# 14. Phase 10 — README / Installation

The README should support someone who has never seen the codebase.

Minimum structure:

```text
What is Orbyn?
What does it currently do?
Installation
External prerequisites
Quick start
First discovery
Inspecting results
Exporting results
Architecture overview
Security / authorization warning
Known limitations
Contributing
License
Third-party software
```

`INSTALL.md` must contain actual commands required for supported platforms.

Clearly state that users should scan only networks/systems they are authorized to assess.

Do not describe roadmap features as currently available.

### Acceptance criteria

A new technical user should be able to go from:

```text
repository
```

to:

```text
successful local discovery
```

using only repository documentation.

---

# 15. Phase 11 — CI

CI should run at minimum:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
cargo audit
cargo deny check licenses
cargo deny check sources
```

Separate jobs when useful so failures clearly identify the responsible subsystem.

Do not hide failures using:

```yaml
continue-on-error: true
```

unless explicitly justified and documented.

### Acceptance criteria

- [x] Formatting is enforced.
- [x] Clippy is enforced.
- [x] Tests are enforced.
- [x] Release build is tested.
- [x] Vulnerability auditing runs.
- [x] License auditing runs.
- [x] Source auditing runs.

---

# 16. Phase 12 — Release Artifact Inspection

Before publishing, inspect the actual generated artifact.

It should contain only files intentionally distributed.

Verify that it does NOT accidentally contain:

```text
.env
target/
*.db
*.sqlite
credentials
private keys
developer configuration
IDE metadata
Nmap binaries
Npcap
SSH binaries
snmpwalk
packet captures
debug logs
test output
```

Verify license/documentation files are included where appropriate.

### Acceptance criteria

- [ ] Artifact contents manually inspected.
- [ ] No secrets included.
- [ ] No external executable bundled accidentally.
- [ ] Correct Orbyn license included.
- [ ] Version is correct.

The `v1.0.2` published assets could not be retrieved in the current
environment. The release workflow now packages and inspects the binary,
`LICENSE`, and `THIRD_PARTY_NOTICES.md` before upload for future releases.

---

# 17. Phase 13 — Release Notes

Create release notes containing:

## Orbyn vX.Y.Z

### Current capabilities

Only list functionality demonstrated by tests or manual verification.

### External requirements

Explicitly identify dependencies such as Nmap where applicable.

### Known limitations

Be specific.

Do not disguise missing functionality as working functionality.

### Security

State that discovery must only be performed against authorized systems.

### License

State that Orbyn itself is released under Apache-2.0 and that external software retains its respective licensing terms.

---

# 18. Final Release Gate

The release is **NOT READY** if any of these are true:

- [ ] `cargo build --release` fails.
- [ ] tests fail.
- [ ] Clippy fails.
- [ ] formatting check fails.
- [ ] license check fails.
- [ ] unidentified dependency licenses exist.
- [ ] secrets exist in repository history/current artifact requiring remediation.
- [ ] Nmap/Npcap is accidentally bundled.
- [ ] CLI panics during expected user errors.
- [ ] README installation path does not work.
- [ ] release version is inconsistent.
- [ ] release artifact contains unintended files.

The release is considered ready when all blocking items are resolved.

---

# 19. Definition of Done

A clean environment should be able to perform approximately this lifecycle:

```text
Install Orbyn
      ↓
Install documented external prerequisites
      ↓
orbyn --help
      ↓
initialize/use local database
      ↓
run authorized discovery
      ↓
collector executes
      ↓
results normalize
      ↓
results persist
      ↓
user queries/exports inventory
```

without:

- modifying source code
- manually editing the database
- undocumented setup
- panic/crash
- bundled proprietary/external tools
- license ambiguity

---

# 20. Required Agent Report

When all work is complete, do **not** simply report "done".

Produce:

```markdown
# Pre-Release Report

## Release candidate
Version:

## Build
PASS / FAIL

## Tests
X passed
X failed
X ignored

## Clippy
PASS / FAIL

## Formatting
PASS / FAIL

## License audit
PASS / FAIL

## Security audit
PASS / FAIL

## External dependencies
- Nmap:
- OpenSSH:
- Net-SNMP:

## Files added
...

## Files modified
...

## Important fixes
...

## Known limitations
...

## Deferred work
...

## Blocking issues
...

## Release recommendation
READY / NOT READY
```

`READY` may only be reported when every release gate above passes.

If something cannot be verified in the agent's environment, report:

```text
NOT VERIFIED
```

rather than assuming it works.

---

# 21. Priority Order

If time is limited, execute in this order:

**P0 — Release blockers**

```text
build
tests
secrets
license compliance
external software boundary
Nmap execution safety
persistence integrity
```

**P1 — Release quality**

```text
CI
README
INSTALL
error messages
integration tests
release artifacts
```

**P2 — Polish**

```text
additional documentation
developer ergonomics
non-critical refactoring
minor CLI UX improvements
```

Do not work on P2 while a P0 issue remains unresolved.

---

## Core principle

The purpose of this work is not to make Orbyn feature-complete.

The purpose is to make the **existing functionality trustworthy enough to publish**.

Prefer:

```text
small + tested + documented + legally clear
```

over:

```text
more features + uncertain behavior
```
