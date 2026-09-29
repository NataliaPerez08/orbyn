# Plan de resolución de Known Issues

Plan de trabajo para resolver los issues registrados en `KnowIssues.md`.
Se agrupan por fases y cada item incluye el enfoque propuesto.

**Sincronizado con el estado actual de `KnowIssues.md`.** Ya resueltos y por
tanto fuera de este plan: **#1, #2, #4, #5, #6 (community SNMP), #6 (orden de
dependencias), #7, #8, #9, #10, #11, #12, #13, #14, #15, #16, #19, #20, #21,
#23, #24, #25, #26, #27, #28, #29, #30, #31, #32, #33, #34, #35, #36, #37,
#38 y #39**.
**#3** (auth por password) es una decisión de diseño: no se planifica.

## Fase 1 — Seguridad y bugs críticos ✅

Completada: se retiró el archivo temporal de token de NetBox (#5), se añadió
redacción central de secretos (#2), el upsert de capacidad ya no conserva
valores obsoletos (#8), las dependencias dejaron de depender del orden de
descubrimiento (#6), `--no-verify` avisa de forma prominente (#4) y la
community SNMP ya no viaja en argv (#6).

## Fase 2 — Calidad de datos y parsers ✅

Completada: el `sysDescr` crudo se guarda en su propio campo `sys_descr` y
`os_name` se deriva por reglas (#9), `classify_device` aplica límites de
palabra para descartar falsos positivos como "bios" (#10), la tabla EOL se
externalizó a `src/assessment/eol_os.csv` con versión derivada del propio
archivo y cadencia trimestral documentada y cubierta por test (#7), el parser
de `ss`/`netstat` cubre con fixtures las variantes BusyBox y net-tools,
incluida la columna de proceso de `netstat -p` (#12), y la evidencia DNS
maneja cadenas CNAME (vía `dig`, con fallback al resolver del sistema) y
matching inverso por PTR (#16).

## Fase 3 — Integridad de inventario e integraciones

Completada. Resumen de lo implementado:

- **#21** — `orbyn import` (JSON/CSV) hace round-trip completo de interfaces
  y servicios: el CSV parsea las secciones `#interfaces` y `#services` del
  export, el JSON acepta el objeto completo de `export --format json`, los
  `asset_id` en forma de IP se resuelven al id canónico (`domain::asset_id`)
  y las filas que referencian assets desconocidos se omiten con aviso.
- **#23** — `orbyn export --format ansible-yaml` renderiza el inventario en
  el layout YAML de Ansible (`all.children.<group>.hosts`), compartiendo el
  código de agrupación con el formato INI.
- **#24** — el export Terraform incluye `os_name`/`os_version`/
  `first_seen`/`last_seen` y `--tf-import <type>` genera bloques `import`
  por asset (id del proveedor como placeholder visible).
- **#20** — `orbyn netbox import` incorpora `dcim/interfaces` +
  `virtualization/interfaces` (MAC/MTU/enabled) y `ipam/ip-addresses`
  (IP asignada a la interfaz, `dns_name` como fallback de hostname). El
  export hacia NetBox queda fuera por diseño: Orbyn es de solo lectura
  contra NetBox.

## Fase 4 — CLI y datos operativos ✅

Completada:

- **#30** — `orbyn annotate --unset <field>` (repetible: environment | owner
  | criticality) limpia anotaciones; `AssetAnnotations` gana un campo
  `unset` que se aplica tras los setters.
- **#31** — los jobs persisten `filesystems_found`,
  `running_services_found` y `connections_found` (migración `0007`), y
  `orbyn jobs` los muestra en tabla y CSV.
- **#35** — `domain::EvidenceKind` centraliza los valores de evidencia y
  `Dependency::evidence_kind()` sustituye los literales `"dns"` en reglas
  de assessment, grouping y render; el literal del SQL de reconcile queda
  fijado por test al valor canónico.

## Fase 5 — Escala y plataforma ✅

Completada:

- **#27** — el store gana lecturas bulk (`list_all_services/interfaces/
  filesystems/capacities/connections`): una query por tabla en `assess` y
  `export` en vez de una por asset.
- **#29** — `--target` repetible con pool de workers acotado por
  `--concurrency` (default 4) y pacing de lanzamientos con `--rate-limit`;
  un job registra todos los targets y conserva los datos de los targets
  exitosos aunque otros fallen.
- **#32** — job `windows-latest` en CI (build + test): los fakes E2E
  compilan vacíos en Windows y las suites unitarias y de store corren ahí.

Diferidos (ver "Aceptados / fuera de plan"): **#17 WinRM**, **#18 vCenter**.
**#25 PostgreSQL** se retomó y completó como Fase 7.

## Fase 6 — Endurecimiento de seguridad restante ✅

Completada:

- **#38** — `--community` acepta `ORBYN_SNMP_COMMUNITY` vía clap (paridad
  con `--token`), ambos flags aceptan el literal `-` para leer el secreto
  por stdin (una línea, sin argv ni env), y el path de `discover` registra
  el valor de CLI/stdin en el `Redactor` antes de persistir o imprimir
  errores de job. Cobertura E2E: el secreto por stdin llega al `snmp.conf`
  y al header `Authorization` de curl sin aparecer en output ni en el argv
  de los hijos, y un walk fallido demuestra la redacción del valor de CLI.
- **#39** — el primer walk SNMP del proceso limpia directorios
  `orbyn-snmp-<uuid>` obsoletos (match exacto de nombre, uid propio en
  Unix, mtime > 1 h), best-effort y acotado por `std::sync::Once`; el
  borrado post-walk existente se conserva. Cobertura unitaria: stale
  eliminado, fresco conservado, nombres ajenos intactos.

## Fase 7 — Backend PostgreSQL (#25) ✅

Completada:

- **#25** — `PostgresStore` (`src/store/postgres.rs`) implementa el
  contrato `Store` completo sobre el driver PostgreSQL de sqlx (feature
  `postgres` + TLS rustls/webpki). `--db`/`ORBYN_DB` aceptan URLs
  `postgres://`/`postgresql://` (`DbTarget` en `src/config.rs`); los paths
  de filesystem siguen seleccionando SQLite. El esquema vive en
  `migrations/postgres/` (BIGINT/DOUBLE PRECISION/BOOLEAN) y se aplica
  automáticamente al abrir; el mapeo de filas se comparte con SQLite vía
  `src/store/rows.rs`. TLS se negocia cuando el servidor lo ofrece
  (`?sslmode=require` lo exige). Cobertura: `tests/postgres_store.rs`
  (seis tests: round-trip de todos los tipos de observación, bulk reads,
  confirm/remove de dependencias, anotaciones, jobs/audit, límites de
  métricas) corre contra una base viva cuando `ORBYN_PG_TEST_URL` está
  definido, y CI la ejecuta contra un servicio `postgres:16`. La excepción
  de auditoría `RUSTSEC-2023-0071` queda resuelta: el `rsa` 0.9.10 fijado
  en el lockfile ya contiene el parche.

## Aceptados / fuera de plan

- **#22 `export --format table` eliminado** — cambio incompatible documentado
  frente a v0.5; no se reintroduce.
- **#3 Auth por password** — decisión de diseño: se apoya en ssh-agent /
  identity files, Orbyn no almacena credenciales.
- **#17 WinRM nativo** — diferido: la recolección Windows viaja por
  PowerShell sobre OpenSSH; un adaptador WS-Man exige un cliente SOAP/sesión
  que no vale la pena mantener ahora.
- **#18 vCenter** — diferido: requiere cliente SOAP/sesiones; queda para una
  fase de integraciones de virtualización.
