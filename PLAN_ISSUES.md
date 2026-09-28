# Plan de resolución de Known Issues

Plan de trabajo para resolver los issues registrados en `KnowIssues.md`.
Se agrupan por fases y cada item incluye el enfoque propuesto.

**Sincronizado con el estado actual de `KnowIssues.md`.** Ya resueltos y por
tanto fuera de este plan: **#1, #2, #4, #5, #6 (community SNMP), #6 (orden de
dependencias), #7, #8, #9, #10, #11, #12, #13, #14, #15, #16, #19, #20, #21,
#23, #24, #26, #28, #33, #34, #36 y #37**.
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

## Fase 4 — CLI y datos operativos

- **#30 `annotate --unset`** — flag para limpiar environment/owner/criticality
  (hoy solo se pueden quitar tags con `--remove-tag`).
- **#31 Job outcome completo** — persistir los counts de filesystems, servicios
  en ejecución y conexiones, no solo assets/services.
- **#35 Magic strings DNS** — sustituir los literales `"dns"` /
  `evidence_source != "dns"` por una columna/`evidence_kind`.

## Fase 5 — Escala y plataforma

- **#27 N+1 en assess/export** — queries bulk en el store para
  `list_services`/`list_filesystems`/`get_capacity`/`list_connections`.
- **#29 Discovery sin concurrencia** — workers + rate limit + scheduling
  (un target por ejecución hoy).
- **#17 WinRM**, **#18 vCenter**, **#25 PostgreSQL** — adaptadores/backends
  diferidos.
- **#32 E2E solo Unix** — cobertura automatizada en Windows.

## Fase 6 — Endurecimiento de seguridad restante

- **#38 Secretos en el argv de Orbyn** — aceptar `--token`/`--community` por
  env/stdin, o registrar los valores explicados por CLI en el `Redactor`.
- **#39 `snmp.conf` temporal tras SIGKILL** — limpieza de directorios
  `orbyn-snmp-*` obsoletos al arrancar o gestión de ciclo de vida más estricta
  del archivo temporal.

## Aceptados / fuera de plan

- **#22 `export --format table` eliminado** — cambio incompatible documentado
  frente a v0.5; no se reintroduce.
- **#3 Auth por password** — decisión de diseño: se apoya en ssh-agent /
  identity files, Orbyn no almacena credenciales.
