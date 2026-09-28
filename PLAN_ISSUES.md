# Plan de resolución de Known Issues

Plan de trabajo para resolver los issues registrados en `KnowIssues.md`.
Se agrupan por fases y cada item incluye el enfoque propuesto.

**Sincronizado con el estado actual de `KnowIssues.md`.** Ya resueltos y por
tanto fuera de este plan: **#1, #2, #4, #5, #6 (community SNMP), #6 (orden de
dependencias), #8, #11, #13, #14, #15, #19, #26, #28, #33, #34, #36 y #37**.
Mitigados con trabajo residual (permanecen en Fase 2): **#7, #12 y #16**.
**#3** (auth por password) es una decisión de diseño: no se planifica.

## Fase 1 — Seguridad y bugs críticos ✅

Completada: se retiró el archivo temporal de token de NetBox (#5), se añadió
redacción central de secretos (#2), el upsert de capacidad ya no conserva
valores obsoletos (#8), las dependencias dejaron de depender del orden de
descubrimiento (#6), `--no-verify` avisa de forma prominente (#4) y la
community SNMP ya no viaja en argv (#6).

## Fase 2 — Calidad de datos y parsers

- **#9 `sysDescr` como `os_name`** — guardar el raw en un campo aparte y derivar
  vendor/OS por reglas; no volcar la cadena `sysDescr` completa en `os_name`.
- **#10 Heurísticas de `classify_device`** — matching más estricto (límites de
  palabra, prioridad de coincidencias exactas sobre subcadenas).
- **#7 Tabla EOL estática** — ~~MITIGADO~~ externalizar la tabla a datos y
  mantener la cadencia de actualización; `EOL_TABLE_VERSION` ya se emite como
  evidencia.
- **#12 Parser de `ss`/`netstat`** — ~~MITIGADO~~ añadir fixtures de las
  variantes BusyBox restantes.
- **#16 Evidencia DNS superficial** — ~~MITIGADO~~ manejo de cadenas CNAME y
  matching adicional por IP.

## Fase 3 — Integridad de inventario e integraciones

- **#21 Import descarta interfaces/services** — extender `ImportedAsset` y
  `orbyn import` para un round-trip completo (interfaces y servicios), no solo
  assets.
- **#20 Import NetBox mínimo** — añadir `dcim/interfaces` + `ipam/ip-addresses`
  (`dns_name`) y valorar export hacia NetBox.
- **#23 YAML Ansible** — segundo formato de inventario Ansible.
- **#24 Terraform completo** — incluir los metadatos soportados
  (`os_name`/`os_version`/`first_seen`/`last_seen`) y generación de bloques
  `import`.

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
