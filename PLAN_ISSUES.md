# Plan de resolución de Known Issues

Plan de trabajo para resolver los issues registrados en `KnowIssues.md`.
Se agrupan por fases y cada item incluye el enfoque propuesto. Los items marcados
como `~~FIXED~~` en `KnowIssues.md` (#1, #11, #13, #33, #34) quedan fuera.

## Fase 1 — Seguridad y bugs críticos ✅

Hecho:

1. **#5 Permisos del archivo token de NetBox solo en Unix** — ~~FIXED
   El token ahora se pasa a curl por stdin (`-H @-`): no hay archivo temporal
   en ninguna plataforma. (`src/integrations/netbox.rs`)

2. **#2 Sin redacción central de secretos** — ~~FIXED~~
   Nuevo módulo `src/redact.rs` (`Redactor` basado en valores) aplicado a los
   errores de discovery y NetBox antes de escribirlos a logs/registros del job.

3. **#8 Capacity merge conserva valores obsoletos** — ~~FIXED~~
   El upsert de `asset_capacity` ahora sobrescribe cada campo con la última
   observación: un campo no detectado se graba como NULL ("unknown now").

4. **#6 Dependencias dependientes del orden de descubrimiento** — ~~FIXED~~
   Cada batch de `store_observations` re-resuelve los edges desde todas las
   conexiones contra el inventario completo (SQL único), más el método
   `reconcile_dependencies` en el trait `Store`.

5. **#4 `--no-verify` deshabilita la verificación TLS** — ~~FIXED~~
   Ahora imprime un warning prominente al usarlo.

## Fase 2 — Calidad de datos

6. **#7 Tabla EOL estática** — externalizar a datos y marcar `RULES_VERSION` al
   actualizarla.
7. **#9 `sysDescr` como `os_name`** — guardar el raw y derivar vendor/OS por
   reglas.
8. **#10 Heurísticas de `classify_device`** — matching más estricto (boundaries,
   prioridad de coincidencias exactas).
9. **#12 Parser de `ss`/`netstat`** — tolerante a variantes (BusyBox).
10. **#14 Hostnames duplicados** — resolución determinista + warning.
11. **#15 Colisión en `mermaid_node_id`** — incluir tipo/hash en el id.
12. **#16 Evidencia DNS superficial** — timeout, CNAME y match por IP.

## Fase 3 — Features de valor alto

13. **#19 Samples de métricas no persistidos** — tabla time-series.
14. **#20 Import NetBox mínimo** — `dcim/interfaces` + `ipam/ip-addresses`.
15. **#21 Import descarta interfaces/services** — ciclo completo round-trip.
16. **#30 `annotate` no puede limpiar valores** — flag `--unset`.
17. **#31 Job outcome incompleto** — persistir counts de fs/services/conexiones.
18. **#35 Magic strings para DNS** — columna `evidence_kind`.

## Fase 4 — Escala y plataforma

19. **#27 N+1 en assess/export** — queries bulk.
20. **#28 NetBox sin paginación** — iterar `next`.
21. **#29 Discovery sin concurrencia** — workers + rate limit + scheduling.
22. **#26 Sin CI** — GitHub Actions (fmt, clippy, build, test, E2E Linux).
23. **#17 WinRM**, **#18 vCenter**, **#22 export table**, **#23 YAML Ansible**,
    **#24 Terraform completo**, **#25 PostgreSQL** (candidatos a roadmaps).