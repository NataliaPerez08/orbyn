# Resumen de seguridad — SECURITY.md y THREAT_MODEL.md

> Documento de síntesis. No sustituye a las fuentes: ver
> [SECURITY.md](SECURITY.md) (política) y [THREAT_MODEL.md](THREAT_MODEL.md)
> (modelo de amenazas STRIDE). Actualizado tras la incorporación de los
> adaptadores cloud (Proxmox VE, AWS, Huawei Cloud).

---

## 1. SECURITY.md — Política de seguridad

**Principio rector:** solo uso autorizado. Orbyn debe ejecutarse únicamente
contra infraestructura que el operador está autorizado a inspeccionar; no
proporciona attestation ni servicio de autorización remoto.

### Reglas de diseño

- **Read-only por defecto:** los collectors nunca modifican el sistema destino.
- **Alcance explícito y validado:** se rechazan escaneos no restringidos
  (`0.0.0.0/0`); los prefijos más anchos que /16 (IPv4) o /48 (IPv6) exigen el
  opt-in `--allow-large-cidr`.
- **Sin shell:** los targets y opciones se pasan a los subprocesos como
  vectores de argumentos, nunca interpolados en una cadena de shell.
- **Secretos fuera de logs y salida:** los flags secretos (`--token`,
  `--community`, `--winrm-password`, `--secret-key`, `--session-token`) caen a
  variables de entorno (`ORBYN_NETBOX_TOKEN`, `ORBYN_SNMP_COMMUNITY`,
  `ORBYN_WINRM_PASSWORD`, `ORBYN_PROMETHEUS_TOKEN`, `ORBYN_ZABBIX_TOKEN`,
  `ORBYN_PROXMOX_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `HUAWEICLOUD_SDK_SK`) y aceptan el literal `-` para leer una línea de stdin.
  Los valores suministrados en argv generan advertencia en tiempo de ejecución
  y se registran en el `Redactor` (`src/redact.rs`).
- **Sin almacenamiento de credenciales:**
  - SSH delega la autenticación en ssh-agent o ficheros de identidad
    (`CredentialProfile`); Orbyn no guarda ninguna credencial.
  - La contraseña WinRM vive solo en memoria durante la ejecución y llega a
    `curl` mediante un config por stdin (`-K -`), nunca por argv; siempre sobre
    HTTPS (5986 por defecto).
  - Los tokens de API (NetBox, Prometheus, Zabbix, Proxmox) y las firmas de
    proveedores cloud (AWS SigV4, Huawei AK/SK `SDK-HMAC-SHA256`) viajan a
    `curl` por stdin (cabeceras o config), nunca a un fichero temporal.
- **SNMP:** la comunidad se escribe en un `snmp.conf` efímero con permisos
  `0600` dentro de un directorio `0700`, seleccionado vía `SNMPCONFPATH`; jamás
  aparece en los argumentos de `snmpwalk`.
- **Límites de recursos:** respuestas acotadas (16 MiB por respuesta, 60 s por
  petición, tope de 50k puntos por consulta en Prometheus); salida de
  subprocesos limitada por ejecución (16 MiB stdout / 1 MiB stderr), con error
  explícito si se trunca en lugar de parsear un payload parcial.
- **Aislamiento del proceso hijo:** los subprocesos nunca heredan las variables
  de entorno secretas (`SCRUBBED_ENV` en `src/integrations/cloud/mod.rs`:
  tokens `ORBYN_*`, `ORBYN_DB`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `HUAWEICLOUD_SDK_SK`), de modo que un binario secuestrado no puede leerlas.
- **PostgreSQL:** Orbyn no almacena credenciales de base de datos; la
  contraseña se mantiene fuera de argv (`ORBYN_PG_PASSWORD` / `PGPASSWORD`) y
  un URL con contraseña embebida genera advertencia. TLS se negocia cuando el
  servidor lo ofrece y se puede forzar con `?sslmode=require`.
- **Auditoría de dependencias:** RustSec (`cargo audit`); la excepción histórica
  `RUSTSEC-2023-0071` (`rsa`) está resuelta con la versión 0.9.10 bloqueada.

### Divulgación responsable

Los problemas de seguridad se reportan de forma privada a los maintainers
(issue en borrador o GitHub security advisory). Nunca incluir credenciales ni
salida de escaneo real en reportes públicos.

### Referencias cruzadas

- [THREAT_MODEL.md](THREAT_MODEL.md): modelo STRIDE por frontera de confianza.
- [SECURITY_AUDIT.md](SECURITY_AUDIT.md): auditoría completa de 27 hallazgos
  (OY-01..OY-27); 16 corregidos y el resto documentados como residuales
  aceptados (R-8..R-12 en el modelo de amenazas).

---

## 2. THREAT_MODEL.md — Modelo de amenazas (STRIDE)

**Alcance:** el CLI de Orbyn (`orbyn`), herramienta local de usuario único, sin
servidor ni superficie remota ni almacén multiusuario. Revisado para la
versión v1.0 (2026-09-20).

### Fronteras de confianza y flujo de datos

```text
operador ──► A: CLI / env / config (.env, args, stdin)
                 │  targets y credenciales (solo en memoria)
                 ▼
            proceso orbyn (collectors → normalización → store/assess)
                 │            │            │            │
        B: subprocesos   C: resolver   D: persistencia   E: salida
        (nmap/snmpwalk/  DNS (dig /    (SQLite /          (stdout, stderr,
        ssh/curl/dig)    getaddrinfo)   PostgreSQL)        exports, Mermaid)
        └→ hosts remotos y APIs
```

### Activos que importan

- Credenciales de discovery/importación: tokens NetBox/Prometheus/Zabbix,
  comunidad SNMP, contraseña WinRM, token Proxmox, claves AWS
  (access/secret/session) y AK/SK de Huawei Cloud.
- Identidad SSH (solo la ruta del fichero, nunca los bytes de la clave).
- La verdad del inventario (assets, servicios, dependencias, anotaciones).
- El historial de auditoría (jobs, operaciones, fallos y motivos).
- El alcance de escaneo autorizado por el operador.

### Análisis STRIDE por frontera (hallazgos clave)

| Frontera | Amenaza | Estado |
|---|---|---|
| A | Inyección de shell vía `--target` | Resuelta: vectores de argumento, sin `sh -c` |
| A | Secretos visibles en el propio argv | Resuelta: fallback a env + stdin (`-`) + redactor |
| A | Entorno malicioso que redirige `ORBYN_*_BIN` a un binario hostil | Residual aceptado: el operador protege su shell/PATH |
| A | CSV/JSON de import malicioso | Resuelta: SQL parametrizado (`sqlx`) |
| B | Binarios comprometidos (nmap/curl/ssh) ejecutando código | Realidad de supply-chain: instalar desde el gestor del SO, usuario dedicado |
| B | Servidor NetBox hostil (JSON extremo, `next` hacia origen atacante) | Resuelta: parsing acotado + gramática de origen estricta (`url_origin`) |
| B | Hijos que inundan o bloquean pipes (DoS) | Resuelta: `process::run_captured` (pipes concurrentes, timeout, kill) |
| B | Fuga de la contraseña WinRM | Resuelta: HTTPS + stdin config + redactor + env saneada |
| B | `--no-verify` desactiva la verificación TLS | Residual aceptado: advertencia prominente, decisión del operador |
| C | DNS spoofing inyecta dependencias falsas | Mitigado por diseño: aristas de confianza 0.4, jamás autoritativas |
| D | Otro usuario local lee la base de datos | Residual documentado: sin cifrado en reposo; el operador protege el fichero |
| D | Fila de auditoría que filtre un secreto | Resuelta: redactor aplicado en el límite de escritura |
| E | Exports en texto plano con inventario sensible | Residual documentado: responsabilidad del operador (no commitear exports) |

### Recomendaciones abiertas (residuales)

| ID | Riesgo residual | Tratamiento |
|---|---|---|
| R-8 | SSH acepta claves de host desconocidas en la primera conexión (TOFU) | Aceptado; `known_hosts` gestionado como seguimiento para entornos de alta seguridad |
| R-9 | `--no-verify` desactiva TLS (NetBox y adaptadores cloud) | Aceptado por diseño para instancias self-signed, con advertencia |
| R-10 | `orbyn import` lee ficheros/stdin sin tope de tamaño | Abierto, bajo: futuro tope de bytes con error claro |
| R-11 | Windows: `snmp.conf` temporal depende de las ACL de `%TEMP%` | Aceptado: riesgo bajo (directorio por usuario) |
| R-12 | Informativas OY-21..OY-27 (secretos sin zeroize, eco de terminal, audit sin anti-tamper, `export --output` sobrescribe, escapes ANSI/OSC, etc.) | Documentadas en SECURITY_AUDIT.md; ninguna explotable sin compromiso local adicional |

### Componente de mayor riesgo

La **frontera del collector (A + B)**: donde las credenciales y la capacidad
de escaneo se cruzan con entrada no confiable. Reglas que gobiernan la
revisión de código:

1. Targets → vectores de argumentos, nunca cadenas de shell.
2. Sin `sh -c`; las rutas de binarios son el único código externo ejecutado.
3. Los secretos viven solo en memoria; redactar antes de cualquier límite de
   escritura.
4. Alcance validado (`0.0.0.0/0` rechazado; `--allow-large-cidr` para más
   ancho) antes de ejecutar cualquier herramienta.
5. Collectors read-only.
6. Sin almacenamiento de credenciales (ssh-agent / ficheros por ruta).

### Checklist de revisión (obligatorio para cambios en `src/collectors/`,
`src/integrations/`, `src/config.rs` o `src/redact.rs`)

- [ ] Targets y opciones llegan a los subprocesos como vectores de argumentos.
- [ ] Todo subproceso nuevo pasa por `process::run_captured`.
- [ ] Ningún binario nuevo se invoca sin documentar por qué y su postura de confianza.
- [ ] Toda fuente de secreto nueva se registra en `Redactor::from_env`.
- [ ] Las firmas/tokens de proveedores cloud (AWS SigV4, Huawei AK/SK) llegan a
      `curl` por stdin, nunca por argv.
- [ ] Ninguna credencial se escribe en la DB, un fichero temporal, un export o un log.
- [ ] La redacción de salida cubre la nueva ruta de error (job audit + stderr).
- [ ] Toda superficie HTTP nueva verifica TLS por defecto y advierte si se desactiva.
- [ ] La validación de alcance sigue rechazando targets no restringidos.
