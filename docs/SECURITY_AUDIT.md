# Auditoría de seguridad — orbyn v1.0.2

- **Fecha**: 2026-09-30
- **Alcance**: todo el código fuente (`src/`, `tests/`, `migrations/`, CI), `Cargo.lock`,
  flujos de secretos, ejecución de subprocesos, almacenamiento y exportación.
- **Commit auditado**: `db7b5af` (main)
- **Metodología**: revisión manual agresiva de código + verificación empírica de cada
  hallazgo explotable (PoCs ejecutados contra el binario de debug) + `cargo audit`
  (RustSec, 251 crates).
- **Severidades**: Alta / Media / Baja / Informativa.

## Estado de remediación

| ID | Estado | Detalle |
|----|--------|---------|
| OY-01 | ✅ Corregido | `.env` se carga solo del directorio actual (sin ascender) + warning cuando define un `ORBYN_*_BIN` no estándar |
| OY-02 | ✅ Corregido | `env_remove` de `ORBYN_SNMP_COMMUNITY`/`ORBYN_NETBOX_TOKEN`/`ORBYN_DB` en los 4 spawns (nmap, snmpwalk, ssh, curl) + test E2E |
| OY-03 | ✅ Corregido | `hide_env_values = true` en `--community` y `--token` + test de help |
| OY-04 | ✅ Corregido | `csv()` neutraliza fórmulas (`= + - @ \t \r`) con prefijo `'` + tests |
| OY-05 | ✅ Corregido | SQLite pre-creado `0600`, directorio nuevo `0700`, WAL/SHM restringidos post-migrate + test |
| OY-06 | ✅ Corregido | URLs sin password aceptan `ORBYN_PG_PASSWORD`/`PGPASSWORD` (estilo libpq); URL con password embebido dispara warning y el valor queda registrado en el Redactor |
| OY-07 | ✅ Corregido | `resolve_secret` advierte cuando el secreto llega como valor literal de flag (no con `-`/env), recomendando stdin o variable de entorno |
| OY-08 | ✅ Corregido | `run_captured` exige topes de stdout y stderr (16 MiB / 1 MiB por defecto) con drenaje del excedente y flag de truncado; los collectors fallan con error explícito si la salida se corta |
| OY-09 | ✅ Corregido | Piso de prefijo por defecto: IPv4 /16, IPv6 /48 (`MIN_IPV4_PREFIX`/`MIN_IPV6_PREFIX`); `--allow-large-cidr` es el opt-in explícito y `/0` sigue rechazado bajo cualquier política |
| OY-10 | ✅ Corregido | Las 21 referencias a actions de CI y release quedan fijadas por SHA de commit (con comentario de versión) y los tokens siguen el mínimo privilegio (`contents: read` salvo el job que publica) |
| OY-11 | ✅ Corregido | `validate_ssh_user` rechaza valores con `-` inicial + tests |
| OY-12 | ✅ Corregido | Warning obligatorio para `--url http://` + test del predicado |
| OY-13 | ✅ Corregido | Umbral del Redactor bajado de 6 a 4 chars + test (`cisco` cubierto) |
| OY-14 | ✅ Corregido | `resolve_secret` rechaza `\n`/`\r`/`\0` en ambas rutas (flag y stdin) + test |
| OY-15 | ✅ Corregido | Truncado por caracteres en `derive_os_from_sysdescr` + test de regresión multibyte |
| OY-16 | ✅ Corregido | `hcl_string` escapa `\n`/`\r`/`\t`/controles como `\uXXXX` y dobla `${` a `$${` (también cierra la inyección de interpolación de Terraform) + tests |
| OY-17–OY-27 | 📄 Residuales | Documentados como riesgo residual aceptado en `THREAT_MODEL.md` (R-8..R-12); ver detalle abajo |

Todos los fix verificados con los PoC del informe re-ejecutados contra el binario
recompilado (y el fallback `PGPASSWORD` probado contra un PostgreSQL vivo),
además de `cargo fmt`, `clippy -D warnings` y la suite completa.

## Resumen ejecutivo

| Severidad    | Cantidad |
|--------------|----------|
| Alta         | 1        |
| Media        | 11       |
| Baja         | 8        |
| Informativa  | 7        |

Los hallazgos más graves no están en el código de almacenamiento (SQL 100%
parametrizado, auditoría de dependencias limpia), sino en el **perímetro de
procesos y configuración**: carga automática de `.env` desde directorios padres,
secretos heredados por los binarios hijos, filtrado del valor de variables de
entorno en `--help`, inyección de fórmulas CSV, y permisos laxos del archivo de
base de datos. Todos los hallazgos marcados como **PoC** fueron reproducidos
contra el binario compilado.

| ID    | Severidad | Hallazgo |
|-------|-----------|----------|
| OY-01 | Alta      | `.env` de directorios padres + `ORBYN_*_BIN` = ejecución arbitraria |
| OY-02 | Media     | Secretos heredados en el entorno de los procesos hijos |
| OY-03 | Media     | `--help` imprime el valor de `ORBYN_SNMP_COMMUNITY` / `ORBYN_NETBOX_TOKEN` |
| OY-04 | Media     | Inyección de fórmulas CSV en `orbyn export --format csv` |
| OY-05 | Media     | Base SQLite creada `0644` (legible por cualquier usuario local) |
| OY-06 | Media     | Password de PostgreSQL en argv (`/proc/<pid>/cmdline` world-readable) |
| OY-07 | Media     | `--community` / `--token` como flag quedan en argv del proceso |
| OY-08 | Media     | stdout/stderr de hijos sin límite → OOM (amplificado por CIDR /1) |
| OY-09 | Media     | Guard de alcance trivialmente evadible (`1.0.0.0/1` aceptado) |
| OY-10 | Media     | CI: actions fijadas por tag mutable, sin `permissions:` |
| OY-11 | Media     | Inyección de argumentos en `ssh` vía `--user=-o...` |
| OY-12 | Media     | `netbox --url http://` aceptado sin advertencia (token en claro) |
| OY-13 | Baja      | Redactor ignora secretos de menos de 6 caracteres |
| OY-14 | Baja      | Token NetBox sin validación CRLF (header injection vía `-H @-`) |
| OY-15 | Baja      | Panic por slicing UTF-8 con `sysDescr` hostil |
| OY-16 | Baja      | `hcl_string` no escapa saltos de línea (HCL malformado) |
| OY-17 | Baja      | `StrictHostKeyChecking=accept-new` (TOFU) |
| OY-18 | Baja      | `--no-verify` desactiva la verificación TLS de NetBox |
| OY-19 | Baja      | `import` / stdin sin límite de tamaño |
| OY-20 | Baja      | Windows: `snmp.conf` temporal sin hardening de permisos |
| OY-21 | Informativa | Secretos sin zeroize; `Debug` derivado en `Cli`/`Config`/`DbTarget` |
| OY-22 | Informativa | `resolve_secret` lee stdin con eco de terminal |
| OY-23 | Informativa | Race del probe de uid puede degradar la limpieza stale |
| OY-24 | Informativa | Audit trail sin protección anti-tamper |
| OY-25 | Informativa | `export --output` sobrescribe archivos arbitrarios |
| OY-26 | Informativa | Escapes de terminal desde hostnames controlados por dispositivos |
| OY-27 | Informativa | `deps dns` resuelve hostnames controlados por dispositivos |

---

## Hallazgos

### OY-01 (Alta) — `.env` de directorios padres + `ORBYN_*_BIN` = ejecución arbitraria de binarios

- **Ubicación**: `src/main.rs:396` (`dotenvy::dotenv().ok()`), collectors que leen
  `ORBYN_NMAP_BIN` / `ORBYN_SNMP_BIN` / `ORBYN_SSH_BIN` / `ORBYN_CURL_BIN`
  (`nmap.rs:41`, `snmp.rs:79`, `ssh.rs:78`, `netbox.rs:472`).
- **Descripción**: `dotenvy::dotenv()` busca `.env` en el directorio actual **y en
  todos sus ancestros**, y sobrescribe el entorno del proceso. Cualquier variable
  `ORBYN_*_BIN` allí definida se ejecuta como proceso hijo en el siguiente scan.
  Ejecutar `orbyn` dentro de un subdirectorio de un árbol con un `.env` controlado
  por un tercero (repo clonado, directorio compartido, descompresión de un tarball)
  implica ejecución arbitraria de código con los privilegios del operador.
- **PoC (ejecutado)**:
  ```text
  $ mkdir -p /tmp/dotenv-demo/sub && printf 'ORBYN_NMAP_BIN=/tmp/opencode/evil-nmap\n' > /tmp/dotenv-demo/.env
  $ cd /tmp/dotenv-demo/sub && orbyn discover --target 10.99.0.0/30
  >>> .env DEL PADRE EJECUTÓ BINARIO ARBITRARIO   (evil-nmap escribió /tmp/opencode/evil-ran.txt)
  ```
- **Impacto**: RCE local en el contexto del operador de orbyn.
- **Remediación**: hacer la carga de `.env` opt-in (`--env-file <path>` explícito),
  o limitarla al `.env` del directorio actual sin ascender, advirtiendo cuando se
  cargan variables `ORBYN_*_BIN`. Documentar que `ORBYN_*_BIN` es una vía de
  ejecución por diseño.

### OY-02 (Media) — Secretos heredados en el entorno de los procesos hijos

- **Ubicación**: `src/collectors/snmp.rs:201-216` (solo agrega `SNMPCONFPATH`),
  `src/integrations/netbox.rs:538-553`; ningún `Command` del código usa
  `env_remove`/`env_clear`.
- **Descripción**: el trabajo de la Fase 6 sacó los secretos del argv de los hijos,
  pero **no del entorno heredado**: `ORBYN_SNMP_COMMUNITY` y `ORBYN_NETBOX_TOKEN`
  viajan completos en el environment de `snmpwalk` y `curl`. La cadena realista es
  un PATH hijack del binario legítimo (`snmpwalk`/`curl` se resuelven por PATH
  cuando `ORBYN_*_BIN` no se fijó), que lee el secreto de su propio entorno.
- **PoC (ejecutado)**:
  ```text
  $ ORBYN_SNMP_BIN=/tmp/opencode/fake-snmpwalk ORBYN_SNMP_COMMUNITY=ComunidadSecreta99 \
      orbyn discover --collector snmp --target 127.0.0.1
  $ grep ComunidadSecreta99 /tmp/opencode/child-env.txt
  >>> SECRETO PRESENTE EN EL ENV DEL HIJO
  ```
- **Impacto**: exfiltración de community SNMP y token NetBox por cualquier binario
  hijo comprometido o suplantado.
- **Remediación**: en cada spawn de collector/integración, `env_remove` de
  `ORBYN_SNMP_COMMUNITY` y `ORBYN_NETBOX_TOKEN` (mínimo), o `env_clear` con una
  allowlist explícita. Añadir test E2E que falle si el secreto aparece en el env
  del hijo.

### OY-03 (Media) — `--help` imprime el valor de las variables de entorno secretas

- **Ubicación**: `src/main.rs:119-120` (`--community`, `env = "ORBYN_SNMP_COMMUNITY"`)
  y `src/main.rs:386-387` (`--token`, `env = "ORBYN_NETBOX_TOKEN"`); falta
  `hide_env_values = true` en ambos `#[arg]`.
- **Descripción**: clap muestra `[env: VAR=valor]` en la ayuda con el valor actual
  de la variable. Cualquier `orbyn discover --help` o `orbyn netbox import --help`
  ejecutado con los secretos en el entorno los imprime a stdout — terminal
  compartida, logs de CI, scrollback, pipas a `tee`.
- **PoC (ejecutado)**:
  ```text
  $ ORBYN_SNMP_COMMUNITY=topsecret123 orbyn discover --help | grep topsecret
  ... so it never lands in argv [env: ORBYN_SNMP_COMMUNITY=topsecret123]
  $ ORBYN_NETBOX_TOKEN=nbtoken9876 orbyn netbox import --help
  [env: ORBYN_NETBOX_TOKEN=nbtoken9876]
  ```
- **Remediación**: `#[arg(long, env = "...", hide_env_values = true)]` en ambos
  flags. Test que ejecute `--help` con los env seteados y afirme que el valor no
  aparece.

### OY-04 (Media) — Inyección de fórmulas CSV en `orbyn export --format csv`

- **Ubicación**: `src/output/mod.rs:1046-1052` (`fn csv` cita correctamente pero no
  neutraliza fórmulas); flujo de datos: `sysName` SNMP (`snmp.rs:114`) / hostname
  de nmap (`nmap.rs:194-196`) / `import` JSON-CSV (`main.rs:1352-1383`) →
  `assets.hostname`/`tags` → export.
- **Descripción**: un hostname o tag que empiece con `=`, `+`, `-` o `@` se escribe
  tal cual en el CSV. Al abrir el export en Excel/LibreOffice/Sheets se evalúa como
  fórmula (`=HYPERLINK`, `=WEBSERVICE`, DDE `=cmd|...`). El origen puede ser un
  dispositivo hostil que controla su `sysName` o el registro PTR, o un archivo de
  import malicioso.
- **PoC (ejecutado)**:
  ```text
  $ echo '{"assets":[{"ip":"10.99.0.2","hostname":"=HYPERLINK(\"http://evil.example\",\"click\")","tags":["=cmd|/c calc!A1"]}]}' | orbyn import --format json
  $ orbyn export --format csv | grep 10.99.0.2
  10-99-0-2,10.99.0.2,"=HYPERLINK(""http://evil.example"",""click"")",,,,,,,=cmd|/c calc!A1,...
  ```
- **Remediación**: en `csv()`, si el campo empieza con `= + - @` (o tab), prefijar
  una comilla simple o espacio. Aplicar lo mismo a los renderers de Ansible/Terraform
  donde corresponda (ver OY-16).

### OY-05 (Media) — Base SQLite creada con permisos `0644`

- **Ubicación**: `src/store/sqlite.rs:29-54` (`SqliteConnectOptions::new()
  .filename(path).create_if_missing(true)` sin modo de creación; `create_dir_all`
  del padre con umask por defecto).
- **PoC (ejecutado)**:
  ```text
  $ orbyn --db /tmp/perm-test/orbyn.db import ... ; stat -c "%a %n" ...
  755 /tmp/perm-test
  644 /tmp/perm-test/orbyn.db
  ```
- **Impacto**: el inventario completo (topología, IPs, OS, servicios, conexiones
  activas, errores de jobs redactados) es legible por cualquier usuario local de la
  máquina. En hosts multiusuario es fuga de información de infraestructura.
- **Remediación**: crear el archivo con `0600` antes de abrirlo si no existe
  (`OpenOptions::new().write(true).create_new(true).mode(0o600)`), y crear el
  directorio padre con `0700`; o documentar `umask 077` como requisito.

### OY-06 (Media) — Password de PostgreSQL en argv

- **Ubicación**: `src/config.rs:21-27` (`DbTarget::parse`), `src/main.rs:43-44`
  (`--db` global), `src/store/postgres.rs:35-42`.
- **Descripción**: `--db "postgres://usuario:password@host/db"` deja el password en
  el argv del proceso. En Linux `/proc/<pid>/cmdline` es legible por **cualquier**
  usuario local y aparece en `ps auxww`. Es el residual D-4 de THREAT_MODEL.md, pero
  hoy no existe alternativa técnica en la CLI (no hay soporte de `PGPASSWORD`,
  `.pgpass` ni lectura por stdin para la URL).
- **Verificado**: los errores de conexión/parseo de sqlx **no** revelan la URL ni el
  password (probado con password incorrecto y URL malformada) — el riesgo se limita
  a argv.
- **Remediación**: aceptar `?auth=` o variables dedicadas, soportar
  `PGPASSWORD`/`.pgpass` documentándolo, o `-` para leer la URL por stdin. Registrar
  el password en el `Redactor` como defensa en profundidad.

### OY-07 (Media) — `--community` / `--token` como valor de flag quedan en argv

- **Ubicación**: `src/main.rs:117-120`, `384-387`; `resolve_secret` (`main.rs:748`).
- **Descripción**: la opción `-` (stdin) existe y está testeada, pero el camino
  directo `--community valor` / `--token valor` expone el secreto en
  `/proc/<pid>/cmdline` igual que OY-06. No hay advertencia en runtime cuando se
  usa el flag con un valor literal.
- **Remediación**: advertir (stderr) cuando el valor no viene de stdin, o deprecar
  el valor directo en favor de `-`/env. Documentar el residual en SECURITY.md junto
  a OY-06.

### OY-08 (Media) — stdout/stderr de hijos sin límite de captura → OOM

- **Ubicación**: `src/process.rs:111-118` (stderr **sin tope** en ningún caso),
  `src/process.rs:101-105` (stdout sin tope cuando el caller pasa `None`);
  callers: `nmap.rs:78-89` (`None`), `snmp.rs:219-226` (`None`), `ssh.rs:117-124`
  (`None`), `windows.rs` vía el mismo transporte. Solo NetBox pasa un tope
  (`netbox.rs:563`, 16 MB).
- **Descripción**: un dispositivo hostil (o un binario comprometido) que emita
  salida continua hace crecer sin límite los `String` de captura hasta el timeout
  (30 s–30 min según collector). El caso nmap es peor: un scan de un CIDR /1 con
  `-sV` puede producir XML de GBs durante el timeout por defecto de 1800 s.
- **Impacto**: denegación de servicio del proceso de descubrimiento (OOM del
  operador).
- **Remediación**: exigir `max_stdout_bytes` en todos los callers y añadir
  `max_stderr_bytes` a `run_captured` (p. ej. 16 MB, configurable). El drenaje
  post-tope ya existe para stdout; replicarlo para stderr.

### OY-09 (Media) — Guard de alcance evadible con `1.0.0.0/1`

- **Ubicación**: `src/collectors/types.rs:55-82` (rechaza `0.0.0.0/0`, `::/0`,
  cualquier `/0` y `0.0.0.0/8`), `src/collectors/nmap.rs:28-31` (comentario: "CIDR
  targets down to /1 are accepted").
- **Descripción**: `1.0.0.0/1` (la mitad de Internet) y `128.0.0.0/1` pasan la
  validación. El guard anti-scan-global es cosmético contra un operador
  equivocado, que es exactamente la amenaza que dice mitigar.
- **Remediación**: mínimo de prefijo configurable (p. ej. rechazar < /16 por
  defecto con `--allow-large-cidr` para sobreescribir), o tope de hosts por job.

### OY-10 (Media) — CI: actions por tag mutable y sin `permissions:`

- **Ubicación**: `.github/workflows/ci.yml` — `actions/checkout@v4`,
  `dtolnay/rust-toolchain@1.98.1`, `Swatinem/rust-cache@v2`,
  `rustsec/audit-check@v2`; sin bloque `permissions:` en workflow ni jobs.
- **Descripción**: los tags de actions son mutables; un compromiso del upstream
  (o del tag) ejecuta código arbitrario en CI con el token del repo. Sin
  `permissions:` explícito, el token recibe los defaults del repo.
- **Remediación**: fijar cada action por SHA de commit y añadir
  `permissions: contents: read` a nivel de workflow.

### OY-11 (Media) — Inyección de argumentos en `ssh` vía `--user`

- **Ubicación**: `src/collectors/ssh.rs:86-106` — `destination =
  format!("{}@{}", self.profile.username, host)` se pasa como un único arg; un
  username que empieza con `-` se interpreta como opción de ssh.
- **PoC (ejecutado)**:
  ```text
  $ orbyn discover --collector ssh --target 127.0.0.1 --user=-oProxyCommand=touch\ /tmp/opencode/PWNED
  ssh exited with 255 against -oProxyCommand=touch /tmp/opencode/PWNED@127.0.0.1:
  hostname contains invalid characters
  ```
- **Análisis honesto**: la opción inyectada **se consume** (`-oProxyCommand=...`
  llega a ssh como opción), pero el destino real queda destruido (el probe pasa a
  ser el "hostname") y el sufijo `@host` corrompe los valores inyectados, así que
  **no se logró RCE directo**: ssh falla antes de ejecutar el ProxyCommand. El
  impacto práctico es la inyección de opciones (p. ej. `-F` hacia un config
  hostil, si el atacante además controla un archivo en el path con sufijo) y el
  rompimiento silencioso del scan. Nota: clap bloquea `--user -oX` sin `=`, pero
  la sintaxis `--user=-oX` pasa.
- **Remediación**: rechazar usernames que empiecen con `-` (o insertar `--` antes
  del destination — OpenSSH lo soporta). Validación + test.

### OY-12 (Media) — `netbox --url http://` aceptado sin advertencia

- **Ubicación**: `src/integrations/netbox.rs:61-119` (`url_origin` acepta `http`),
  `src/main.rs:630-668` (solo `--no-verify` produce warning).
- **Descripción**: un NetBox en `http://` envía el token de Authorization en claro
  por la red. La validación de origen es estricta, pero el esquema inseguro pasa
  sin ninguna señal al operador, a diferencia de `--no-verify` que sí advierte.
- **Remediación**: warning obligatorio para `http://` (o rechazo salvo
  `--allow-http`), simétrico al de `--no-verify`.

### OY-13 (Baja) — Redactor ignora secretos de menos de 6 caracteres

- **Ubicación**: `src/redact.rs:25-30` (`if value.len() >= 6`).
- **Descripción**: una community SNMP de 5 caracteres (p. ej. `cisco`, default
  común) jamás se registra en el `Redactor` y por lo tanto jamás se redacta de
  errores de job. El umbral existe para evitar falsos positivos, pero falla en
  silencio para secretos cortos.
- **Remediación**: bajar el umbral a 3-4, o registrar todo y aceptar los falsos
  positivos en secretos de operador. Al menos, loguear (sin el valor) que un
  secreto corto no quedó cubierto.

### OY-14 (Baja) — Token NetBox sin validación CRLF antes de `-H @-`

- **Ubicación**: `src/integrations/netbox.rs:627-629`
  (`format!("Authorization: Token {token}\n")`), contraste con
  `src/collectors/snmp.rs:240-242` que sí rechaza `\n`/`\r`/`\0` en la community.
- **Descripción**: un `ORBYN_NETBOX_TOKEN` con saltos de línea incrustados (vía
  env o `.env`) se convierte en múltiples headers leídos por curl (`-H @-` lee una
  línea por header) → header injection en la petición a NetBox.
- **Remediación**: validar `\n`/`\r`/`\0` en `resolve_secret`/`token_header_line`,
  igual que `write_community_config`.

### OY-15 (Baja) — Panic por slicing UTF-8 con `sysDescr` hostil

- **Ubicación**: `src/collectors/snmp.rs:386-390` — `&segment[..79]` cuando
  `segment.len() > 80`, sin `is_char_boundary`.
- **Descripción**: un `sysDescr` cuyo byte 79 cae dentro de un carácter
  multibyte (equivalente UTF-8 válido desde el agente SNMP) produce un panic del
  task del collector. El `JoinError` lo convierte en fallo del job (no hay
  corrupción de memoria), pero un dispositivo hostil puede tumbar el descubrimiento
  de forma repetida.
- **Remediación**: usar `char_indices`/`floor_char_boundary` o truncar por chars.

### OY-16 (Baja) — `hcl_string` no escapa saltos de línea

- **Ubicación**: `src/integrations/terraform.rs:151-153` (solo escapa `\` y `"`).
- **Descripción**: un hostname con `\n` (posible vía `import` JSON) rompe el
  string HCL y genera un archivo de export malformado. No hay breakout del string
  (las comillas sí se escapan), pero el resultado no compila en Terraform.
- **Remediación**: escapar `\n`/`\r`/`\t` como en `yaml_scalar`
  (`ansible.rs:166-178`), que sí lo hace bien.

### OY-17 (Baja) — `StrictHostKeyChecking=accept-new` (TOFU)

- **Ubicación**: `src/collectors/ssh.rs:98`.
- **Descripción**: la primera conexión a cada host acepta cualquier clave de host:
  un MITM en la primera conexión alimenta inventario falso (o sondea el probe).
  Elección razonable para un tool de descubrimiento, pero sin alternativa
  estricta.
- **Remediación**: flag `--strict-host-key` que use `StrictHostKeyChecking=yes`,
  y documentar el residual TOFU en THREAT_MODEL.md.

### OY-18 (Baja) — `--no-verify` desactiva la verificación TLS de NetBox

- **Ubicación**: `src/main.rs:639-646` (warning), `src/integrations/netbox.rs:541-543`.
- **Descripción**: existe por diseño para self-signed, con warning claro. Un
  MITM silencioso captura el token. Residual aceptado; se lista para que conste y
  para considerar caducar el flag en favor de `--ca-bundle`.

### OY-19 (Baja) — `import` / stdin sin límite de tamaño

- **Ubicación**: `src/main.rs:1411-1423` (`read_to_string` ilimitado de archivo o
  stdin), `src/import.rs` (sin topes de filas).
- **Remediación**: tope de bytes de entrada (p. ej. 64 MB) con error claro.

### OY-20 (Baja) — Windows: `snmp.conf` temporal sin hardening

- **Ubicación**: `src/collectors/snmp.rs:248-269` — `set_permissions` solo en
  bloques `#[cfg(unix)]`.
- **Descripción**: en Windows el directorio y archivo con la community se crean
  con ACLs heredadas de `%TEMP%` (por usuario, riesgo bajo) pero sin hardening
  explícito.
- **Remediación**: documentar, o fijar ACL de solo-usuario vía
  `std::os::windows::fs`.

### Informativas

- **OY-21** — Los secretos viven en `String` sin zeroize y `Cli`/`Config`/`DbTarget`
  derivan `Debug` con la URL (y su password) dentro: hoy nadie los imprime, pero un
  futuro `tracing::debug!("{cli:?}")` los filtraría. Considerar un `Debug` que
  redacte.
- **OY-22** — `resolve_secret` lee de stdin con eco de terminal: el secreto es
  visible al teclearlo (a diferencia de `read -s`). Documentar.
- **OY-23** — `current_uid` (`snmp.rs:341-348`) stats un probe file en temp
  compartido: una carrera puede devolver un uid ajeno y degradar (no romper) la
  limpieza stale.
- **OY-24** — El audit trail vive en la misma DB editable por el operador: sin
  protección anti-tamper. Documentar como límite del diseño.
- **OY-25** — `export --output` sobrescribe cualquier archivo elegido por el
  operador con permisos por defecto. Elección del operador; sin follow symlinks
  porque usa `fs::write` directo.
- **OY-26** — Hostnames controlados por dispositivos se imprimen en tablas del
  terminal: escapes ANSI/OSC desde un `sysName` hostil pueden manipular terminales
  antiguos. Modernos lo mitigan.
- **OY-27** — `deps dns` resuelve hostnames presentes en el inventario: nombres
  controlados por dispositivos generan consultas DNS hacia el resolver
  configurado (canal de exfiltración ya implícito en el dato).

---

## Defensas verificadas que funcionan

- **SQL 100% parametrizado** en SQLite y PostgreSQL; las únicas interpolaciones son
  `LIMIT {entero tipado}` (`sqlite.rs:509,693,765`, `postgres.rs:508,695,770`).
- **NetBox**: parser de URL estricto sin userinfo ni percent-encoding
  (`netbox.rs:61-119`), chequeo de origen exacto en paginación contra redirección
  maliciosa (`netbox.rs:526-528`), tope de 16 MB por respuesta, token por stdin
  `-H @-` fuera de argv (`netbox.rs:544-548`), curl sin `-L` (no sigue redirects).
- **SNMP**: config temporal `0700`/`0600` en Unix (`snmp.rs:248-269`), rechazo de
  `\n`/`\r`/`\0` en la community, secreto fuera de argv (config file +
  `SNMPCONFPATH`), limpieza de directorios stale con chequeo de uid y match exacto
  de nombre (`snmp.rs:289-336`).
- **Redacción** de errores de job en el límite de escritura (`main.rs:843,899`) y
  del path netbox (`main.rs:653-660`).
- **`cargo audit` limpio**: 251 crates, 0 vulnerabilidades; `rsa` 0.9.10 con el
  parche de RUSTSEC-2023-0071 (el advisory afecta < 0.9.0).
- **`.env` está en `.gitignore`** y no hay secretos en el repo.
- **quick-xml sin resolución de entidades** (sin XXE en el parser de nmap).
- **`run_captured`**: lecturas concurrentes de pipes (sin deadlock), timeout único
  de ciclo de vida, `kill_on_drop` en todos los spawns, topes de captura por
  stream con drenaje del excedente y reporte de truncado (OY-08).
- **Errores de conexión PostgreSQL no revelan** URL ni password (verificado con
  password incorrecto y URL malformada).
- **Sin `unsafe`** y sin invocación de shell en todo el árbol.
- **`validate_target`** rechaza `0.0.0.0/0`, `::/0`, cualquier `/0`, `0.0.0.0/8`
  y, desde la remediación de OY-09, todo prefijo por debajo de /16 (IPv4) o
  /48 (IPv6) salvo `--allow-large-cidr`.

## Plan de remediación sugerido

1. **Inmediato (horas, sin cambios de comportamiento)**: OY-03
   (`hide_env_values`), OY-14 (validación CRLF del token), OY-15 (slicing UTF-8),
   OY-11 (rechazar `--user` con `-` inicial), OY-13 (umbral del redactor).
   **Completado.**
2. **Corto plazo (días)**: OY-02 (`env_remove` de secretos en hijos + test E2E),
   OY-05 (SQLite `0600`), OY-04 (neutralizar fórmulas CSV), OY-12 (warning
   `http://`), OY-01 (dotenvy opt-in o sin ascenso de directorios).
   **Completado.**
3. **Medio plazo**: OY-06/OY-07 (password de DB fuera de argv + registro en el
   Redactor), OY-08 (topes de captura para todos los hijos), OY-09 (mínimo de
   prefijo CIDR), OY-10 (pin SHA + `permissions:` en CI), OY-16 (escapes HCL).
   **Completado.**
4. **Documentar como residuales**: OY-17, OY-18, OY-19, OY-20, OY-21–OY-27 en
   THREAT_MODEL.md / SECURITY.md. **Completado** (THREAT_MODEL.md R-8..R-12).

## Nota metodológica

Los hallazgos OY-01, OY-02, OY-03, OY-04, OY-05 y OY-11 incluyen transcripciones de
PoC ejecutados contra `target/debug/orbyn` en el commit auditado. OY-06 se verificó
en sentido contrario (los errores de sqlx no revelan credenciales). El resto son
hallazgos de revisión de código con referencia exacta a archivo y línea. La
auditoría de dependencias (`cargo audit` v0.22.2, advisory-db con 1277 avisos)
reportó cero vulnerabilidades para el `Cargo.lock` actual.
