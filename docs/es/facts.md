# Hechos

Un hecho es una observación de una máquina, escrita por `oscompliance-agent` como una línea JSON en `/var/log/oscompliance/facts.ndjson`. Los hechos no llevan veredicto, ni identificador de evidencia, ni de requisito: el catálogo asocia hechos con evidencias y el motor los juzga.

Esquemas: [`catalog/schemas/facts`](../../catalog/schemas/facts) (JSON Schema). Tipos Go: [`catalog/fact`](../../catalog/fact). Ejemplos: [`catalog/schemas/facts/examples`](../../catalog/schemas/facts/examples).

## Envoltura

Cada línea lleva estos campos, con los datos a su lado en el nivel superior.

| Campo | Significado |
|---|---|
| `oscompliance` | Versión de la envoltura. También es la marca en la que se basa el decodificador de Wazuh. |
| `fact` | Tipo de hecho. Elige el esquema de los datos. |
| `ts` | Hora de la observación, UTC, RFC 3339 con sufijo Z. |
| `host` | Nombre de host del sistema observado. |
| `agent_version` | Versión del agente oscompliance que emitió el hecho. |
| `run_id` | Identificador de una pasada de recogida. Todos los hechos de una pasada lo comparten; los hechos snapshot lo usan para demostrar que está completa. |
| `records_run_id` | Se define en un snapshot cuyos registros no han cambiado desde una pasada anterior: sus registros son los de esa pasada, que el agente no vuelve a emitir. El agente emite cada registro al menos cada 3 días. |

```json
{"oscompliance":"1","fact":"group_record","ts":"2026-11-01T10:17:02Z","host":"web-01","agent_version":"1.0.0","run_id":"5f0c…","group_name":"sudo","gid":27,"members":["alice"]}
```

## Pasadas

- Un colector emite primero sus registros y al final un snapshot. El snapshot lleva `records_emitted`, para que el motor distinga una pasada completa de una parcial.
- Un snapshot se emite aunque no se haya podido leer su fuente; su `status` y su `error` indican por qué, y las evidencias que lo necesitan quedan NOT_EVALUABLE por COLLECTION.
- Un colector cuya salida no ha cambiado no envía nada. `agent_pass` cierra cada pasada y nombra, para cada uno de esos colectores, la pasada anterior cuyos registros siguen vigentes. Todo se envía de nuevo al menos cada tres días.
- El agente nunca envía un hash de contraseña, una clave privada, el contenido de un fichero ni un valor de configuración que los controles no juzgan.

## Colectores

| Colector | Hechos | Lee |
|---|---|---|
| `identity` | [identity_record](#identity_record), [identity_snapshot](#identity_snapshot) | /etc/passwd, /etc/shadow, `sshd -T -C user=<account>`, authorized_keys files, wtmp, lastlog |
| `groups` | [group_record](#group_record), [group_snapshot](#group_snapshot) | /etc/group |
| `umask` | [umask_snapshot](#umask_snapshot) | login.defs, /etc/profile, /etc/bash.bashrc, /etc/profile.d |
| `sudoers` | [sudo_grant](#sudo_grant), [sudoers_snapshot](#sudoers_snapshot) | /etc/sudoers y cada fichero incluido |
| `config` | [config_file](#config_file), [config_snapshot](#config_snapshot) | login.defs, faillock.conf, pwquality.conf, pwhistory.conf, sshd_config, ssh_config, Postfix main.cf, `sshd -T`, `ssh -V`, smb.conf, vsftpd.conf |
| `pam` | [pam_rule](#pam_rule), [pam_snapshot](#pam_snapshot) | /etc/pam.d |
| `authprobe` | [auth_log_probe](#auth_log_probe) | escribe una línea en syslog (authpriv) |
| `listening` | [listening_socket](#listening_socket), [listening_snapshot](#listening_snapshot) | /proc/net, /proc/<pid>, `systemctl` |
| `services` | [service_log](#service_log), [service_log_snapshot](#service_log_snapshot) | el agent.conf compartido, los registros de servicio declarados (solo metadatos) |
| `wazuh` | [wazuh_agent_config](#wazuh_agent_config) | ossec.conf y el agent.conf compartido |
| `acl` | [acl_record](#acl_record), [acl_snapshot](#acl_snapshot) | modo, propietario y ACL de `acl_paths` |
| `audit` | [audit_watch_snapshot](#audit_watch_snapshot) | `auditctl -s`, `auditctl -l`; carga las vigilancias pedidas |
| `firewall` | [firewall_snapshot](#firewall_snapshot) | `nft -j` o, si no, `iptables -S` |
| `neighbours` | [neighbour_snapshot](#neighbour_snapshot) | /proc/net/arp |
| `virtualization` | [virtualization](#virtualization) | `systemd-detect-virt`, DMI, /proc/cpuinfo |
| `packages` | [package_selection](#package_selection) | `apt-mark showmanual`, `dnf repoquery --userinstalled` |
| `units` | [unit_snapshot](#unit_snapshot) | `systemctl` |
| `backups` | [backup_snapshot](#backup_snapshot) | metadatos de `backup_sources` y `backup_keys` |
| `updates` | [update_status](#update_status) | `apt-get -s` (una simulación, sin descargas), horas de las listas de paquetes |
| `transactions` | [package_transaction](#package_transaction), [transaction_snapshot](#transaction_snapshot) | /var/log/apt/history.log |
| `snapshots` | [snapshot_list](#snapshot_list) | listas de snapshots de LVM, ZFS y Btrfs |
| `malware` | [malware_protection](#malware_protection) | procesos antimalware, base de datos y ajustes de ClamAV, fapolicyd, scripts de respuesta activa, YARA |
| `timesync` | [time_sync](#time_sync) | chrony o systemd-timesyncd |
| `keys` | [key_record](#key_record), [certificate_record](#certificate_record), [key_snapshot](#key_snapshot) | cabeceras PEM bajo raíces fijas y `key_stores`; nunca el material de las claves |
| `device` | [device_security](#device_security) | chasis, dconf, TMOUT, logind, dispositivo raíz, resolv.conf, carga, memoria, sysctl |
| `sweep` | [special_file](#special_file), [file_sweep_snapshot](#file_sweep_snapshot) | cada sistema de ficheros local, solo metadatos (diario) |
| en cada pasada | [agent_pass](#agent_pass) | cierra la pasada |

El agente de Windows escribe los mismos hechos desde fuentes de Windows, más [file_access](#file_access); sus colectores están en [Agente de Windows](install-windows.md).

## Indexación en Wazuh

| Regla | Indexa |
|---|---|
| 119000 | cualquier línea de `facts.ndjson` con la envoltura (nivel 0) |
| 119001 | un hecho con `fact` y `run_id` válidos (nivel 3, grupo `oscompliance_fact`) |
| 119002 | la sonda de autenticación (grupo `oscompliance_probe`) |
| 119003 | un evento JSON de un servicio externo declarado (grupo `oscompliance_service`) |
| 119004 | un registro de auditd con una clave `oscompliance_*` (grupo `oscompliance_audit`) |
| 119007 | cualquier línea de `C:\ProgramData\oscompliance\facts.ndjson` con la envoltura (nivel 0), padre de 119001 |
| 119008 | el evento 1006 del agente de Windows: una vigilancia de lectura suspendida por su volumen (nivel 10, grupo `oscompliance_audit`) |

En `wazuh-alerts-*`, cada campo de datos queda bajo `data.` y los valores simples llegan como cadenas; el motor los convierte de nuevo con los tipos Go. Los nombres de campo evitan los que Wazuh renombra o mapea como objetos (`user`, `port`, `process`), y `catalog/fact` lo comprueba.

Un campo nunca cambia su tipo JSON entre versiones: el índice de alertas lo mapea la primera vez que lo ve, y un tipo distinto se rechazaría el resto del día. Una forma nueva lleva un nombre nuevo.

## Referencia

### acl_record

Modo, propietario y ACL POSIX de una ruta que el manager ha pedido vigilar al agente (acl_paths de la configuración de grupo que escribe el motor). Se emite antes del acl_snapshot del mismo run_id.

| Campo | Tipo | Significado |
|---|---|---|
| `path` | cadena |  |
| `status` | `read`, `absent`, `unreadable` |  |
| `error` | cadena |  |
| `mode` | cadena | Bits de permisos en octal, cuatro dígitos (0750). |
| `owner` | cadena | Nombres de propietario y grupo, propietario:grupo; números cuando no tienen nombre. |
| `acl` | lista | Entradas de ACL extendida en la forma corta de setfacl, ordenadas: u:nombre:rwx, g:nombre:r-x, m::r-x, y d: para las entradas por defecto. Vacío cuando la ruta no tiene ACL extendida. |

### acl_snapshot

Resumen de una lectura de las rutas de la configuración de grupo, emitido después de sus hechos acl_record.

| Campo | Tipo | Significado |
|---|---|---|
| `config` | cadena |  |
| `status` | `read`, `absent`, `unreadable` | read; absent (la configuración de grupo no lleva rutas); unreadable. |
| `error` | cadena |  |
| `records_emitted` | entero |  |

### agent_pass

Último hecho de cada pasada de recogida. Un colector cuyos registros y snapshot no han cambiado desde el último envío no envía nada; in_force nombra, para cada uno de esos colectores que se ejecutó en la pasada y para los que enviaron sus hechos, el snapshot vigente. El motor toma como actual un snapshot más antiguo que su ventana cuando lo nombra el agent_pass más reciente de la ventana. El agente envía cada colector completo al menos cada 3 días.

| Campo | Tipo | Significado |
|---|---|---|
| `in_force` | lista | Un "fact:run_id" por colector: el hecho snapshot y la pasada que lo envió. |
| `requested_group` | cadena | Grupo de Wazuh al que la máquina pide entrar, de `wazuh_group` en `agent.json`, que escribe `install.sh agent --group`. El motor añade el agente cuando el grupo está en el alcance ENS. No aparece si no se pide ningún grupo. |

### audit_watch_snapshot

Las vigilancias de auditd que ha pedido el manager en la configuración de grupo que escribe el motor, y si están cargadas. Las rutas de audit_watches reciben dos, una por permiso (w, a), con las claves oscompliance_write y oscompliance_attr. Las rutas de read_watches reciben cuatro, una por permiso (r, w, x, a), con las claves oscompliance_read, oscompliance_write, oscompliance_exec y oscompliance_attr. La regla de lectura solo registra sesiones con UID de inicio de sesión (auid!=-1). Cada acceso lleva su tipo. El agente carga con auditctl una vigilancia que falta y retira, listadas en `unloaded`, las que ya no se piden, las de lectura cargadas con -w antes del filtro de auid y las de lectura suspendidas por su volumen. Los binarios de exec_watches (P-03 de op.acc.3) reciben una vigilancia de ejecución cada uno, clave oscompliance_exec.

| Campo | Tipo | Significado |
|---|---|---|
| `auditd` | `running`, `stopped`, `absent`, `error` | running; stopped (el demonio no se ejecuta o la auditoría del núcleo está apagada); absent (auditctl sin instalar); error. |
| `error` | cadena |  |
| `wanted` | lista | Rutas de audit_watches y read_watches. |
| `loaded` | lista | Rutas pedidas con todas sus vigilancias cargadas. |
| `failed` | lista | Rutas pedidas cuya vigilancia no se ha podido cargar, con el motivo. Aquí se rechaza una vigilancia de lectura sobre un fichero que lee todo proceso (/etc/passwd, /etc/group, el almacén de CA, /usr…), porque llenaría el disco. |
| `read_wanted` | lista | Rutas pedidas cuyas lecturas se auditan (read_watches). |
| `exec_wanted` | lista | Binarios cuyas ejecuciones ha pedido auditar el manager (exec_watches). |
| `exec_loaded` | lista | Binarios de exec_wanted con su vigilancia de ejecución cargada. |
| `perm_rules` | entero | Reglas cargadas con la clave oscompliance_perm: cambios de modo, propietario y atributos hechos por personas (auid 1000 o superior) y escrituras en /etc/group, /etc/gshadow, /etc/sudoers y /etc/sudoers.d. El agente las carga cuando no hay ninguna. |

### auth_log_probe

El agente ha escrito la línea "auth log probe <run_id>" en syslog con el nivel authpriv y la etiqueta oscompliance-agent, donde se escribe el registro de autenticación. Cuando la misma línea vuelve como alerta de Wazuh (regla 119002), el registro de autenticación de la máquina llega a Wazuh, haya iniciado sesión alguien o no.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `written`, `error` | written; error (no se ha podido llegar a syslog). |
| `error` | cadena |  |

### backup_snapshot

Las copias que guarda cada fuente de la configuración de grupo (backup_sources): un directorio git, un directorio o un patrón de ficheros, con las fechas de su copia más reciente y más antigua, quién puede leerlas y su sistema de ficheros; y el modo de las claves que las cifran (backup_keys).

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `absent`, `unreadable` |  |
| `error` | cadena |  |
| `sources` | lista |  |
| `key_files` | lista |  |

### certificate_record

Un certificado X.509 encontrado en disco, sin las CA públicas del sistema: sujeto, caducidad y algoritmos de clave pública y de firma.

| Campo | Tipo | Significado |
|---|---|---|
| `path` | cadena |  |
| `subject` | cadena |  |
| `not_after` | cadena |  |
| `key_algorithm` | cadena |  |
| `key_bits` | entero |  |
| `signature_algorithm` | cadena |  |

### config_file

Una fuente de configuración leída como entradas clave y valor, en el orden de la fuente: un fichero (login.defs, faillock.conf, pwquality.conf...) o la configuración efectiva que imprime un programa (sshd -T). Solo se envían las claves que juzgan los controles (Keys en agent/internal/collect/config): los ficheros de configuración pueden contener secretos. Se emite antes del config_snapshot del mismo run_id.

| Campo | Tipo | Significado |
|---|---|---|
| `source` | cadena | Ruta, o el comando para el tipo command. |
| `kind` | `file`, `command` |  |
| `status` | `read`, `absent`, `unreadable`, `error` | read; absent (falta el fichero o el programa no está instalado: nada configurado); unreadable; error (el comando ha fallado). |
| `error` | cadena |  |
| `entries` | lista | Cada ajuste, en orden; una clave puede repetirse (prevalece la última donde el programa lo indica). |

### config_snapshot

Resumen de una lectura de las fuentes de configuración, emitido después de sus registros config_file.

| Campo | Tipo | Significado |
|---|---|---|
| `records_emitted` | entero |  |

### device_security

Cómo protege la máquina una sesión desatendida y su disco: chasis, bloqueo de pantalla de la sesión gráfica (dconf del sistema), tiempos de inactividad de los shells (TMOUT) y de logind (StopIdleSessionSec), cifrado del sistema de ficheros raíz y los servidores DNS que consulta la máquina (resolv.conf, los superiores de systemd-resolved), y su carga: la carga media de 15 minutos frente a sus CPU y la memoria en uso, en tramos del diez por ciento, y si las cookies SYN están activadas.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `chassis_type` | entero |  |
| `portable` | booleano |  |
| `graphical` | booleano |  |
| `lock_idle_delay_seconds` | entero |  |
| `lock_enabled` | booleano |  |
| `lock_delay_seconds` | entero |  |
| `shell_timeout_seconds` | entero |  |
| `shell_timeout_readonly` | booleano |  |
| `logind_idle_seconds` | entero |  |
| `root_device` | cadena |  |
| `root_encrypted` | booleano |  |
| `dns_resolvers` | lista |  |
| `cpu_count` | entero |  |
| `load_percent` | entero |  |
| `memory_used_percent` | entero |  |
| `syn_cookies` | booleano |  |

### file_sweep_snapshot

Resumen de un barrido del sistema de ficheros, emitido después de sus registros special_file. El barrido recorre cada sistema de ficheros local (un dispositivo por raíz, sin pasar nunca a otro), descartando los pseudo sistemas de ficheros y los de contenedores. Solo está completo con status complete y sin directorios ilegibles.

| Campo | Tipo | Significado |
|---|---|---|
| `roots` | lista | Puntos de montaje recorridos. |
| `pruned` | lista |  |
| `status` | `complete`, `timeout`, `truncated`, `error` | complete; timeout: lo ha detenido el límite de tiempo; truncated: más ficheros especiales de los que emite el agente; error: el barrido no ha podido empezar (sweep_error indica por qué). |
| `sweep_error` | cadena |  |
| `unreadable` | entero | Directorios que el barrido no ha podido leer: lo que contienen no se ha visto. |
| `records_emitted` | entero |  |

### file_access

Un acceso auditado a una ruta vigilada en Windows, leído por `-guard-audit` del evento 4663 del registro Seguridad. El motor lo lee como un acceso de auditd de la misma vigilancia.

| Campo | Tipo | Significado |
|---|---|---|
| `time` | cadena | Cuándo registró Windows el acceso. |
| `watch` | cadena | La ruta vigilada bajo la que está el objeto. |
| `path` | cadena | El objeto al que se accedió. |
| `access` | `read`, `write` |  |
| `account` | cadena | La cuenta del sujeto; SYSTEM, LOCAL SERVICE o NETWORK SERVICE para los servicios del sistema operativo. |
| `domain` | cadena |  |
| `process_name` | cadena | El ejecutable que hizo el acceso. |

### firewall_snapshot

El filtro de paquetes de la máquina: sus cadenas base en los puntos input y forward y su política por defecto. Una máquina sin cadena base de entrada lo acepta todo.

| Campo | Tipo | Significado |
|---|---|---|
| `tool` | `nft`, `iptables`, `none` | nft, iptables o none (sin herramienta de filtro de paquetes instalada). |
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `chains` | lista |  |

### group_record

Un grupo del fichero de grupos con sus miembros explícitos. Se emite una vez por grupo, antes del group_snapshot del mismo run_id. Qué grupos conceden privilegios lo decide el motor (P-11), no aquí.

| Campo | Tipo | Significado |
|---|---|---|
| `group_name` | cadena |  |
| `gid` | entero |  |
| `members` | lista | Lista de miembros de la línea del grupo (campo 4), en el orden del fichero. Las cuentas que lo tienen como grupo primario no se listan, igual que en el fichero. |

### group_snapshot

Resumen de una lectura del fichero de grupos. Se emite una vez por pasada, después de cada group_record del mismo run_id. Se emite aunque no se haya podido leer el fichero; entonces no se emite ningún group_record.

| Campo | Tipo | Significado |
|---|---|---|
| `group_path` | cadena |  |
| `group_status` | `read`, `unreadable`, `implausible` | read, unreadable o implausible (sin entrada de GID 0). |
| `group_error` | cadena | Solo cuando group_status no es read. |
| `records_emitted` | entero | Hechos group_record emitidos en este run_id. Solo cuando es read. |

### identity_record

Una entrada de los ficheros de identidad (passwd unido con shadow), con cualquier UID. Se emite una vez por entrada, antes del identity_snapshot del mismo run_id. El motor compara los registros de dos pasadas para encontrar cuentas creadas, modificadas y borradas. Nunca lleva un hash de contraseña: solo su estado. Tampoco las claves: solo cuántas aceptaría sshd.

| Campo | Tipo | Significado |
|---|---|---|
| `account_name` | cadena |  |
| `uid` | entero |  |
| `gid` | entero |  |
| `shell` | cadena | Shell de inicio de sesión tal como está en passwd. Cadena vacía cuando el campo está vacío. |
| `password_state` | `set`, `locked`, `empty`, `missing`, `other` | Del campo de contraseña de shadow. set: un hash. locked: empieza por ! o *. empty: sin contraseña. missing: sin entrada en shadow para la cuenta. other: cualquier otra cosa. |
| `account_expires` | cadena | Fecha de caducidad de la cuenta (campo 8 de shadow), UTC. Ausente cuando el campo está vacío. |
| `authorized_keys` | entero | Claves públicas que aceptaría sshd para la cuenta: líneas no vacías ni de comentario de las rutas AuthorizedKeysFile del identity_snapshot. 0 cuando sshd no está instalado. Ausente cuando no se puede saber: sshd -T ha fallado, se usa un AuthorizedKeysCommand o existe un fichero de claves que no se puede leer. |
| `password_changed` | cadena | Fecha del último cambio de contraseña (campo 3 de shadow), UTC. Ausente cuando el campo está vacío o es 0. |
| `password_change_forced` | booleano | El campo 3 de shadow es 0: la contraseña se debe cambiar en el siguiente inicio de sesión. |
| `password_max_days` | entero | Antigüedad máxima de la contraseña en días (campo 5 de shadow). Ausente cuando el campo está vacío: la contraseña nunca caduca. 99999 se escribe tal cual. |
| `password_inactive_days` | entero | Días tras la caducidad antes de deshabilitar la cuenta (campo 7 de shadow). Ausente cuando está vacío. |
| `authorized_keys_changed` | cadena | Hora de modificación más reciente de los ficheros de claves autorizadas de la cuenta: la última vez que se añadió o retiró una clave, así que alguna clave tiene al menos esta antigüedad. Ausente cuando no existe ningún fichero de claves o no se puede saber. |
| `last_login` | cadena | Inicio de sesión interactivo más reciente de la cuenta en los registros de inicio de sesión del identity_snapshot (wtmp, lastlog). Ausente cuando ninguno lo registra. |

### identity_snapshot

Resumen de una lectura de los ficheros de identidad. Se emite una vez por pasada, después de cada identity_record del mismo run_id, así que también marca la pasada como completa. Se emite aunque no se haya podido leer un fichero; entonces no se emite ningún identity_record.

| Campo | Tipo | Significado |
|---|---|---|
| `passwd_path` | cadena |  |
| `passwd_status` | `read`, `unreadable`, `implausible` | read, unreadable o implausible (sin entrada de UID 0). |
| `passwd_error` | cadena | Solo cuando passwd_status no es read. |
| `shadow_path` | cadena |  |
| `shadow_status` | `read`, `unreadable` | read o unreadable. No se intenta (unreadable, con un error que lo indica) cuando no se ha leído passwd. |
| `shadow_error` | cadena | Solo cuando shadow_status no es read. |
| `records_emitted` | entero | Hechos identity_record emitidos en este run_id. Solo cuando se han leído los dos ficheros. |
| `sshd_status` | `read`, `absent`, `command`, `error` | Cómo ha sabido el agente dónde busca claves sshd. read: de sshd -T. absent: sin binario de sshd, así que sin inicios de sesión con clave. command: decide un AuthorizedKeysCommand, las claves no se pueden contar. error: sshd -T ha fallado. |
| `sshd_error` | cadena | Solo cuando sshd_status es error. |
| `authorized_keys_files` | lista | Patrones AuthorizedKeysFile de sshd -T, tal como están escritos (%h, %u, %U, %% sin expandir). Solo cuando sshd_status es read. |
| `login_records` | lista | Ficheros de registro de inicios de sesión leídos para last_login, en orden. Un fichero que falta no registra nada; last_login solo es tan completo como los ficheros leídos. |

### key_record

Una clave privada encontrada en disco por su cabecera PEM: ruta, tipo, huella de su parte pública (SHA256, como la escribe OpenSSH), modo y propietario.

| Campo | Tipo | Significado |
|---|---|---|
| `path` | cadena |  |
| `key_kind` | `openssh`, `rsa`, `ec`, `encrypted`, `pkcs8` |  |
| `fingerprint` | cadena |  |
| `mode` | cadena |  |
| `owner` | cadena |  |

### key_snapshot

El barrido de claves y certificados detrás de los registros key_record y certificate_record de una pasada.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `roots` | lista |  |
| `truncated` | booleano |  |
| `keys_emitted` | entero |  |
| `certificates_emitted` | entero |  |

### listening_snapshot

Resumen de una lectura de los sockets en escucha, emitido después de sus registros listening_socket.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `unreadable` | read; unreadable (no se ha podido leer /proc/net). |
| `error` | cadena |  |
| `addresses` | lista | Direcciones de las interfaces de la máquina, sin loopback: lo que exponen 0.0.0.0 y ::. |
| `processes_matched` | booleano | false cuando no se han podido asociar los sockets a procesos (el agente no es root). |
| `systemd` | `read`, `absent`, `error` | read: se ha preguntado el estado de las unidades; absent: sin systemctl (contenedores, sistemas sin systemd); error. |
| `records_emitted` | entero |  |

### listening_socket

Un socket que acepta conexiones desde fuera de la máquina (sin loopback): TCP en LISTEN, o UDP enlazado sin otro extremo. Qué servicio es, y si cifra, lo decide el motor. Se emite antes del listening_snapshot del mismo run_id. Los nombres de campo evitan los objetos de la plantilla de alertas de Wazuh (data.port, data.process).

| Campo | Tipo | Significado |
|---|---|---|
| `protocol` | `tcp`, `udp` |  |
| `local_address` | cadena | Dirección local tal como está enlazada: 0.0.0.0 o :: son todas las direcciones de la máquina (listening_snapshot.addresses). |
| `local_port` | entero |  |
| `process_id` | entero | Proceso que tiene el socket; ausente cuando no se ha podido asociar ninguno (sin root). |
| `process_name` | cadena | Nombre del proceso (/proc/<pid>/comm). |
| `process_exe` | cadena | Ruta del ejecutable, cuando se puede leer. |
| `unit` | cadena | Unidad de systemd del proceso (de su cgroup), o el servicio que activa una unidad de socket en escucha. |
| `unit_enabled` | cadena | systemctl is-enabled de unit, tal como se imprime (enabled, disabled, static, masked...). |
| `socket_unit` | cadena | Unidad de socket de systemd que escucha en esta dirección (activación por socket), cuando la hay. |
| `socket_enabled` | cadena | systemctl is-enabled de socket_unit. |

### malware_protection

Las defensas de la máquina contra el código dañino: productos antimalware y si se ejecutan, firmas, ajustes y último análisis completo de ClamAV, fapolicyd, y los scripts de respuesta activa y YARA instalados.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `unreadable` |  |
| `error` | cadena |  |
| `products` | lista |  |
| `signatures` | cadena |  |
| `enabled_settings` | lista | Ajustes de ClamAV activados: proteccion_tiempo_real, actualizacion_automatica_firmas, analisis_comprimidos, registro_syslog. |
| `last_scan` | cadena |  |
| `allowlist` | `enforcing`, `permissive`, `stopped`, `absent` |  |
| `responses` | lista |  |
| `yara` | booleano |  |

### neighbour_snapshot

La tabla de vecinos IPv4 de la máquina (/proc/net/arp): los hosts con los que se ha comunicado en sus enlaces. Se excluyen las entradas aún en resolución.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `unreadable` |  |
| `error` | cadena |  |
| `neighbours` | lista |  |

### package_selection

Los paquetes instalados a petición (apt-mark showmanual, dnf repoquery --userinstalled), no las dependencias que arrastraron.

| Campo | Tipo | Significado |
|---|---|---|
| `manager` | `apt`, `dnf`, `none` |  |
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `packages` | lista |  |

### package_transaction

Una transacción de apt de /var/log/apt/history.log: cuándo se ejecutó, quién la pidió y los paquetes que cambió (nombre versión).

| Campo | Tipo | Significado |
|---|---|---|
| `start` | cadena |  |
| `end` | cadena |  |
| `actor` | cadena |  |
| `command` | cadena |  |
| `installed` | lista |  |
| `upgraded` | lista |  |
| `removed` | lista |  |

### pam_rule

Una regla de la pila de un servicio PAM, en orden de evaluación, con include, substack e @include ya resueltos: el motor ve la pila que ejecuta PAM. Se emite antes del pam_snapshot del mismo run_id.

| Campo | Tipo | Significado |
|---|---|---|
| `service` | cadena | Servicio PAM: el nombre del fichero bajo /etc/pam.d (sshd, login, su, common-password...). |
| `position` | entero | Orden desde 0 dentro de la pila resuelta del servicio. |
| `type` | `auth`, `account`, `password`, `session` |  |
| `control` | cadena | required, requisite, sufficient, optional o un bloque [value=action ...] tal como está escrito. |
| `module` | cadena | Nombre del módulo sin ruta (pam_unix.so). |
| `args` | lista | Los argumentos que juzgan los controles (deny, unlock_time, minlen, minclass, los créditos, dictcheck, remember, obscure, trust); los demás nunca salen de la máquina. |
| `file` | cadena | Fichero en el que está escrita la regla (posiblemente uno incluido). |
| `line` | entero |  |
| `via` | lista | Cadena de includes desde el fichero del servicio, primero el más externo. |
| `module_missing` | booleano | El fichero del módulo no está instalado: PAM omite una regla "-" y hace fallar una normal, así que la regla no impone nada. |

### pam_snapshot

Resumen de una lectura de /etc/pam.d, emitido después de sus registros pam_rule.

| Campo | Tipo | Significado |
|---|---|---|
| `services` | lista |  |
| `status` | `read`, `absent`, `unreadable` | read; absent (sin /etc/pam.d); unreadable. |
| `error` | cadena |  |
| `problems` | lista | Reglas o includes que no se han podido seguir (include que falta, bucle, fichero ilegible), hasta 20. |
| `records_emitted` | entero |  |

### service_log

El registro de autenticación de un servicio de usuarios externos, tal como lo lee el agente de Wazuh: un <localfile> de la configuración compartida del agente cuya etiqueta oscompliance_service nombra el servicio. Informa del fichero y de sus copias rotadas, para que el motor determine la retención y la continuidad (un registro borrado, truncado o rotado sin dejar rastro). Se emite antes del service_log_snapshot del mismo run_id.

| Campo | Tipo | Significado |
|---|---|---|
| `service` | cadena |  |
| `path` | cadena | El <location> del localfile. |
| `status` | `read`, `absent`, `unreadable` | read; absent (el fichero no existe); unreadable. |
| `error` | cadena |  |
| `inode` | entero |  |
| `size` | entero |  |
| `modified` | cadena |  |
| `rotated` | lista | Copias rotadas junto a él (ruta.N, ruta-FECHA, ruta.N.gz...), primero la más antigua. |
| `earliest_event` | cadena | ts de la primera línea del contrato de la copia más antigua: hasta dónde llega en disco el registro del servicio. Ausente cuando no se ha podido leer ninguna línea. |

### service_log_snapshot

Resumen de una lectura de los registros de servicios de usuarios externos declarados al agente de Wazuh, emitido después de sus registros service_log. Ningún servicio declarado es una lectura válida sin registros.

| Campo | Tipo | Significado |
|---|---|---|
| `config` | cadena | La configuración compartida del agente de Wazuh leída. |
| `status` | `read`, `absent`, `unreadable` | read; absent (sin configuración compartida: el agente no está en ningún grupo); unreadable. |
| `error` | cadena |  |
| `agent_name` | cadena | Nombre del agente de Wazuh con el que se comparan los bloques agent_config. |
| `records_emitted` | entero |  |

### snapshot_list

Los snapshots de LVM, ZFS y Btrfs de la máquina y cuándo se hizo cada uno.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `snapshots` | lista |  |

### special_file

Un fichero o directorio que el barrido ha encontrado con al menos una propiedad relevante para el control de acceso: SUID, SGID, escribible por todos, o sin propietario o grupo en la base de datos local de cuentas. Se emite antes del file_sweep_snapshot del mismo run_id. Cuáles se permiten (P-10 línea base de SUID, P-11 excepciones de escritura, P-02 alcance) lo decide el motor.

| Campo | Tipo | Significado |
|---|---|---|
| `path` | cadena |  |
| `kind` | `file`, `directory` |  |
| `mode` | cadena | Bits de permisos en octal, 4 dígitos, como cadena (conserva el cero inicial). |
| `uid` | entero |  |
| `gid` | entero |  |
| `suid` | booleano |  |
| `sgid` | booleano |  |
| `sticky` | booleano |  |
| `world_writable` | booleano |  |
| `no_owner` | booleano | uid sin entrada en passwd. |
| `no_group` | booleano | gid sin entrada en group. |

### sudo_grant

Un sujeto de una especificación de usuario de sudoers, con los alias expandidos pero sin resolver los grupos: el motor resuelve grupos y UID con los hechos de identidad y de grupo. Se emite antes del sudoers_snapshot del mismo run_id. Los sujetos negados no conceden nada y no se emiten.

| Campo | Tipo | Significado |
|---|---|---|
| `subject_kind` | `user`, `group`, `uid`, `gid` | user: un nombre de usuario; group: %grupo; uid: #uid; gid: %#gid. |
| `subject` | cadena | El nombre o número, sin % ni #. |
| `file` | cadena |  |
| `line` | entero |  |
| `nopasswd` | booleano | La especificación lleva una etiqueta NOPASSWD. |
| `nopasswd_commands` | lista | Comandos que este sujeto ejecuta sin contraseña (etiqueta NOPASSWD, que se aplica a los siguientes comandos de la lista hasta PASSWD), en orden, con Cmnd_Alias expandidos. ALL es cualquier comando. Un nombre que queda en mayúsculas es un Cmnd_Alias sin definir. Se excluyen los comandos negados. |
| `spec` | cadena | Lo que concede la especificación, tal como está escrito tras la lista de usuarios y con los espacios reducidos: lista de hosts, =, runas y comandos (ALL=(ALL:ALL) ALL). |

### sudoers_snapshot

Resumen de una lectura de la política de sudoers (/etc/sudoers y los ficheros que incluye sudo), emitido después de sus registros sudo_grant. blind_spots cuenta lo leído que no se puede atribuir a sujetos con nombre; mientras no sea cero, no se puede afirmar que nadie más tiene sudo.

| Campo | Tipo | Significado |
|---|---|---|
| `files` | lista |  |
| `status` | `read`, `absent`, `unreadable` | read: se ha leído /etc/sudoers; absent: sin política de sudo en este host (sudo sin instalar); unreadable. |
| `blind_spots` | entero |  |
| `blind_spot_reasons` | lista | Hasta 20 motivos breves, para el veredicto. |
| `defaults` | lista | Cada ajuste Defaults, en el orden del fichero: binding es lo que sigue a Defaults ("" global, @host, :user, !command, >runas), setting es una entrada tal como está escrita (!authenticate, timestamp_timeout=-1). |
| `records_emitted` | entero |  |

### time_sync

Cómo mantiene la máquina su reloj: chrony o systemd-timesyncd, si está sincronizado, su desfase, las fuentes en uso y si están autenticadas.

| Campo | Tipo | Significado |
|---|---|---|
| `tool` | `chrony`, `timesyncd`, `none` |  |
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `synchronised` | booleano |  |
| `offset_seconds` | número |  |
| `sources` | lista |  |
| `authenticated` | booleano |  |

### transaction_snapshot

La lectura del historial de apt detrás de los registros package_transaction de una pasada.

| Campo | Tipo | Significado |
|---|---|---|
| `manager` | `apt`, `none` |  |
| `status` | `read`, `absent`, `unreadable` |  |
| `error` | cadena |  |
| `records_emitted` | entero |  |

### umask_snapshot

La umask declarada por cada fuente de shell e inicio de sesión de todo el sistema, leída en una pasada. El motor toma la declaración menos restrictiva y la compara bit a bit con P-07. Una fuente leída sin ninguna declaración no se incluye.

| Campo | Tipo | Significado |
|---|---|---|
| `sources` | lista |  |

### unit_snapshot

Los servicios de systemd en marcha en la máquina y los fallidos. absent: la máquina no ejecuta systemd.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `absent`, `error` |  |
| `error` | cadena |  |
| `units` | lista |  |
| `failed` | lista | Servicios que systemd lista como fallidos. |

### update_status

Lo que apt actualizaría ahora (una simulación, sin descargas) y la hora de su lista de paquetes más reciente.

| Campo | Tipo | Significado |
|---|---|---|
| `manager` | `apt`, `none` |  |
| `status` | `read`, `error` |  |
| `error` | cadena |  |
| `lists_updated` | cadena |  |
| `pending` | entero |  |
| `security` | entero |  |

### virtualization

Si la máquina es virtual, según systemd-detect-virt, el firmware (DMI) o la marca de hipervisor de la CPU. Los contenedores no son máquinas virtuales.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `unreadable` |  |
| `error` | cadena |  |
| `virtual` | booleano |  |
| `platform` | cadena | Como lo nombra systemd-detect-virt --vm (kvm, vmware, microsoft...), o unknown. |
| `vendor` | cadena |  |
| `product` | cadena |  |
| `source` | `systemd-detect-virt`, `dmi`, `cpuinfo` |  |

### wazuh_agent_config

Lo que el agente de Wazuh de la máquina está configurado para vigilar, según su ossec.conf y los bloques del agent.conf compartido que se le aplican: los directorios de FIM y los ficheros de registro que lee. El motor comprueba con él que un silencio de Wazuh es un silencio real.

| Campo | Tipo | Significado |
|---|---|---|
| `status` | `read`, `absent`, `unreadable` | read; absent (sin agente de Wazuh instalado); unreadable. |
| `error` | cadena |  |
| `syscheck_disabled` | booleano | FIM está apagado (<disabled>yes</disabled>). |
| `syscheck_frequency` | entero | Segundos entre análisis de FIM programados. |
| `directories` | lista | <directories> de FIM, una entrada por ruta. |
| `ignored` | lista | Entradas <ignore> de FIM. |
| `localfiles` | lista |  |
| `syscollector_disabled` | booleano | Sin wodle de syscollector, o <disabled>yes</disabled>. |
| `syscollector_interval` | entero | Segundos entre análisis de syscollector. |
| `syscollector_scans` | lista | Análisis de syscollector activados. |
| `sca_disabled` | booleano | Sin bloque <sca>, o <enabled>no</enabled>. |
| `sca_interval` | entero | Segundos entre evaluaciones de SCA. |
| `syscheck_scan_on_start` | booleano | FIM analiza cuando arranca el agente (valor por defecto de Wazuh). |
| `rootcheck_disabled` | booleano |  |
| `integrations` | lista | Nombres de <integration> de este ossec.conf (en el manager: virustotal, slack...). |
| `active_responses` | lista | Scripts de respuesta activa que el manager envía a esta máquina (shared/ar.conf), sin los reinicios. |
| `sealed_days` | lista | Días (AAAA-MM-DD) de los últimos 400 cuyo registro de alertas está firmado (.log.sum). Vacío fuera del manager. |
| `lists` | lista | Listas CDB de etc/lists. Vacío fuera del manager. |
| `ruleset_files` | entero | Ficheros de reglas de ruleset/rules. 0 fuera del manager. |
| `custom_rules` | lista | Ficheros de etc/rules. Vacío fuera del manager. |
