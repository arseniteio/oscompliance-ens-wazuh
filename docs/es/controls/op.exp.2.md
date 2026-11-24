# op.exp.2 Configuración de seguridad

op.exp.2 juzga que cada activo está bastionado: se evalúa frente a una línea base segura y supera el umbral, no quedan cuentas estándar, no escucha nada sin justificar, los valores por defecto son los seguros y las máquinas virtuales se gestionan como las físicas.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.2. Definición: [`catalog/controls/ens/op.exp.2.json`](../../../catalog/controls/ens/op.exp.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 cuentas y contraseñas estándar retiradas | B/M/A | EV-01, EV-02 |
| 2.2 mínima funcionalidad | B/M/A | EV-01, EV-03, EV-06 |
| 2.3 seguridad por defecto | B/M/A | EV-01, EV-04, EV-06 |
| 2.4 máquinas virtuales con el mismo rigor | B/M/A | EV-05 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de resumen de SCA (reglas 19001 a 19005, `data.sca.type: summary`) | política, puntuación, comprobaciones superadas y falladas de cada evaluación | EV-01, EV-06 |
| hecho `wazuh_agent_config` | los ajustes de SCA del agente | EV-01, EV-06 |
| `wazuh-monitoring-*` | último keepalive de cada agente | EV-01, EV-06 |
| `identity_snapshot`, `identity_record` ([op.acc.1](op.acc.1.md)) | cuentas, estado de la contraseña, UID, claves | EV-02, EV-04 |
| inicios de sesión por sshd, regla 5715 y derivadas | inicios de sesión con éxito | EV-02 |
| `listening_snapshot`, `listening_socket` ([op.acc.6](op.acc.6.md)) | sockets en escucha y su proceso | EV-03 |
| `config_snapshot`, `config_file` (`sshd -T`) | ajustes efectivos de sshd | EV-04 |
| `acl_snapshot`, `acl_record` ([op.acc.2](op.acc.2.md)) | modo y propietario de los ficheros de P-08 | EV-04 |
| hecho `virtualization` | si el activo es virtual | EV-05 |

Wazuh genera un resumen de SCA solo cuando cambia el resultado, así que el resumen más reciente de cada política es el vigente, por antiguo que sea. El motor mira 366 días atrás. La actualidad se demuestra como en op.exp.1: SCA activado, su intervalo dentro de P-09 y el último keepalive dentro de P-09.

Las rutas de P-08 llegan al agente con las rutas de ACL de la configuración de grupo (`acl_paths`).

### `wazuh_agent_config`, campos de SCA

| Campo | Significado |
|---|---|
| `sca_disabled` | `<enabled>no</enabled>` en `<sca>`, o sin bloque `<sca>` |
| `sca_interval` | segundos entre evaluaciones; el valor por defecto de Wazuh es 12 horas |

### `config_file` para `sshd -T`

Añade `permitrootlogin`, `permitemptypasswords`, `x11forwarding`, `hostbasedauthentication`, `ignorerhosts`, `ciphers`, `macs` y `kexalgorithms` a las claves que ya envía op.acc.6.

### `virtualization`

Uno por pasada: `status` (`read`, `unreadable`), `virtual`, `platform` (como lo nombra `systemd-detect-virt --vm`, `unknown` cuando solo lo indican DMI o la CPU), `vendor`, `product` y `source` (`systemd-detect-virt`, `dmi`, `cpuinfo`). Los contenedores no son máquinas virtuales.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 políticas SCA del activo (identificadores) | sistema; integradas por tipo de sistema | EV-01, EV-06 |
| P-02 servicios justificados `servicio \| puertos` | sistema; nombre del proceso, puertos separados por comas, vacío para cualquiera | EV-03 |
| P-03 cuentas estándar `cuenta \| producto` | | EV-02 |
| P-04 excepciones autorizadas `activo \| comprobacion \| motivo \| aprobo \| vigencia` | | EV-04 |
| P-05 puntuación SCA mínima (%) | | EV-06 |
| P-06 máquinas virtuales `hipervisor \| maquina \| gestion` | `maquina` y `gestion` son nombres de agente o una referencia | EV-05 |
| P-07 comprobación antes de producción | documental | |
| P-08 ficheros sensibles `ruta \| modo \| propietario` | sistema; integrados por tipo de sistema | EV-04 |
| P-09 horas que una evaluación puede pasar sin actualizarse | | EV-01, EV-06 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp2`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION.

- EV-01 evaluación de la línea base. SCA desactivado, intervalo por encima de P-09 o sin contacto dentro de P-09: NON_COMPLIANT. Sin resumen de ninguna política de P-01: NON_COMPLIANT. Si no, COMPLIANT con cada política y su puntuación.
- EV-02 cuentas estándar. Una cuenta de P-03 que existe y está activa (según op.acc.1: contraseña utilizable o claves SSH con shell de inicio de sesión), o que ha iniciado sesión en la ventana: NON_COMPLIANT. Una que existe deshabilitada se notifica, no falla.
- EV-03 servicios justificados. Cada socket en escucha debe coincidir con una fila de P-02 por proceso y, si la fila tiene puertos, por puerto; si no, NON_COMPLIANT con proceso y puerto.
- EV-04 valores por defecto seguros. Desviaciones: `permitrootlogin` de sshd distinto de `no`, `permitemptypasswords`, `x11forwarding` o `hostbasedauthentication` en `yes`, `ignorerhosts` en `no`, cifrados, MAC o intercambios de claves débiles; un fichero de P-08 más abierto que su modo o que no pertenece a su propietario; una cuenta con contraseña vacía; un UID 0 distinto de root. Cada una se nombra `<comprobación>[:<sujeto>]` (`ssh_permitrootlogin`, `permisos:/etc/shadow`, `uid0:toor`). Una desviación con una fila de P-04 para este activo y una `vigencia` no vencida está autorizada. Cualquier otra: NON_COMPLIANT.
- EV-05 máquinas virtuales. Un activo no virtual: COMPLIANT. Un activo virtual debe ser una `maquina` de P-06 y, si su `gestion` nombra un agente, ese agente debe estar informando; si no, NON_COMPLIANT.
- EV-06 puntuación de la línea base. La puntuación más reciente de cada política de P-01 evaluada debe ser al menos P-05; si no, NON_COMPLIANT con las puntuaciones inferiores.

## No se mide

- La conformidad antes de producción. Ningún hecho muestra el orden entre el bastionado y la puesta en marcha. P-07 queda como documentación.
