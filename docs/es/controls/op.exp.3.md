# op.exp.3 Gestión de la configuración de seguridad

op.exp.3 añade el tiempo a op.exp.2: la línea base se mantiene sin regresiones, solo las cuentas autorizadas editan la configuración de seguridad, no se instala nada sin autorizar, solo se ejecutan servicios autorizados, la configuración tiene copia y se verifica periódicamente.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.3. Definición: [`catalog/controls/ens/op.exp.3.json`](../../../catalog/controls/ens/op.exp.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 mínima funcionalidad mantenida | B/M/A | EV-01, EV-04, EV-10 |
| 3.2 mínimo privilegio mantenido | B/M/A | EV-01, EV-10 |
| 3.3 cambios autorizados previamente | B/M/A | EV-05 |
| 3.4 reacción a vulnerabilidades notificadas | B/M/A | EV-06 |
| 3.5 reacción a incidentes | B/M/A | EV-07 |
| 3.6 solo el personal autorizado edita la configuración | B/M/A | EV-02 |
| r1.1 línea base autorizada | M/A | atestación (P-ATT) |
| r1.2 verificación periódica frente a la línea base | M/A | EV-03, EV-11 |
| r1.3 lista de servicios autorizados | M/A | EV-04 |
| r2.1 muy pocos administradores | A | EV-08 |
| r3.1 copias de la configuración | A | EV-09 |
| r4.1, r5.1 | ninguno | |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de resumen de SCA ([op.exp.2](op.exp.2.md)) | cada puntuación de la ventana y la más reciente | EV-01 |
| alertas de comprobación de SCA, regla 19007 con `data.sca.check.previous_result: passed` | comprobaciones que han pasado de superadas a falladas | EV-10 |
| escrituras auditadas, regla 119004 clave `oscompliance_write` | quién ha escrito bajo las rutas de P-04 | EV-02, EV-08 |
| alertas de FIM (`syscheck`) y P-10 de op.exp.5 | ediciones bajo P-04 y el registro de cambios | EV-05 |
| `wazuh-states-vulnerabilities-*` y P-01 de op.exp.4 | vulnerabilidades abiertas y sus plazos | EV-06 |
| P-13 de op.exp.7 | el registro de incidentes | EV-07 |
| `audit_watch_snapshot`, `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | la cadena de auditoría | EV-02, EV-08 |
| `identity_snapshot`, `identity_record` ([op.acc.1](op.acc.1.md)) | la cuenta detrás de un UID de auditoría | EV-02, EV-08 |
| alertas de dpkg, regla 2901 (`data.package`) | paquetes recién instalados | EV-03 |
| hecho `package_selection` | paquetes instalados a petición, no como dependencias | EV-03 |
| hecho `unit_snapshot` | servicios de systemd en marcha | EV-04 |
| `listening_snapshot`, `listening_socket` ([op.acc.6](op.acc.6.md)) | procesos en escucha fuera de una unidad | EV-04 |
| hecho `backup_snapshot` | la copia más reciente de cada fuente de P-07 | EV-09 |

Las rutas de P-04 llegan a auditd con las vigilancias de la configuración de grupo (`audit_watches`), que solo registran escrituras y cambios de atributos, porque EV-02 juzga ediciones y no lecturas; las fuentes de P-07 llegan al agente como `backup_sources`.

### `package_selection`

Uno por pasada: `manager` (`apt`, `dnf`, `none`), `status` (`read`, `error`) y `packages`, los nombres que listan `apt-mark showmanual` o `dnf repoquery --userinstalled`. Solo se emite cuando cambia.

### `unit_snapshot`

Uno por pasada: `status` (`read`, `absent` cuando no hay systemd, `error`) y `units`, los servicios que lista `systemctl list-units --type=service --state=running`. Solo se emite cuando cambia.

### `backup_snapshot`

Uno por pasada, `sources` con `source`, `status` (`read`, `absent`, `error`) y `newest`, la hora de la copia más reciente. Una fuente es `git:<directorio>` (hora de su último commit, como etckeeper guarda `/etc`) o un patrón de ficheros (hora del fichero más reciente que coincide). El resto del hecho está en [mp.info.6](mp.info.6.md).

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 software autorizado además de la línea base (nombres de paquete) | sistema | EV-03 |
| P-02 servicios autorizados (nombres de unidad o de proceso) | sistema; integrados por tipo de sistema | EV-04 |
| P-03 cuentas autorizadas para editar la configuración de seguridad | | EV-02 |
| P-04 rutas de la configuración de seguridad | plataforma; integradas por tipo de sistema | EV-02, EV-08 |
| P-05 días entre verificaciones | | EV-11 |
| P-06 procedimiento de autorización de cambios | documental; el registro es P-10 de op.exp.5 | |
| P-07 copias de la configuración `alcance \| fuente \| destino` | sistema | EV-09 |
| P-08 desviación aceptada (%) | documental | |
| P-09 número máximo de administradores efectivos | | EV-08 |
| P-10 horas de antigüedad máxima de una copia | | EV-09 |
| P-11 registro de verificaciones `fecha \| alcance \| responsable` | | EV-11 |
| P-12 días de la serie de puntuaciones | | EV-01 |
| P-ATT atestaciones documentales | 3.3, 3.4, 3.5, r1.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp3`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION. La cadena de auditoría es la de op.acc.4: auditd en marcha, todas las rutas de P-04 vigiladas y el registro de auditoría leído por Wazuh.

- EV-01 línea base mantenida. Cada resumen de las políticas de P-01 de op.exp.2 en los últimos P-12 días, y el más reciente, deben ser al menos P-05 de op.exp.2; si no, NON_COMPLIANT con el más bajo. Se aplica la actualidad de SCA de EV-01 de op.exp.2.
- EV-02 quién edita. Cada escritura con éxito de la ventana bajo P-04 debe ser de una cuenta de P-03; si no, NON_COMPLIANT. Escrituras cuya cuenta no se puede nombrar: NOT_EVALUABLE por EVIDENCE. Ninguna, con la cadena completa: COMPLIANT.
- EV-03 software no autorizado. Cada paquete recién instalado en la ventana que el activo mantiene a petición debe estar en P-01; si no, NON_COMPLIANT. Las dependencias no se juzgan. En un activo con dnf: NOT_EVALUABLE por COLLECTION, porque Wazuh no decodifica el paquete de una línea de yum o dnf.
- EV-04 servicios autorizados. Cada unidad en marcha, y cada proceso en escucha fuera de una unidad, debe estar en P-02 (`getty@.service` cubre cualquier `getty@tty1.service`); si no, NON_COMPLIANT. Sin systemd solo se juzgan los procesos en escucha.
- EV-05 ediciones autorizadas. Cada cambio de FIM de la ventana bajo P-04 debe estar cubierto por una solicitud aprobada de P-10 de op.exp.5 ([op.exp.5](op.exp.5.md)); si no, NON_COMPLIANT.
- EV-06 reacción a vulnerabilidades. EV-02 de op.exp.4 con los plazos de P-01 de op.exp.4 ([op.exp.4](op.exp.4.md)).
- EV-07 reacción a incidentes. EV-12 de op.exp.7 sobre el registro de P-13 de op.exp.7: cada incidente cerrado del activo registra sus medidas.
- EV-08 administradores. Las cuentas que han escrito bajo P-04 en la ventana deben ser como máximo P-09; si no, NON_COMPLIANT.
- EV-09 copias de la configuración. La copia más reciente de cada fuente de P-07 debe quedar dentro de P-10 horas; si no, NON_COMPLIANT. Una fuente sin copia: NON_COMPLIANT.
- EV-10 regresiones. Una comprobación que ha pasado de superada a fallada en los últimos P-12 días: NON_COMPLIANT con las comprobaciones. Ninguna: COMPLIANT.
- EV-11 verificación periódica. La fecha más reciente de P-11 que no esté en el futuro debe quedar dentro de P-05 días.

## No se mide

- Las instalaciones de paquetes en activos rpm para EV-03. Wazuh no decodifica `/var/log/dnf.rpm.log`, así que esas activos quedan NOT_EVALUABLE por COLLECTION.
