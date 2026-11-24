# op.acc.3 Segregación de funciones y tareas

op.acc.3 juzga lo que hacen las personas: los binarios que ejecutan y las rutas que tocan, clasificados en funciones con P-03, frente a los pares de funciones que P-02 prohíbe a una misma persona y las tareas críticas para las que P-04 exige varias personas.

Niveles: MEDIO, ALTO. Anexo II, apartado 4.2.3. Definición: [`catalog/controls/ens/op.acc.3.json`](../../../catalog/controls/ens/op.acc.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 desarrollo y operación separados | M/A | EV-01, EV-06 |
| 3.2 autorización y control separados, tareas críticas compartidas | M/A | EV-02, EV-03, EV-06 |
| r1.1 configuración y mantenimiento separados (R1) | A | EV-04, EV-06 |
| r1.2 cuentas de auditoría sin otra función (R1) | A | EV-05 |
| r2.1 cuentas de auditoría controladas (R2) | ninguno | P-ATT |
| r3.1 acceso a la información de seguridad (R3) | ninguno | EV-07 |

## Fuentes

Una acción es una cuenta ejecutando un binario o tocando una ruta.

| Fuente | Contenido | Lo usa |
|---|---|---|
| auditd mediante el decodificador de auditoría de Wazuh, regla 119004 | `audit.auid` (el inicio de sesión, que se conserva a través de su y sudo), `audit.exe`, `audit.file.name`, `audit.key` | todas las evidencias |
| alertas de sudo 5402, 5403, 5407 | `data.srcuser`, `data.command` (la línea de comando completa) | todas las evidencias |
| `audit_watch_snapshot` ([op.acc.2](op.acc.2.md)) | estado de auditd y vigilancias cargadas | silencio |
| `identity_*` ([op.acc.1](op.acc.1.md)) | nombres de los UID de auditoría | todas las evidencias |

El motor deriva las vigilancias de auditd de P-03 y las escribe en la configuración de grupo: los binarios de un directorio bin o sbin pasan a vigilancias de ejecución (`exec_watches`, clave `oscompliance_exec`); las rutas de P-03 y las rutas de seguridad (/var/ossec/etc, /etc/audit, /var/log/audit) pasan a `read_watches`. Un cambio en P-03 llega a todos los agentes sin tocar ningún activo.

Las acciones se agrupan por nombre de cuenta en todos los activos durante los últimos P-06 días: el mismo nombre es la misma persona. Un UID de auditoría sin nombre se notifica y nunca se agrupa.

La cadena de auditoría de un activo está completa cuando auditd funciona, todos los indicadores de ruta de P-03 están vigilados (exactamente o bajo un directorio vigilado) y Wazuh lee el registro de auditoría.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 funciones por persona | documental | |
| P-02 pares incompatibles `a \| b`; `b` puede ser `*` | | EV-01, EV-02, EV-04, EV-05 |
| P-03 `funcion \| indicador \| ...` | plataforma | todas las evidencias |
| P-04 `tarea \| personas \| indicador ...` | | EV-03 |
| P-05 cuentas de auditoría | | EV-05 |
| P-06 ventana de correlación, días | | todas las evidencias |
| P-ATT atestaciones documentales | | r2.1 |

Los nombres de función se comparan sin mayúsculas ni acentos ("Operación" es "operacion"). Los indicadores se buscan como subcadenas del binario, la línea de comando o la ruta, sin distinguir mayúsculas. Cada evidencia de pares juzga un par, buscado en P-02 en cualquier orden: EV-01 `desarrollo | operacion`, EV-02 `autorizacion | control`, EV-04 `configuracion | mantenimiento`, EV-05 `auditoria | *`.

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opacc3`. Si P-02, P-03 o P-06 no se pueden usar, todas las evidencias quedan NOT_EVALUABLE por CONFIGURATION. El silencio en un activo con la cadena de auditoría incompleta es NOT_EVALUABLE por COLLECTION; un incumplimiento encontrado se mantiene.

- EV-01, EV-02, EV-04 pares incompatibles. Una persona que ha actuado en este activo y tiene las dos funciones del par, aquí o en cualquier otro activo: NON_COMPLIANT, con una acción de cada función. El par no está en P-02: NOT_EVALUABLE por CONFIGURATION.
- EV-03 tareas críticas. Una tarea ejecutada en este activo por menos personas distintas de las que exige P-04, durante la ventana: NON_COMPLIANT. Una tarea no ejecutada no es un fallo. Una fila sin número de personas (2 o más) o sin comando: NOT_EVALUABLE por CONFIGURATION.
- EV-05 cuentas de auditoría. Con `auditoria | *` en P-02, una persona con auditoria y cualquier otra función; para cada cuenta de P-05, cualquier función que no sea auditoria o supervision: NON_COMPLIANT. Si no se declara ninguno de los dos: NOT_EVALUABLE por CONFIGURATION.
- EV-06 acciones por cuenta. Las cuentas que han actuado en este activo y sus funciones. Acciones cuya cuenta no se puede nombrar: NOT_EVALUABLE por EVIDENCE.
- EV-07 información de seguridad. Quién ha leído o cambiado las rutas de seguridad. Solo informativa: r3.1 no se aplica en ningún nivel.

## No se mide

- Las funciones sobre el papel (P-01). El control juzga lo que han hecho las personas, no lo que dice el organigrama; P-01 queda como documentación.
- Las acciones fuera de auditd y sudo, como el trabajo hecho desde la interfaz de una aplicación.
