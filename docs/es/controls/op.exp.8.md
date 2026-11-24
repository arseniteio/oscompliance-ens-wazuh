# op.exp.8 Registro de la actividad

op.exp.8 es donde Wazuh es el propio control: cada activo mantiene un registro de auditoría con los campos mínimos y lo entrega sin huecos, los registros se revisan, el reloj está sincronizado, la retención y las copias del indexer coinciden con lo declarado, solo las cuentas autorizadas leen los registros y, en ALTA, el manager analiza y responde por sí mismo.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.8. Definición: [`catalog/controls/ens/op.exp.8.json`](../../../catalog/controls/ens/op.exp.8.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 8.1 registro de auditoría con los campos mínimos | B/M/A | EV-01, EV-03, EV-04, EV-13 |
| 8.2 registros de actividad en los servidores | B/M/A | EV-02, EV-04 |
| r1.1 revisión periódica | M/A | EV-05 |
| r2.1 hora sincronizada y protegida | M/A | EV-06 |
| r3.1 eventos auditados y retención documentados | M/A | EV-07 |
| r4.1 acceso a los registros solo para personal autorizado | M/A | EV-08, EV-09, EV-13 |
| r5.1 análisis en busca de compromisos | A | EV-10 |
| r5.2 recogida, correlación y respuesta automáticas | A | EV-11, EV-12 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `audit_watch_snapshot`, `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | estado de auditd, los registros que lee Wazuh, FIM de la configuración del propio agente | EV-01, EV-13 |
| alertas de auditoría (`rule.groups: audit`) | los campos de los registros recientes | EV-03 |
| `wazuh-monitoring-*` | estado y keepalive de cada agente cada pocos minutos | EV-02, EV-04 |
| hecho `time_sync` | el reloj y su sincronización | EV-06 |
| políticas ISM de `wazuh-alerts-*` | cuándo borra alertas el indexer | EV-07 |
| snapshots del indexer | el snapshot correcto más reciente | EV-09 |
| `acl_snapshot`, `acl_record` ([op.acc.2](op.acc.2.md)) | propietario, modo y ACL de las rutas de registro de P-14 | EV-08 |
| `wazuh_agent_config` del manager, campos adicionales | ficheros de reglas del ruleset y reglas propias | EV-10 |
| respuestas activas ([op.exp.6](op.exp.6.md)) | enviadas, instaladas y ejecutadas | EV-11, EV-12 |

Las rutas de P-14 llegan al agente con las rutas de ACL de la configuración de grupo.

### `time_sync`

Uno por pasada: `tool` (`chrony`, `timesyncd`, `none`), `status`, `synchronised`, `offset` (segundos, chrony), `sources` (servidores en uso) y `authenticated` (una fuente `nts` o `key` en la configuración de chrony).

### `wazuh_agent_config`, campos adicionales

`ruleset_files`, los ficheros de reglas de `ruleset/rules`, y `custom_rules`, los ficheros de `etc/rules`. Ambos están vacíos fuera del manager.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 eventos auditables `categoria_evento \| fuente \| nivel_minimo` | documental | |
| P-02 servidores en alcance | documental | |
| P-03 campos mínimos por fuente | documental | |
| P-04 días entre revisiones de los registros | | EV-05 |
| P-05 fuentes de tiempo `fuente_tiempo \| metodo` | | EV-06 |
| P-06 desfase máximo del reloj (s) | | EV-06 |
| P-07 retención por categoría `categoria_evento \| dias_retencion` | | EV-07 |
| P-08 cuentas que pueden leer los registros `cuenta \| permiso \| alcance_indices` | | EV-08 |
| P-09 copias de los registros `alcance \| destino \| frecuencia \| acceso_restringido` | `frecuencia` en días | EV-09 |
| P-10 conjuntos de reglas desplegados `conjunto_reglas \| cobertura \| mapeo_attck` | `wazuh` o `propias` | EV-10 |
| P-11 respuestas automáticas `accion \| disparador \| alcance \| reversion` | | EV-11 |
| P-12 horas que un activo puede estar en silencio | por activo; el valor de organización es el último recurso | EV-02, EV-04 |
| P-13 registro de revisiones `fecha \| revisor \| alcance \| hallazgos` | | EV-05 |
| P-14 rutas de los registros de actividad | plataforma; integradas por tipo de sistema | EV-08 |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp8`.

- EV-01 registro de auditoría. auditd en marcha y Wazuh leyendo el registro de auditoría y un registro de sistema (journald, syslog o auth.log); si no, NON_COMPLIANT.
- EV-02 cobertura. Como EV-04 de op.exp.1 con P-12.
- EV-03 campos. Las alertas de auditoría de la ventana deben llevar usuario (`auid` o `uid`), hora, objeto (`file.name` o `exe`), tipo y resultado (`success`). Sin alertas de auditoría: NOT_EVALUABLE por COLLECTION.
- EV-04 continuidad. Un registro de monitorización de la ventana con el agente no activo, o dos registros separados más de P-12: NON_COMPLIANT con los huecos.
- EV-05 revisión. P-13 frente a P-04 (`passes.Review`).
- EV-06 hora. Sincronizada, `|offset|` dentro de P-06, una fuente entre las de P-05 y autenticada cuando P-05 pide NTS o una clave; si no, NON_COMPLIANT. Sin servicio de sincronización: NON_COMPLIANT.
- EV-07 retención. La política ISM de los índices de alertas no debe borrarlos antes de la retención más larga de P-07. Sin política: COMPLIANT, no se borra nada.
- EV-08 acceso a los registros. Ninguna ruta de registro de P-14 legible por todos, y cada cuenta que nombra una entrada de ACL en P-08; si no, NON_COMPLIANT.
- EV-09 copias de los registros. El snapshot correcto más reciente del indexer debe quedar dentro de la `frecuencia` más corta de P-09.
- EV-10 análisis. `wazuh` en P-10 necesita el ruleset en el manager; `propias`, ficheros de reglas propias además de `local_rules.xml`.
- EV-11 respuesta automática. Cada `accion` de P-11 debe ser una respuesta activa que el manager envía al activo, con su script en él.
- EV-12 respuestas ejecutadas. Se listan las respuestas activas de la ventana.
- EV-13 integridad del sistema de registro. El agente informando y FIM vigilando `/var/ossec/etc`; si no, NON_COMPLIANT.
