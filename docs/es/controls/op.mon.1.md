# op.mon.1 Detección de intrusión

op.mon.1 juzga el manager de Wazuh como sistema de detección de intrusiones: si se ejecuta y carga reglas, si esas reglas cubren el análisis de riesgos, están al día y solo se silencian con aprobación, si cada activo está bajo él y produce detecciones, y si le llega la detección de red que pide el análisis de riesgos.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.7.1. Definición: [`catalog/controls/ens/op.mon.1.json`](../../../catalog/controls/ens/op.mon.1.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 1.1 herramientas de detección | B/M/A | EV-01 a EV-05 |
| r1.1 detección basada en reglas | M/A | EV-01, EV-08 |
| r2.1 procedimientos de respuesta a alertas | A | atestación (P-ATT) |
| r3.1 acciones automáticas | ninguno | EV-07 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| API de Wazuh `/manager/status` | procesos del manager | EV-01 |
| API de Wazuh `/rules?status=enabled` | reglas cargadas: id, nivel, fichero, directorio | EV-01, EV-04, EV-08 |
| API de Wazuh `/manager/configuration` | `ruleset` (rule_exclude), `active-response` | EV-07, EV-08 |
| API de Wazuh `/syscollector/000/packages` | versión y hora de instalación de `wazuh-manager` | EV-08 |
| `wazuh-monitoring-*` | último keepalive de cada activo | EV-02 |
| hecho `wazuh_agent_config` ([op.acc.2](op.acc.2.md)) | FIM y SCA activados | EV-02 |
| alertas, sin las de OSCompliance | alerta más reciente de cada activo en 90 días | EV-03 |
| alertas de los grupos `ids`, `suricata`, `snort`, `zeek`, `nids` | alertas de intrusión de red de la flota | EV-05 |
| alertas de respuesta activa | respuestas ejecutadas en el activo | EV-07 |

El motor lee el manager con su usuario de API (`-wazuh-api`); el rol necesita `manager:read` y `rules:read` (catalog/wazuh/engine-api-role.json). Sin la API, EV-01, EV-04, EV-07 y EV-08 quedan NOT_EVALUABLE. El manager se lee una vez y se juzga para cada activo.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 detección de red `necesaria \| producto \| justificacion` | una fila | EV-05 |
| P-02 conjuntos de reglas `conjunto \| descripcion \| minimo_reglas` | `wazuh`, `propias` o un fichero de reglas | EV-01 |
| P-03 situaciones de compromiso `situacion \| ambito \| reglas` | identificadores y rangos de reglas | EV-04 |
| P-04 procedimientos de respuesta a alertas | documental | |
| P-05 silenciado aprobado `regla \| motivo \| aprobador` | | EV-08 |
| P-06 respuestas automáticas `accion \| reglas \| alcance \| timeout` | | EV-07 |
| P-07 antigüedad máxima de las reglas en días | | EV-08 |
| P-08 días sin detecciones | | EV-03, EV-05 |
| P-09 horas sin informar | | EV-02 |
| P-ATT atestaciones documentales | r2.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opmon1`.

- EV-01 detección en marcha. `wazuh-analysisd`, `wazuh-remoted`, `wazuh-db` y `wazuh-modulesd` en marcha, reglas de nivel 1 o superior cargadas, y cada conjunto de reglas de P-02 con al menos `minimo_reglas`.
- EV-02 cobertura. El último keepalive del activo dentro de P-09 horas, y ni FIM ni SCA desactivados en la configuración de su agente. Wazuh no guarda keepalive del manager: informa mientras `wazuh-analysisd` se ejecuta.
- EV-03 detecciones. Una alerta del activo dentro de P-08 días.
- EV-04 análisis de riesgos. Cada situación de P-03 tiene una regla cargada de nivel 1 o superior entre sus reglas.
- EV-05 detección de red. Cuando P-01 dice `sí`, una alerta de intrusión de red dentro de P-08 días; si no, COMPLIANT con su justificación.
- EV-07 respuestas automáticas. Cada acción de P-06 configurada y no desactivada en la respuesta activa del manager.
- EV-08 reglas al día. El paquete `wazuh-manager` instalado dentro de P-07 días, y cada fichero de reglas excluido y cada regla de Wazuh reescrita a nivel 0 en `etc/rules` (id por debajo de 100000) en P-05 con motivo y aprobador.

## No se mide

- La aplicación de los procedimientos. op.exp.7 juzga el tratamiento de cada alerta; r2.1 queda como atestación.
