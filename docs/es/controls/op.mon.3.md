# op.mon.3 Vigilancia

op.mon.3 juzga la recogida de eventos de seguridad: si el manager los recibe y cada fuente declarada los envía, si se correlacionan, si se mide la exposición de cada máquina, si se cubren las anomalías de red, los volúmenes de consultas y las alertas en tiempo real, y las inspecciones periódicas.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.7.3. Definición: [`catalog/controls/ens/op.mon.3.json`](../../../catalog/controls/ens/op.mon.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 recogida automática | B/M/A | EV-01, EV-02 |
| r1.1 correlación | M/A | EV-03 |
| r2.1 exposición | M/A | EV-04 |
| r3.1 comportamiento anómalo | A | EV-05 |
| r3.2 APT de red | A | EV-06 |
| r4.1 observatorios digitales | A | EV-07 |
| r5.1 límites de consultas | A | EV-08 |
| r5.2 alertas en tiempo real | A | EV-09 |
| r6.1 comprobaciones de configuración | A | EV-10 |
| r6.2 análisis de vulnerabilidades | A | EV-11 |
| r6.3 pruebas de penetración | A | EV-12 |
| r7.1 metadatos en interconexiones | ninguno | |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| API de Wazuh ([op.mon.1](op.mon.1.md)) | procesos, reglas, `global`, `alerts`, `integration`, `vulnerability-detection` | EV-01, EV-03, EV-04, EV-08, EV-09, EV-11 |
| `wazuh-monitoring-*` | último keepalive | EV-01 |
| hecho `wazuh_agent_config` | localfiles, SCA activado | EV-02, EV-04, EV-10 |
| alertas por `location` | evento más reciente de cada registro de cada máquina, una semana atrás; un registro de eventos de Windows por su canal (`data.win.system.channel`) | EV-02 |
| alertas de los grupos de detección de red ([op.mon.1](op.mon.1.md)) | | EV-06 |
| alertas de resumen de SCA ([op.exp.2](op.exp.2.md)) | políticas con resultado | EV-04, EV-10 |
| hecho `wazuh_agent_config` del manager ([op.exp.8](op.exp.8.md)) | listas CDB y cuándo cambiaron | EV-07 |
| `wazuh-states-inventory-packages-*` | paquetes inventariados | EV-04, EV-11 |

Wazuh deja el inventario del propio manager fuera de los índices de estado: los paquetes del agente 000 se leen mediante la API ([op.exp.1](op.exp.1.md)).

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 fuentes de eventos `fuente \| sistema \| ubicacion \| max_horas` | `sistema` un nombre de agente o `*` | EV-02 |
| P-02 reglas de correlación `conjunto \| minimo_reglas_correlacion` | | EV-03 |
| P-03 horas sin eventos | por máquina; el valor de organización es el último recurso | EV-01 |
| P-04 comportamientos anómalos `tipo \| indicador \| fuente \| reglas` | | EV-05 |
| P-06 observatorio `servicio \| proveedor \| alcance \| listas` | nombres de listas CDB | EV-07 |
| P-05 sonda de red `producto \| ubicacion \| dias_maximos_sin_alerta` | | EV-06 |
| P-07 límites de consultas `sistema \| perfil \| umbral \| ventana \| reglas` | | EV-08 |
| P-08 destinatarios en tiempo real `destinatario \| canal \| nivel` | `correo` o el nombre de una integración | EV-09 |
| P-09 plan de inspecciones `tipo \| periodicidad_dias \| ejecutor` | | EV-10 a EV-12 |
| P-10 registro de inspecciones `fecha \| tipo \| alcance \| ejecutor \| hallazgos \| estado` | | EV-10 a EV-12 |
| P-11 días que una lista CDB del observatorio puede pasar sin actualizarse | | EV-07 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opmon3`.

- EV-01 recogida. `wazuh-remoted`, `wazuh-analysisd` y `wazuh-db` en marcha, y el último keepalive de la máquina dentro de P-03 horas.
- EV-02 fuentes. Cada fuente de P-01 para la máquina (o `*`) debe ser un localfile de su agente con un evento de esa ubicación dentro de `max_horas` (24 si está vacío). Sin fuentes para la máquina: NOT_EVALUABLE.
- EV-03 correlación. Reglas de nivel 1 o superior con `frequency`, `if_matched_sid` o `if_matched_group` cargadas; cada conjunto de P-02 con al menos su número.
- EV-04 exposición. El detector de vulnerabilidades activado, paquetes de la máquina inventariados, SCA activado y con resultado para ella.
- EV-05 comportamiento anómalo. Como EV-04 de mp.com.3 para los comportamientos de P-04.
- EV-06 APT de red. Una sonda en P-05 cuyas alertas de intrusión de red están dentro de sus días (7 si está vacío).
- EV-07 ciberobservatorio. Cada lista CDB de P-06 presente en el manager y cambiada dentro de P-11 días.
- EV-08 límites de consultas. Cada fila de P-07 tiene entre sus reglas una regla cargada con `frequency` y nivel 1 o superior.
- EV-09 alertas en tiempo real. `correo`: notificación por correo activada, destinatarios definidos y el nivel de alerta de correo igual o inferior a `nivel`; cualquier otro canal: una integración con ese nombre igual o inferior a `nivel`.
- EV-10 comprobaciones de configuración. COMPLIANT cuando SCA comprueba la máquina de forma continua (el SCA de EV-04 y la máquina informando); si no, la fila `configuración` más reciente de P-10 dentro de sus días de P-09.
- EV-11 análisis de vulnerabilidades. Como EV-10, con el detector de vulnerabilidades sobre los paquetes de la máquina, o una fila `vulnerabilidades`.
- EV-12 pruebas de penetración. La fila `pentest` más reciente de P-10 dentro de sus días de P-09.

## No se mide

- EV-13: ninguna fuente produce un veredicto para ella.
- Los ficheros de estado de logcollector y las bases de datos del agente: una fuente cuenta como recogida cuando sus eventos llegan al índice de alertas.
