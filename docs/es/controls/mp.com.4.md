# mp.com.4 Separación de flujos de información en la red

mp.com.4 juzga los segmentos de la red: cada activo en un segmento declarado y solo en uno salvo que sea un punto de interconexión, flujos entre segmentos limitados a la matriz, redes inalámbricas en su propio segmento, la forma de segmentar elegida en vigor, los puntos de interconexión vigilados y los incidentes contenidos en su segmento.

Niveles: MEDIO, ALTO. Anexo II, apartado 5.4.4. Definición: [`catalog/controls/ens/mp.com.4.json`](../../../catalog/controls/ens/mp.com.4.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 4.1 tráfico segregado | M/A | EV-01, EV-02, EV-03, EV-09, EV-10 |
| 4.2 redes inalámbricas en un segmento aparte | M/A | EV-04 |
| r1.1 segmentos por VLAN | M | EV-07 |
| r1.2 usuarios, servicios y administración | M | EV-08 |
| r2.1 segmentos por VPN | M/A | EV-07 |
| r3.1 segmentos por medios físicos separados | M/A | atestación (P-ATT) |
| r4.1 control de entrada a cada segmento | A | EV-05 |
| r4.2 punto de interconexión vigilado | A | EV-05 |

P-03 elige una forma de segmentar: los refuerzos de las otras dos son NOT_APPLICABLE. La VLAN sola no es opción en ALTO: ahí EV-07 es NON_COMPLIANT y r2.1 y r3.1 se mantienen.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| inventario de red ([mp.com.1](mp.com.1.md)) | direcciones por interfaz, tipos de interfaz | EV-01, EV-03, EV-04, EV-07, EV-09 |
| alertas de cada punto de P-05 | horas con alertas y flujos aceptados ([mp.com.1](mp.com.1.md)) | EV-02, EV-05 |
| P-13 de op.exp.7, registro de incidentes | incidentes de los últimos 90 días y sus sistemas | EV-09 |
| `wazuh-monitoring-*` | nombres de agente, para encontrar los activos de un incidente | EV-09 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 segmentos `segmento \| proposito \| rango \| vlan` | `proposito` usuarios, servicios, administración, inalámbrico, otro | EV-01 a EV-04, EV-07 a EV-09 |
| P-02 matriz de flujos `origen \| destino \| protocolo \| puerto` | nombres de segmento o `*` | EV-02 |
| P-03 forma de segmentar | VLAN, VPN, medios físicos separados | EV-07, decisiones |
| P-04 redes inalámbricas, P-06 control de entrada | documental | |
| P-05 puntos de interconexión `punto \| segmentos \| equipo \| fuente` | | EV-02, EV-03, EV-05 |
| P-07 días entre revisiones de la matriz | | EV-10 |
| P-08 revisiones de la matriz `fecha \| responsable \| cambios` | | EV-10 |
| P-09 horas sin registros de un punto | | EV-05 |
| P-ATT atestaciones documentales | r3.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpcom4`. Una dirección pertenece al rango más estrecho de P-01 que la contiene; las direcciones de loopback y de enlace local no pertenecen a ninguno.

- EV-01 segmento declarado. Cada dirección del activo en un segmento.
- EV-02 flujos. Cada flujo aceptado de los puntos de P-05 entre dos segmentos coincide con una fila de P-02. Sin puntos: NOT_EVALUABLE.
- EV-03 puentes. El activo en un segmento, o nombrada como `equipo` de un punto de P-05.
- EV-04 inalámbrico. Cada interfaz inalámbrica activa (tipo wireless o un nombre que empieza por `wl`) con sus direcciones en un segmento `inalámbrico`.
- EV-05 registros de interconexión. Como EV-01 de mp.com.1 sobre los puntos de P-05 y P-09.
- EV-07 forma de segmentar. VLAN: cada segmento con su `vlan`; VPN: una interfaz de túnel activa en el activo.
- EV-08 segmentos mínimos. Segmentos de usuarios, servicios y administración.
- EV-09 incidentes contenidos. Ningún incidente de los últimos 90 días cuyas activos estén en más de un segmento.
- EV-10 matriz revisada. La revisión más reciente de P-08 dentro de P-07 días.

## No se mide

- Los usuarios asociados a su segmento. Ningún registro de control de acceso a la red llega a Wazuh de una forma que el motor pueda leer; P-06 queda como documental.
