# mp.eq.4 Otros dispositivos conectados a la red

mp.eq.4 juzga los dispositivos que no admiten agente: cada dispositivo que un activo ve a su lado debe estar inventariado o ser parte de la flota, sus flujos dentro de lo que su tipo puede hacer, sus registros llegando a Wazuh, y un borrado para los que guardan información.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.3.4. Definición: [`catalog/controls/ens/mp.eq.4.json`](../../../catalog/controls/ens/mp.eq.4.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 4.1 configuración segura y flujos controlados | B/M/A | EV-01 a EV-04 |
| 4.2 borrado del almacenamiento de los dispositivos | B/M/A | EV-04, EV-08 |
| r1.1 productos según op.pl.5 | M/A | atestación (P-ATT) |
| r2.1 control de dispositivos conectados | ninguno | EV-01 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| hecho `neighbour_snapshot` ([op.exp.1](op.exp.1.md)) | la tabla de vecinos del activo | EV-01, EV-02 |
| inventario de red ([mp.com.1](mp.com.1.md)) | direcciones de cada activo de la flota | EV-02 |
| alertas de las fuentes de P-03 con flujos aceptados ([mp.com.1](mp.com.1.md)) | | EV-03 |
| alertas de cada dispositivo de P-04 | horas con alertas, una semana atrás | EV-04 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 dispositivos `dispositivo \| tipo \| direccion \| mac \| responsable \| almacenamiento` | | EV-02, EV-03, EV-08 |
| P-02 flujos por tipo `tipo \| destino \| protocolo \| puerto` | | EV-03 |
| P-03 fuentes de flujos `fuente \| tipo \| nombre_wazuh` | | EV-03 |
| P-04 dispositivos con registros `dispositivo \| configuracion \| fuente` | | EV-04 |
| P-05 borrados `dispositivo \| almacenamiento \| metodo \| cuando` | | EV-08 |
| P-06 horas sin registros de un dispositivo | | EV-04 |
| P-07 productos certificados, P-08 invitados y dispositivos personales, P-09 control de conexión | documental | |
| P-ATT atestaciones documentales | r1.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpeq4`.

- EV-01 descubrimiento. La tabla de vecinos del activo leída.
- EV-02 inventario. Cada vecino coincide con un dispositivo de P-01 por MAC o dirección, o es una dirección de un activo de la flota.
- EV-03 flujos. Cada flujo aceptado de las fuentes de P-03 con un dispositivo de P-01 en cualquier extremo está permitido para su `tipo` hacia el otro extremo. Sin fuentes: NOT_EVALUABLE.
- EV-04 registros de dispositivos. Como EV-01 de mp.com.1 sobre los dispositivos de P-04 y P-06; ningún dispositivo en P-04: NON_COMPLIANT.
- EV-08 borrado. Cada dispositivo de P-01 con `almacenamiento` sí tiene un `metodo` en P-05.

## No se mide

- EV-05 (paneles de administración), EV-06 (conexiones y desconexiones) y EV-07 (dispositivos de invitados): sus fuentes dependen de cada dispositivo y no llegan a Wazuh de una forma común.
- El propio borrado: EV-08 juzga que hay un borrado definido, porque un borrado no deja ningún registro común.
