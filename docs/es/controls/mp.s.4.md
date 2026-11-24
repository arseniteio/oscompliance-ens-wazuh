# mp.s.4 Protección frente a la denegación de servicio

mp.s.4 juzga los activos de los servicios expuestos: su margen de CPU y memoria, las cookies SYN y un cortafuegos que descarta por defecto, los servicios UDP que podrían amplificar ataques, las reglas y la respuesta activa de Wazuh contra la denegación de servicio, y el registro de episodios con su reacción.

Niveles: MEDIO, ALTO. Anexo II, apartado 5.8.4. Definición: [`catalog/controls/ens/mp.s.4.json`](../../../catalog/controls/ens/mp.s.4.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 4.1 capacidad con margen | M/A | EV-01, EV-10 |
| 4.2 prevención de ataques conocidos | M/A | EV-02, EV-10 |
| r1.1 detección y tratamiento | A | EV-03, EV-07, EV-10 |
| r1.2 reacción con el proveedor de comunicaciones | A | EV-06 |
| r2.1 ataques desde las propias instalaciones | ninguno | EV-09 |

Un activo que no es una `maquina` de P-01: todas las evidencias y requisitos NOT_APPLICABLE. Cuando ningún activo de P-01 informa a Wazuh, el manager asume el control: EV-01, EV-02 y EV-09 son ahí NON_COMPLIANT.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| hecho `device_security` ([mp.eq.2](mp.eq.2.md)) | `load_percent`, `memory_used_percent`, `syn_cookies` | EV-01, EV-02 |
| hecho `firewall_snapshot` ([op.acc.4](op.acc.4.md)) | cadenas de entrada y su política | EV-02 |
| reglas y respuesta activa de la API de Wazuh ([op.mon.1](op.mon.1.md)) | | EV-03, EV-07 |
| `listening_snapshot`, `listening_socket` ([op.acc.6](op.acc.6.md)) | sockets UDP | EV-09 |
| P-07 episodios | | EV-06, EV-10 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 servicios expuestos `servicio \| maquina \| criticidad \| disponibilidad` | | alcance |
| P-02 máximo de CPU y memoria en uso, porcentaje | | EV-01 |
| P-03 indicadores de denegación de servicio `ataque \| indicador \| fuente \| reglas` | | EV-03, EV-07 |
| P-04 tecnologías de prevención, P-05 procedimiento de reacción, P-06 contacto del proveedor, P-09 carga prevista | documental | |
| P-07 episodios `inicio \| fin \| servicio \| vector \| impacto \| respuesta \| proveedor` | | EV-06, EV-10 |
| P-08 servicios amplificadores autorizados | nombres o puertos | EV-09 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mps4`.

- EV-01 margen. `load_percent` y `memory_used_percent` como máximo P-02.
- EV-02 prevención. Cookies SYN activadas y una cadena enganchada a input con política drop.
- EV-03 detección. Como EV-04 de mp.com.3 para los indicadores de P-03.
- EV-07 contención. Una respuesta activa no desactivada cuyas reglas incluyen una regla cargada de P-03.
- EV-06 proveedor. Cada episodio con `impacto` alto y `proveedor`.
- EV-10 episodios. Cada episodio con `vector`, `impacto` y `respuesta`.
- EV-09 amplificadores. Ningún socket UDP en 19, 53, 123, 161, 389, 1900, 5353 u 11211 enlazado fuera de loopback, salvo que P-08 nombre el servicio o el puerto.

## No se mide

- Los ataques salientes. Ninguna fuente común los indica; EV-09 vigila los amplificadores.
