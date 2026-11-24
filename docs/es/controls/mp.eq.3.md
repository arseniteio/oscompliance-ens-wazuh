# mp.eq.3 Protección de dispositivos portátiles

mp.eq.3 juzga cada dispositivo portátil: inventariado con su responsable, su custodia comprobada con regularidad, sus pérdidas tratadas a tiempo, sin claves de acceso remoto prescindibles y, en ALTO, con el disco cifrado cuando guarda información de nivel MEDIO o superior.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.3.3. Definición: [`catalog/controls/ens/mp.eq.3.json`](../../../catalog/controls/ens/mp.eq.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 inventario, responsable y custodia | B/M/A | EV-01, EV-02 |
| 3.2 pérdidas notificadas | B/M/A | EV-06 |
| 3.3 acceso remoto limitado | B/M/A | atestación (P-ATT) |
| 3.4 sin claves de acceso remoto prescindibles | B/M/A | EV-03 |
| r1.1 cifrado del disco | A | EV-04 |
| r2.1 uso en lugares protegidos | A | atestación (P-ATT) |

Un activo que no está en P-01 ni es portátil por su chasis: todas las evidencias y requisitos NOT_APPLICABLE.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| hecho `device_security` ([mp.eq.2](mp.eq.2.md)) | chasis, cifrado de la raíz | alcance, EV-04 |
| `wazuh-monitoring-*` | último keepalive | EV-02 |
| `key_snapshot`, `key_record` ([op.exp.10](op.exp.10.md)) | claves privadas en disco | EV-03 |
| P-01, P-09, P-10 | inventario, comprobaciones de custodia, pérdidas | EV-01, EV-02, EV-06 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 inventario `dispositivo \| tipo \| responsable \| nivel_confidencialidad` | `dispositivo` el nombre del agente | alcance, EV-01, EV-04 |
| P-02 días entre comprobaciones de custodia | | EV-02 |
| P-03 procedimiento de pérdida, P-04 perfil de acceso remoto, P-07 normas de uso en el exterior | documental | |
| P-05 claves indispensables | rutas, patrones glob | EV-03 |
| P-08 horas para reaccionar a una pérdida | | EV-06 |
| P-09 comprobaciones de custodia `fecha \| dispositivo \| responsable \| resultado` | | EV-02 |
| P-10 pérdidas `fecha \| dispositivo \| incidente \| acciones_completadas` | | EV-06 |
| P-ATT atestaciones documentales | 3.3, r2.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpeq3`.

- EV-01 inventario. El activo en P-01 con un `responsable`.
- EV-02 custodia. Un keepalive dentro de P-02 días y la comprobación más reciente del dispositivo en P-09 dentro de P-02 días.
- EV-03 claves de acceso remoto. Ninguna clave privada bajo `/home` o `/root` fuera de P-05.
- EV-04 cifrado. Con `nivel_confidencialidad` MEDIO o ALTO, el sistema de ficheros raíz sobre dm-crypt.
- EV-06 pérdidas. Cada pérdida del dispositivo en P-10 con su `incidente` y `acciones_completadas` dentro de P-08 horas.

## No se mide

- El arranque seguro y la contraseña de firmware. Ninguna fuente los lee.
