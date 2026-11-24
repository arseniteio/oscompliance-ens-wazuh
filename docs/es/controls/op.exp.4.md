# op.exp.4 Mantenimiento y actualizaciones de seguridad

op.exp.4 juzga que cada activo se analiza en busca de vulnerabilidades, que cada una se corrige dentro del plazo de su severidad, que el activo sigue las actualizaciones y el soporte de su fabricante, que solo las cuentas autorizadas aplican parches y solo dentro de las ventanas de mantenimiento, que los parches pasan antes por preproducción y que existe un punto de reversión antes de cada cambio.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.4. Definición: [`catalog/controls/ens/op.exp.4.json`](../../../catalog/controls/ens/op.exp.4.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 4.1 seguir los anuncios del fabricante | B/M/A | EV-01, EV-03, EV-05, EV-06 |
| 4.2 plazos según el riesgo | B/M/A | EV-01, EV-02, EV-07 |
| 4.3 mantenimiento por personal autorizado | B/M/A | EV-04 |
| r1.1 probado en preproducción | M/A | EV-08 |
| r2.1 mecanismo de reversión | A | EV-09 |
| r3.1 integridad del firmware | ninguno | |
| r4.1 monitorización continua | ninguno | EV-01 |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| `wazuh-states-vulnerabilities-*` | CVE abiertas por paquete y activo: severidad, CVSS, fecha de detección | EV-01, EV-02 |
| inventario y actualidad de op.exp.1 | paquetes, sistema operativo, ajustes de syscollector, keepalive | EV-01, EV-05, EV-06 |
| `wazuh-states-inventory-packages-*` (`package.vendor`) | fabricantes del software instalado | EV-06 |
| hecho `update_status` | actualizaciones pendientes y antigüedad de las listas de paquetes | EV-03 |
| registros `package_transaction` y su snapshot | transacciones de apt: cuándo, quién, qué | EV-04, EV-07, EV-09 |
| alertas de dpkg, regla 2902 (`data.package`, `data.version`) | versiones instaladas en los activos de preproducción | EV-08 |
| hecho `snapshot_list` | snapshots de LVM, ZFS y Btrfs y sus fechas | EV-09 |

Wazuh no analiza vulnerabilidades del manager en los índices de estado: EV-01 y EV-02 del manager quedan NOT_EVALUABLE por COLLECTION.

### `update_status`

Uno por pasada: `manager` (`apt`, `none`), `status` (`read`, `error`), `lists_updated` (fichero más reciente de `/var/lib/apt/lists`), `pending` y `security` (actualizaciones que instalaría `apt-get -s dist-upgrade`, y las de un repositorio `-security`). Solo se emite cuando cambia.

### `package_transaction` y `transaction_snapshot`

Las transacciones de `/var/log/apt/history.log`, un registro por cada una: `start`, `end`, `actor` (`Requested-By`, o `unattended-upgrades` cuando su línea de comando es unattended-upgrade; si no, `root`), `command`, e `installed`, `upgraded`, `removed` (`nombre versión`). El snapshot lleva `status` y `records_emitted`. Solo se emite cuando cambia el registro.

### `snapshot_list`

Uno por pasada: `status` y `snapshots` con `tool` (`lvm`, `zfs`, `btrfs`), `name` y `created`. Las herramientas ausentes se omiten.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 plazos `criticidad \| dias` | Crítica, Alta, Media, Baja; días vacíos: sin plazo | EV-02 |
| P-02 cuentas autorizadas para aplicar parches `cuenta \| ambito \| tipo` | | EV-04 |
| P-03 fuentes de anuncios del fabricante `fabricante \| fuente \| canal` | `fabricante` se busca dentro del fabricante del paquete | EV-06 |
| P-04 ventanas de mantenimiento `sistema \| ventana` | `*` para todos los activos; `sab 22:00-02:00; * 06:00-07:30` | EV-07 |
| P-05 fin de soporte `producto \| version \| eol` | sistema; integrado por tipo de sistema | EV-05 |
| P-06 preproducción `sistema_prod \| sistema_preprod \| consistencia` | nombres de agente | EV-08 |
| P-07 reversión `sistema \| mecanismo \| evidencia \| ventana_horas` | | EV-09 |
| P-08 severidad por CVSS `criticidad \| cvss_minimo` | documental: la severidad la asigna Wazuh | |
| P-10 días de antigüedad máxima de las listas de paquetes | | EV-03 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp4`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION.

- EV-01 inventario de vulnerabilidades. El inventario de paquetes está al día (EV-02 de op.exp.1): COMPLIANT con las CVE abiertas por severidad. Si no, el juicio de actualidad de op.exp.1.
- EV-02 corrección dentro de plazo. Una CVE abierta cuya antigüedad desde `detected_at` supera los días de su severidad: NON_COMPLIANT con el recuento por severidad y algunas CVE. Wazuh da la severidad a partir de la puntuación CVSS; una CVE sin ella usa la fila `Sin puntuación`. Una severidad sin días no tiene plazo. Ninguna vencida: COMPLIANT.
- EV-03 nivel de parches. Listas de paquetes más antiguas que P-10 días: NON_COMPLIANT, el activo no se entera de las actualizaciones nuevas. Si no, COMPLIANT con las actualizaciones pendientes y de seguridad.
- EV-04 quién aplica parches. Cada transacción de la ventana debe tener un actor de P-02; si no, NON_COMPLIANT.
- EV-05 fin de soporte. El sistema operativo del activo encontrado en P-05 (producto y prefijo de versión) con fecha de fin vencida: NON_COMPLIANT. Sin fila para su sistema operativo: NOT_EVALUABLE por CONFIGURATION.
- EV-06 fuentes de anuncios. Cada fabricante de paquetes del activo debe contener un `fabricante` de P-03; si no, NON_COMPLIANT con los fabricantes.
- EV-07 ventanas de mantenimiento. Cada transacción de la ventana debe empezar dentro de una ventana de P-04 para el activo (su fila o, si no, `*`); si no, NON_COMPLIANT. Las horas son las del activo.
- EV-08 preproducción. En un activo de producción de P-06, cada versión instalada en la ventana debe haberse instalado antes en su activo de preproducción, o estar ahí ahora; si no, NON_COMPLIANT. Un activo que no está en P-06 como producción: NOT_EVALUABLE por CONFIGURATION.
- EV-09 punto de reversión. Cada transacción de la ventana necesita un snapshot creado como mucho `ventana_horas` antes; si no, NON_COMPLIANT.

## No se mide

- EV-10 (evolución de la deuda): Wazuh no guarda historial de vulnerabilidades resueltas.
- EV-11 (firmware): nada lee el firmware. Ninguna categoría exige R3.
- Las transacciones y actualizaciones de dnf: EV-03, EV-04, EV-07 y EV-09 de un activo rpm quedan NOT_EVALUABLE por COLLECTION.
