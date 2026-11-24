# op.exp.1 Inventario de activos

op.exp.1 juzga que cada activo mantiene un inventario técnico actualizado, que sigue informando, que nada desconocido se comunica con él, que el inventario declarado se revisa y que cada activo tiene responsable y naturaleza declarados.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.1. Definición: [`catalog/controls/ens/op.exp.1.json`](../../../catalog/controls/ens/op.exp.1.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 1.1 inventario con naturaleza y responsable | B/M/A | EV-01 a EV-07 |
| r1.1 etiquetado de equipos | ninguno | |
| r2.1 vista continua del estado de la red | ninguno | EV-04 |
| r3.1 activos críticos | ninguno | |
| r4.1 componentes de software de terceros | ninguno | EV-02 |

Ninguna categoría exige refuerzos: son NOT_APPLICABLE y quedan fuera de la puntuación.

## Fuentes

El inventario técnico es el de Wazuh. Syscollector mantiene un documento por elemento en los índices de estado, así que el motor lo lee en lugar de que el agente lo emita de nuevo.

| Fuente | Contenido | Lo usa |
|---|---|---|
| `wazuh-states-inventory-system-*`, `-hardware-*` | sistema operativo, núcleo, arquitectura, CPU, memoria | EV-01 |
| `wazuh-states-inventory-packages-*` | paquetes instalados | EV-02 |
| `wazuh-states-inventory-networks-*`, `-ports-*`, `-processes-*` | direcciones, puertos en escucha, procesos | EV-03, EV-05 |
| API de Wazuh `/syscollector/000/*` | el mismo inventario del manager, que Wazuh no indexa | EV-01 a EV-03, EV-05 |
| `wazuh-monitoring-*` | estado, último keepalive y dirección de cada agente | EV-01 a EV-05 |
| hecho `listening_snapshot` ([op.acc.6](op.acc.6.md)) | las direcciones de la propia activo | EV-05 |
| hecho `wazuh_agent_config` | los ajustes de syscollector del agente | EV-01 a EV-03 |
| hecho `neighbour_snapshot` | la tabla de vecinos del activo | EV-05 |
| alertas de dpkg y yum (reglas 2902, 2903, 2932, 2933, 2934) | paquetes instalados, actualizados o retirados | EV-06 |

Los índices de estado no llevan fecha, así que la actualidad se demuestra por los ajustes y el contacto del agente: syscollector activado, sus análisis activados, su intervalo dentro de P-08 y el último keepalive dentro de P-08.

### `wazuh_agent_config`, campos de syscollector

| Campo | Significado |
|---|---|
| `syscollector_disabled` | `<disabled>yes</disabled>` en el wodle, o sin wodle |
| `syscollector_interval` | segundos entre análisis |
| `syscollector_scans` | análisis activados: `hardware`, `os`, `network`, `packages`, `ports`, `processes` |

Se leen de `ossec.conf` y del `agent.conf` compartido, y prevalece el último, igual que los combina Wazuh.

### `neighbour_snapshot`

Uno por pasada, de `/proc/net/arp` (`Get-NetNeighbor` en Windows): `neighbours` con `ip`, `mac` e `interface`, y `status` (`ok`, `unreadable`). Se excluyen las entradas incompletas (MAC `00:00:00:00:00:00`). Solo se emite cuando cambia.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 activos declarados `activo \| responsable \| rol \| naturaleza` | `activo` es el nombre del agente de Wazuh | EV-07 |
| P-02 activos sin agente `activo \| tipo \| ip \| responsable` | | EV-05 |
| P-03 taxonomía de naturaleza | valores de `naturaleza` y `tipo` | EV-07 |
| P-04 días entre revisiones del inventario | | EV-06 |
| P-05 alerta ante un activo nuevo | documental | |
| P-06 activos críticos | documental, r3.1 | |
| P-08 horas que un inventario puede pasar sin actualizarse | | EV-01 a EV-04 |
| P-09 registro de revisiones del inventario `fecha \| alcance \| responsable` | | EV-06 |
| P-ATT atestaciones documentales | r1.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp1`. Si falta una fuente, NOT_EVALUABLE por COLLECTION; si falta un parámetro o no se puede usar, NOT_EVALUABLE por CONFIGURATION.

- EV-01 hardware y sistema operativo. Necesita el documento de sistema del activo. Syscollector desactivado, `os` o `hardware` desactivados, o un intervalo por encima de P-08: NON_COMPLIANT. Último keepalive más antiguo que P-08: NON_COMPLIANT. Si no, COMPLIANT, con sistema operativo, núcleo, arquitectura, núcleos y memoria en el motivo.
- EV-02 software. La misma regla sobre los documentos de paquetes y el análisis `packages`; el motivo da el recuento por tipo de paquete.
- EV-03 red. La misma regla sobre direcciones, puertos en escucha y procesos, y los análisis `network`, `ports` y `processes`.
- EV-04 activo que informa. Estado `active` y último keepalive dentro de P-08: COMPLIANT. Si no, NON_COMPLIANT con el último keepalive. El manager siempre informa.
- EV-05 vecinos desconocidos. Cada IP vecina debe ser una IP de P-02 o una dirección de cualquier activo con agente (inventario de red, la dirección en la monitorización o las direcciones que informa su agente oscompliance). IP desconocidas: NON_COMPLIANT. Ninguna: COMPLIANT. Sin snapshot, o `unreadable`: NOT_EVALUABLE por COLLECTION.
- EV-06 revisión del inventario. La fecha más reciente de P-09 que no esté en el futuro debe quedar dentro de P-04 días; si no, NON_COMPLIANT. Sin fecha utilizable: NOT_EVALUABLE por CONFIGURATION. El motivo cuenta los cambios de paquetes desde esa revisión.
- EV-07 responsable y naturaleza declarados. El nombre del agente del activo debe ser un `activo` de P-01 y, si P-03 está definido, su `naturaleza` debe ser una de P-03; si no, NON_COMPLIANT.

## No se mide

- Fabricante, modelo y número de serie del hardware: no están en el inventario de hardware de Wazuh.
- Vecinos IPv6.
