# mp.sw.2 Aceptación y puesta en servicio

mp.sw.2 juzga los activos de cada aplicación: cada instalación de sus paquetes precedida por un acta aceptada y, en MEDIO, por la misma versión instalada en preproducción, y la seguridad del activo no peor después: sin regresión de SCA, sin puertos no declarados, sin vulnerabilidades críticas o altas en sus paquetes.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.6.2. Definición: [`catalog/controls/ens/mp.sw.2.json`](../../../catalog/controls/ens/mp.sw.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 criterios de aceptación cumplidos sin daño | B/M/A | EV-01 a EV-05 |
| r1.1 pruebas en una preproducción aislada | M/A | EV-07 |
| r2.1 auditoría del código fuente | ninguno | |

Un activo donde no está desplegada ninguna aplicación de P-01: todas las evidencias y requisitos NOT_APPLICABLE. Cuando ningún activo de P-01 informa a Wazuh, el manager asume el control y todas las evidencias son ahí NON_COMPLIANT.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de dpkg, regla 2902 (`data.package`, `data.version`) | instalaciones de los últimos 90 días, la primera vez de cada versión | EV-01, EV-02, EV-03, EV-07 |
| `wazuh-states-inventory-packages-*` (`package.installed`) | instalaciones rpm de los últimos 90 días: rpm guarda la hora de instalación, dpkg no | EV-01, EV-02, EV-03, EV-07 |
| alertas de SCA, regla 19007 ([op.exp.3](op.exp.3.md)) | comprobaciones que pasaban y ahora fallan | EV-03 |
| `listening_snapshot`, `listening_socket` ([op.acc.6](op.acc.6.md)) | puertos abiertos | EV-04 |
| `wazuh-states-vulnerabilities-*` | vulnerabilidades críticas y altas abiertas por paquete | EV-05 |
| `wazuh-monitoring-*` | nombres de agente, para encontrar el activo de preproducción | EV-07 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 aplicaciones `aplicacion \| maquinas \| paquetes \| responsable \| origen` | activos y paquetes separados por comas | alcance, EV-01, EV-02, EV-05 |
| P-02 criterios de aceptación, P-07 auditorías de código | documental | |
| P-03 preproducción `produccion \| preproduccion \| aislamiento` | | EV-07 |
| P-04 días vigilados tras un despliegue | | EV-03 |
| P-05 puertos esperados `aplicacion \| puerto \| servicio` | `*` para todos los activos | EV-04 |
| P-06 actas de aceptación `fecha \| aplicacion \| version \| resultado \| aceptado_por` | | EV-02 |
| P-ATT atestaciones documentales | | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpsw2`. Un despliegue es una instalación de un paquete de una aplicación del activo en los últimos 90 días.

- EV-01 despliegues vistos. Cada aplicación del activo tiene sus `paquetes`.
- EV-02 aceptación. Cada despliegue tiene un acta de su aplicación, `aceptada`, con `aceptado_por`, con fecha no posterior, cuya `version` está vacía o es un prefijo de la desplegada.
- EV-03 configuración. Ninguna regresión de SCA dentro de P-04 días tras un despliegue.
- EV-04 exposición. Cada puerto abierto fuera de loopback está en P-05 para una aplicación del activo o para `*`.
- EV-05 vulnerabilidades. Ninguna vulnerabilidad crítica o alta abierta en un paquete de las aplicaciones del activo.
- EV-07 preproducción. Cada versión desplegada instalada antes en el activo que P-03 empareja con esta.

## No se mide

- Los hallazgos de la auditoría de código. r2.1 no se aplica a ninguna categoría.
