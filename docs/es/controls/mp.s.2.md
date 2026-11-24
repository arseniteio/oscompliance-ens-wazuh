# mp.s.2 Protección de servicios y aplicaciones web

mp.s.2 juzga los activos que sirven las aplicaciones web: sus registros en Wazuh, los ataques que enumera el requisito vigilados por reglas cargadas, la antigüedad de las vulnerabilidades críticas y altas de la plataforma, y las auditorías de cada aplicación con sus hallazgos resueltos.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.8.2. Definición: [`catalog/controls/ens/mp.s.2.json`](../../../catalog/controls/ens/mp.s.2.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 2.1 sin acceso eludiendo la autenticación | B/M/A | EV-01 a EV-06 |
| 2.2 escalada de privilegios | B/M/A | EV-01, EV-07 |
| 2.3 cross site scripting | B/M/A | EV-01, EV-08 |
| r1.1 auditorías de caja negra | B/M | EV-11 |
| r1.2 frecuencia de auditoría definida | B/M | EV-11 |
| r2.1 auditorías de caja blanca | B/M/A | EV-11 |
| r2.2 metodologías y herramientas automáticas | B/M/A | EV-10, EV-11 |
| r2.3 vulnerabilidades encontradas resueltas | B/M/A | EV-12 |
| r3.1 proxies y cachés | A | atestación (P-ATT) |

Un activo que no es una `maquina` de P-01: todas las evidencias y requisitos NOT_APPLICABLE. Cuando ningún activo de P-01 informa a Wazuh, el manager asume todas las aplicaciones: EV-10 es ahí NON_COMPLIANT. Un sistema sin servicios web desactiva el control. P-07 elige auditorías de caja negra (r1) o de caja blanca (r2): los refuerzos de la otra son NOT_APPLICABLE; en ALTO se aplica caja blanca diga lo que diga P-07.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de cada `fuente` de P-01 | horas con alertas, una semana atrás | EV-01 |
| reglas de la API de Wazuh ([op.mon.1](op.mon.1.md)) | reglas de los indicadores de P-03 | EV-02 a EV-08 |
| `wazuh-states-vulnerabilities-*` | vulnerabilidades abiertas por severidad y día de detección | EV-10 |
| P-08, P-12 | auditorías y sus hallazgos | EV-11, EV-12 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 aplicaciones `aplicacion \| maquina \| fuente \| url \| exposicion` | | alcance, EV-01, EV-11, EV-12 |
| P-02 recursos autenticados, P-04 vías prohibidas, P-05 atributos de cookies, P-06 procedimiento de auditoría, P-13 proxies y cachés | documental | |
| P-03 indicadores de ataque `ataque \| indicador \| fuente \| reglas` | `ataque` uno de los siete del requisito | EV-02 a EV-08 |
| P-07 modalidad de auditoría | caja negra, caja blanca | EV-11, decisiones |
| P-08 auditorías `fecha \| aplicacion \| modalidad \| metodologia \| herramientas \| hallazgos` | | EV-11 |
| P-09 días que una vulnerabilidad crítica o alta puede seguir abierta | | EV-10 |
| P-10 días entre auditorías | | EV-11 |
| P-11 horas sin registros web | | EV-01 |
| P-12 hallazgos `hallazgo \| aplicacion \| severidad \| responsable \| plazo \| estado` | | EV-12 |
| P-ATT atestaciones documentales | r3.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mps2`.

- EV-01 registros. Como EV-01 de mp.com.1 sobre las fuentes de las aplicaciones del activo.
- EV-02 a EV-08 ataques. Como EV-04 de mp.com.3 para acceso sin autenticación, vías alternativas, manipulación de URL, manipulación de cookies, inyección, escalada de privilegios y XSS.
- EV-10 vulnerabilidades. Ninguna vulnerabilidad crítica o alta del activo detectada hace más de P-09 días y aún abierta.
- EV-11 auditorías. Cada aplicación del activo con una auditoría de la modalidad vigente dentro de P-10 días; una de caja blanca, con `metodologia` y `herramientas`.
- EV-12 hallazgos. Cada hallazgo de las aplicaciones del activo en `resuelto`, `cerrado` o dentro de su `plazo`.

## No se mide

- El intento frente al éxito. Los registros web que decodifica Wazuh no distinguen un ataque con éxito.
- Los proxies y cachés. r3.1 es una atestación.
