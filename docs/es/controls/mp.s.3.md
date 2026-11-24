# mp.s.3 Protección de la navegación web

mp.s.3 juzga el filtro de navegación por sus registros y las reglas detrás de cada una de sus funciones, los servidores DNS y el antimalware de cada activo, cuánto tiempo se conservan los registros de navegación, y la concienciación de los usuarios y la formación de los administradores.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.8.3. Definición: [`catalog/controls/ens/mp.s.3.json`](../../../catalog/controls/ens/mp.s.3.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 3.1 normas de uso | B/M/A | atestación (P-ATT) |
| 3.2 concienciación | B/M/A | EV-12 |
| 3.3 administradores formados | B/M/A | EV-13 |
| 3.4 resolución de nombres y conexiones | B/M/A | EV-05, EV-11 |
| 3.5 problemas que llegan por la navegación | B/M/A | EV-01, EV-02, EV-04, EV-06, EV-11 |
| 3.6 código malicioso y contenido activo | B/M/A | EV-01 a EV-04, EV-06 |
| 3.7 política de cookies | B/M/A | atestación (P-ATT) |
| r1.1 navegación registrada y conservada | A | EV-08 |
| r1.2 inspección de canales cifrados | A | atestación (P-ATT) |
| r1.3 lista negra | A | EV-10 |
| r2.1 lista blanca | ninguno | |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de cada `fuente` de P-02 | horas con alertas, una semana atrás | EV-01 |
| reglas de la API de Wazuh ([op.mon.1](op.mon.1.md)) | reglas de los indicadores de P-03 | EV-02 a EV-04, EV-10, EV-11 |
| hecho `device_security` ([mp.eq.2](mp.eq.2.md)) | `dns_resolvers` | EV-05 |
| hecho `malware_protection` ([op.exp.6](op.exp.6.md)) | antimalware en marcha | EV-06 |
| política ISM del índice de alertas ([op.exp.8](op.exp.8.md)) | retención en días | EV-08 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 normas de uso, P-05 política de cookies, P-11 inspección TLS, P-13 lista blanca | documental | |
| P-02 filtros de navegación `filtro \| maquina \| fuente` | | EV-01 |
| P-03 indicadores `filtro \| indicador \| fuente \| reglas` | `filtro` categorías, descargas y contenido activo, reputación, lista negra, evasión | EV-02 a EV-04, EV-10, EV-11 |
| P-04 servidores DNS autorizados | direcciones o CIDR | EV-05 |
| P-06 concienciación `fecha \| actividad \| alcance \| participacion` | | EV-12 |
| P-07 formación de administradores `fecha \| persona \| formacion` | | EV-13 |
| P-08 días de retención de los registros de navegación | | EV-08 |
| P-09, P-10 días entre actividades de concienciación y formaciones | | EV-12, EV-13 |
| P-12 horas sin registros del filtro | | EV-01 |
| P-02 de op.exp.6, antimalware esperado | | EV-06 |
| P-ATT atestaciones documentales | 3.1, 3.7, r1.2 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mps3`. El filtro y los registros son de la organización: se juzgan igual en todos los activos.

- EV-01 registros. Como EV-01 de mp.com.1 sobre las fuentes de P-02 y P-12.
- EV-02 a EV-04, EV-10, EV-11 funciones del filtro. Como EV-04 de mp.com.3 para categorías, descargas y contenido activo, reputación, lista negra y evasión.
- EV-05 DNS. Cada servidor de `dns_resolvers` dentro de una entrada de P-04; `*` no es una entrada. Sin servidor: NON_COMPLIANT.
- EV-06 puesto de trabajo. Como EV-01 de op.exp.6.
- EV-08 retención. La retención del índice de alertas de al menos P-08 días; sin política de retención: NON_COMPLIANT.
- EV-12, EV-13. La fila más reciente de P-06 dentro de P-09 días, y de P-07 dentro de P-10 días.

## No se mide

- EV-07 (cookies) y EV-09 (inspección TLS): ninguna deja registro. Los requisitos 3.7 y r1.2 se juzgan por atestación.
