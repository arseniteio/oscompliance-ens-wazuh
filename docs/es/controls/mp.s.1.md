# mp.s.1 Protección del correo electrónico

mp.s.1 juzga los activos de la plataforma de correo: los registros de la plataforma en Wazuh, sus filtros de spam, malware y código móvil respaldados por reglas cargadas, TLS en tránsito, SPF, DKIM y DMARC de los dominios propios, los cambios en su configuración bajo control de cambios y la concienciación de sus usuarios.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.8.1. Definición: [`catalog/controls/ens/mp.s.1.json`](../../../catalog/controls/ens/mp.s.1.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 1.1 cuerpo y adjuntos protegidos | B/M/A | EV-06, EV-09 |
| 1.2 enrutamiento y conexiones protegidos | B/M/A | EV-06, EV-07, EV-09 |
| 1.3 spam | B/M/A | EV-01, EV-02, EV-09 |
| 1.4 código malicioso | B/M/A | EV-01, EV-03, EV-09 |
| 1.5 código móvil | B/M/A | EV-01, EV-05, EV-09 |
| 1.6 límites al uso privado | B/M/A | atestación (P-ATT) |
| 1.7 concienciación y formación | B/M/A | EV-10 |

Un activo que no es una `maquina` de P-01: todas las evidencias y requisitos NOT_APPLICABLE. Cuando ningún activo de P-01 informa a Wazuh, el manager asume el control: las evidencias de la organización se juzgan ahí y EV-06 y EV-09 son NON_COMPLIANT. Un sistema sin correo desactiva el control.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| alertas de cada `fuente` de P-01 | horas con alertas, una semana atrás | EV-01 |
| reglas de la API de Wazuh ([op.mon.1](op.mon.1.md)) | reglas de los indicadores de P-03 | EV-02, EV-03, EV-05 |
| `config_file` de `/etc/postfix/main.cf` | `smtpd_tls_security_level`, `smtp_tls_security_level`, los cuatro `*_tls_*protocols`, `smtpd_tls_cert_file` | EV-06 |
| registros TXT de DNS, leídos por el motor | `<dominio>`, `_dmarc.<dominio>`, `<selector>._domainkey.<dominio>` | EV-07 |
| alertas de FIM, P-10 de op.exp.5 ([op.exp.5](op.exp.5.md)) | | EV-09 |

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 plataforma `plataforma \| maquina \| fuente` | | alcance, EV-01 |
| P-02 dominios propios `dominio \| selector_dkim \| politica_dmarc` | | EV-07 |
| P-03 filtros `filtro \| indicador \| fuente \| reglas` | `filtro` antispam, antimalware o código móvil | EV-02, EV-03, EV-05 |
| P-04 requisitos de TLS, P-05 cifrado del contenido, P-06 normas de uso | documental | |
| P-07 concienciación `fecha \| actividad \| alcance \| participacion` | | EV-10 |
| P-08 días entre actividades de concienciación | | EV-10 |
| P-09 configuración del correo | sistema; integrada por tipo de sistema | EV-09 |
| P-10 horas sin registros de la plataforma | | EV-01 |
| P-ATT atestaciones documentales | 1.6 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mps1`.

- EV-01 registros. Como EV-01 de mp.com.1 sobre las fuentes de P-01 y P-10.
- EV-02, EV-03, EV-05 filtros. Como EV-04 de mp.com.3 para los indicadores de `antispam`, `antimalware` y `código móvil` de P-03.
- EV-06 TLS. `smtpd_tls_security_level` en may o encrypt, `smtp_tls_security_level` definido y distinto de none, y cada lista de protocolos excluyendo SSLv2, SSLv3, TLSv1 y TLSv1.1 (con `!` o un mínimo `>=TLSv1.2`). Sin Postfix en el activo: NON_COMPLIANT.
- EV-07 dominios. Cada dominio de P-02 con un registro SPF que termina en un `all` distinto de `+all` o `?all`, un registro TXT bajo su selector DKIM y un registro DMARC con `p=quarantine` o `p=reject`.
- EV-09 configuración. Como EV-10 de mp.com.3 sobre P-09.
- EV-10 concienciación. La actividad más reciente de P-07 dentro de P-08 días.

## No se mide

- EV-04 (cada mensaje analizado) y EV-08 (suplantación del dominio propio): ningún registro común las indica. DMARC (EV-07) cubre la suplantación.
- El TLS del correo solo se lee de Postfix. Los demás servidores de correo quedan NOT_EVALUABLE por COLLECTION en EV-06.
