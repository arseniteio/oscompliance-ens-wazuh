# op.exp.10 Protección de claves criptográficas

op.exp.10 juzga lo que del ciclo de vida de las claves reside en los activos: quién lee los almacenes de claves, dónde están las claves privadas y cómo se protegen, si las claves se generan donde se usan, si siguen ahí las claves retiradas, qué algoritmos aceptan y usan los servicios, y la validez de los certificados.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 4.3.10. Definición: [`catalog/controls/ens/op.exp.10.json`](../../../catalog/controls/ens/op.exp.10.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 10.1 claves protegidas durante toda su vida | B/M/A | EV-01, EV-02, EV-07, EV-08 |
| 10.2 generación separada de la explotación | B/M/A | EV-05 |
| 10.3 claves retiradas archivadas fuera de la explotación | B/M/A | EV-06 |
| r1.1 algoritmos autorizados por el CCN | M/A | EV-03, EV-04, EV-07 |
| r2.1 cifradores conformes con CCN-STIC | ninguno | atestación (P-ATT) |

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| accesos auditados, regla 119004 ([op.acc.2](op.acc.2.md)) | lecturas y escrituras bajo los almacenes de P-02, y ejecuciones de herramientas de claves | EV-01, EV-05 |
| `audit_watch_snapshot`, `wazuh_agent_config` | la cadena de auditoría | EV-01, EV-05 |
| `key_snapshot`, `key_record`, `certificate_record` | claves privadas y certificados en disco | EV-02, EV-06 a EV-08 |
| `config_file` para `sshd -T` ([op.exp.2](op.exp.2.md)) | algoritmos que acepta sshd | EV-03 |
| inicios de sesión por sshd (regla 5715) | tipo de clave de cada inicio con clave pública | EV-04 |

Los almacenes de P-02 llegan al agente como `key_stores` y a auditd como vigilancias; cuando el activo tiene almacenes de claves, se vigila la ejecución de `/usr/bin/ssh-keygen` y `/usr/bin/openssl`.

### `key_record`, `certificate_record`, `key_snapshot`

El agente lee ficheros de 64 KiB como máximo bajo `/etc`, `/root`, `/home`, `/srv`, `/opt`, `/usr/local/etc`, `/var/lib` y los almacenes de P-02, sin los almacenes públicos de CA ni las bases de datos de paquetes, con un máximo de 2000 ficheros PEM por pasada. `key_record`: `path`, `key_kind`, `fingerprint` (SHA256 de la parte pública, del `.pub` de una clave OpenSSH), `mode`, `owner`. `certificate_record`: `path`, `subject`, `not_after`, `key_algorithm`, `key_bits`, `signature_algorithm`. Solo se emiten cuando cambian.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 inventario de claves `clave \| finalidad \| soporte \| ubicacion \| responsable \| estado \| huella` | `estado` activa o retirada | EV-06 |
| P-02 almacenes de claves `ruta \| modo_maximo \| propietario` | plataforma; integrados por tipo de sistema | EV-01, EV-02, EV-08 |
| P-03 algoritmos autorizados `uso \| algoritmo \| longitud_min` | `algoritmo` como lo nombra sshd, o parte de ese nombre | EV-03, EV-04, EV-07 |
| P-04 servicios criptográficos | documental | |
| P-05 generación y explotación `medio \| funcion \| aislamiento` | `funcion` generacion o explotacion | EV-05 |
| P-06 archivo de claves retiradas | documental | |
| P-07 procedimiento del ciclo de vida de las claves | documental | |
| P-08 cuentas con acceso a las claves `cuenta \| claves \| operacion` | | EV-01 |
| P-09 cifradores CCN-STIC | documental | |
| P-10 días de aviso antes de que caduque un certificado | | EV-07 |
| P-ATT atestaciones documentales | r2.1 | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/opexp10`.

- EV-01 accesos auditados. Cada acceso con éxito en la ventana bajo un almacén de P-02 de una cuenta fuera de P-08: NON_COMPLIANT. El silencio exige la cadena de auditoría (op.acc.4): auditd en marcha y todos los almacenes vigilados.
- EV-02 claves fuera de los almacenes. Una clave privada cuyo directorio no está bajo un almacén de P-02: NON_COMPLIANT.
- EV-03 algoritmos configurados. Cada cifrado, MAC, intercambio de claves y algoritmo de clave de host que acepta sshd debe contener un `algoritmo` de P-03.
- EV-04 algoritmos usados. El tipo de clave de cada inicio con clave pública de la ventana debe aparecer en un `algoritmo` de P-03.
- EV-05 generación. En un activo que P-05 llama `explotacion`, una ejecución de ssh-keygen u openssl en la ventana: NON_COMPLIANT.
- EV-06 claves retiradas. Una clave de P-01 en `retirada` encontrada en el activo por huella o por ubicación: NON_COMPLIANT.
- EV-07 certificados. Un certificado caducado, una clave RSA de menos de 2048 bits o una firma con MD5 o SHA-1: NON_COMPLIANT. Se nombran los que caducan en P-10 días.
- EV-08 ficheros de claves. Una clave privada más abierta que `modo_maximo` de su almacén, o con otro propietario: NON_COMPLIANT. Una clave fuera de todo almacén solo debe poder leerla su propietario.

## No se mide

- Los almacenes de claves de Windows.
