# mp.info.6 Copias de seguridad

mp.info.6 juzga las copias que cada activo declara en P-04: la fecha y el tamaño de la copia más reciente, cuánto tiempo se ha conservado la más antigua, quién puede leerlas y leer sus claves de cifrado, si una está en otro activo y las pruebas de restauración que registra la organización.

Niveles: BAJO, MEDIO, ALTO. Anexo II, apartado 5.7.6. Definición: [`catalog/controls/ens/mp.info.6.json`](../../../catalog/controls/ens/mp.info.6.json).

## Requisitos

| Requisito | Niveles | Evidencias |
|---|---|---|
| 6.1 copias realizadas | B/M/A | EV-01, EV-02 |
| 6.2.a frecuencia | B/M/A | EV-02 |
| 6.2.b almacenamiento en el lugar | B/M/A | EV-03 |
| 6.2.c almacenamiento en otro lugar | B/M/A | atestación (P-ATT) |
| 6.2.d acceso autorizado | B/M/A | EV-04 |
| r1.1 pruebas de restauración | M/A | EV-05 |
| r2.1 una copia guardada aparte | A | EV-06 |

Un activo sin filas en P-04 no hace ni guarda copias: todos los requisitos son ahí NOT_APPLICABLE. La norma pide copias al sistema: cuando ningún activo de la flota declara copias, el manager asume el control y todas las evidencias son ahí NON_COMPLIANT.

## Fuentes

| Fuente | Contenido | Lo usa |
|---|---|---|
| hecho `backup_snapshot` | las copias de cada fuente de P-04 y las claves de P-08 | EV-01 a EV-04, EV-06 |
| P-06 registro de restauraciones | | EV-05 |

La `ruta` de P-04 llega al agente como `backup_sources`, junto a las fuentes de P-07 de op.exp.3; las claves de P-08, como `backup_keys`.

### `backup_snapshot`

Uno por pasada, solo se emite cuando cambia. `sources`, uno por fuente:

- `source`: `git:<directorio>` (las entradas del reflog de su HEAD, como etckeeper guarda `/etc`), un directorio o un patrón de ficheros (cada fichero regular bajo lo que coincide, 100000 como máximo por fuente, `truncated` por encima).
- `status`: `read`, `absent` (sin copia) o `error`.
- `newest`, `oldest`: horas de la copia más reciente y la más antigua.
- `files`, `bytes`, `newest_bytes`: cuántas copias, su tamaño y el tamaño de la más reciente.
- `mode`, `owner` (`usuario:grupo`): del directorio del que parte la fuente.
- `group_readable`, `other_readable`: copias que el grupo o cualquiera puede leer.
- `filesystem`, `device`: el montaje que contiene la fuente, de `/proc/self/mountinfo`.

`key_files`, uno por clave de P-08: `path`, `status`, `mode`, `owner`.

## Parámetros

| ID | Contenido | Lo usa |
|---|---|---|
| P-01 horas entre copias | cuando la copia no fija ninguna | EV-02 |
| P-02 margen en horas | | EV-02 |
| P-03 días de retención | cuando la copia no fija ninguno | EV-03 |
| P-04 copias `copia \| ruta \| frecuencia_horas \| retencion_dias` | sistema | EV-01 a EV-04, EV-06 |
| P-05 días sin prueba de restauración | | EV-05 |
| P-06 registro de restauraciones `fecha \| maquina \| copia \| resultado \| verificacion` | `resultado` correcta o fallida | EV-05 |
| P-07 cuentas que pueden leer las copias | sistema | EV-04 |
| P-08 ficheros de claves de cifrado | sistema | EV-04 |
| P-09 ubicación alternativa, P-10 herramienta de copias | documental | |
| P-ATT atestaciones documentales | 6.2.c | |

## Cómo se juzga cada evidencia

Los jueces están en `engine/internal/controls/ens/mpinfo6`. Una fuente de P-04 que el agente aún no ha leído, o no ha podido leer, deja EV-01 a EV-04 y EV-06 en NOT_EVALUABLE.

- EV-01 última copia. Cada copia debe tener una copia más reciente y, fuera de git, no debe estar vacía.
- EV-02 intervalo. La copia más reciente de cada copia debe ser más nueva que su `frecuencia_horas`, o P-01, más P-02.
- EV-03 retención. La copia más antigua conservada debe tener al menos `retencion_dias`, o P-03. Una fuente truncada es NOT_EVALUABLE.
- EV-04 acceso. Ninguna copia legible por cualquiera; el propietario de cada fuente, y su grupo cuando las copias son legibles por el grupo, en P-07. Cada clave de P-08 debe existir, ser legible solo por su propietario y pertenecer a una cuenta de P-07.
- EV-05 pruebas de restauración. La fila `correcta` más reciente de P-06 para el activo debe quedar dentro de P-05 días.
- EV-06 copia aparte. Al menos una copia debe estar en un sistema de ficheros de otro activo: NFS, SMB, SSHFS, S3 y otros sistemas de red o FUSE remotos, o un dispositivo con nombre `host:ruta` o `//host/recurso`.

## No se mide

- El latido del colector. Un hecho que falta ya deja todas las evidencias en NOT_EVALUABLE.
